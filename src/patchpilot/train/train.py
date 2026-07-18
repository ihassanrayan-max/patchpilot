"""End-to-end training entry point: features -> CV -> fit -> calibrate -> persist.

We deliberately persist artifacts to plain files under ``models/`` and
``.mlruns/<run_id>/`` rather than depending on the MLflow client. The user
asked us not to wire a Postgres MLflow backend in this sprint; the file
backend offered no concrete benefit over a JSON metadata blob for the
single artifact we produce. A future phase can wrap this in
``mlflow.start_run`` without changing call sites.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from patchpilot.eval.metrics import auc_roc, aucpr, brier_score, precision_at_k
from patchpilot.features.point_in_time import assemble_feature_frame
from patchpilot.ingest.silver import LABEL_HORIZON_DAYS, right_censor_mask
from patchpilot.models.lgbm import DEFAULT_PARAMS, LgbmModel
from patchpilot.train.holdout import (
    compute_holdout_content_sha256,
    load_eval_holdout_config,
    select_eval_holdout,
)
from patchpilot.train.temporal_cv import temporal_splits

MODEL_VERSION = "lgbm@v0.1.0"

_NON_BOOSTER_KEYS = frozenset({"early_stopping_rounds"})

# EPSS-complement is the only supported v0.1 training strategy (see
# publishable_multi-agent_v0.1 plan): the model predicts a residual on top
# of point-in-time EPSS rather than an absolute probability, so scores never
# silently zero out a CVE that EPSS already flags as risky.
SUPPORTED_STRATEGIES = frozenset({"epss_complement"})
DEFAULT_STRATEGY = "epss_complement"


def _load_config(config_path: Path) -> dict[str, Any]:
    """Read settings.toml into a plain dict."""
    with Path(config_path).open("rb") as fh:
        loaded: dict[str, Any] = tomllib.load(fh)
        return loaded


def _feature_flags(config: dict[str, Any]) -> dict[str, bool]:
    """Read [features] toggles from settings.toml with safe defaults."""
    features = config.get("features") or {}
    return {
        "include_tabular": bool(features.get("include_tabular", True)),
        "include_temporal": bool(features.get("include_temporal", True)),
        "include_graph": bool(features.get("include_graph", False)),
    }


def assemble_training_frame(
    silver_path: Path,
    *,
    bronze_dir: Path | None = None,
    include_tabular: bool = True,
    include_temporal: bool = True,
    include_graph: bool = False,
) -> pl.DataFrame:
    """Materialise a point-in-time feature+label frame from the silver parquet."""
    silver = pl.read_parquet(silver_path)
    return assemble_feature_frame(
        silver,
        bronze_dir=bronze_dir,
        include_tabular=include_tabular,
        include_temporal=include_temporal,
        include_graph=include_graph,
        point_in_time=True,
    )


def assemble_scoring_frame(
    silver_path: Path,
    *,
    bronze_dir: Path | None = None,
    include_tabular: bool = True,
    include_temporal: bool = True,
    include_graph: bool = False,
) -> pl.DataFrame:
    """Materialise features for live scoring (current EPSS, global temporal anchor)."""
    silver = pl.read_parquet(silver_path)
    return assemble_feature_frame(
        silver,
        bronze_dir=bronze_dir,
        include_tabular=include_tabular,
        include_temporal=include_temporal,
        include_graph=include_graph,
        point_in_time=False,
    )


def _today_utc_date() -> Any:
    """Return today's UTC date (kept as a helper for test patching)."""
    return datetime.now(UTC).date()


def filter_train_eval_rows(df: pl.DataFrame) -> pl.DataFrame:
    """Apply the right-censoring rule from PLAN.md: drop rows < 30d old."""
    mask = right_censor_mask(
        df.get_column("published_date"),
        _today_utc_date(),
        horizon_days=LABEL_HORIZON_DAYS,
    )
    return df.filter(mask)


def _feature_names(df: pl.DataFrame) -> list[str]:
    """Return the deterministic list of model-input feature columns."""
    return sorted(c for c in df.columns if c.startswith("f_"))


def _row_metrics(y_true: np.ndarray, y_score: np.ndarray) -> dict[str, float]:
    """Compute a tiny in-house metrics blob used during training."""
    return {
        "auc_pr": float(aucpr(y_true, y_score)),
        "auc_roc": float(auc_roc(y_true, y_score)),
        "precision_at_100": float(precision_at_k(y_true, y_score, k=100)),
        "brier": float(brier_score(y_true, y_score)),
    }


def _blend_epss_residual(epss: np.ndarray, residual: np.ndarray) -> np.ndarray:
    """``clamp01(epss + residual)`` — the locked EPSS-complement blend."""
    return np.clip(np.asarray(epss, dtype=np.float64) + np.asarray(residual, dtype=np.float64), 0.0, 1.0)


def _sequential_tune_fold(
    *,
    base_params: dict[str, Any],
    seed: int,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_valid: np.ndarray,
    y_valid: np.ndarray,
    feature_names: list[str],
) -> dict[str, Any]:
    """Pick ``max_depth``, ``num_leaves``, ``min_data_in_leaf`` by sequential grid search.

    Scores candidates by validation AUC-PR of a plain binary classifier.
    Used for the non-complement ablation variants (full / no-epss).
    """

    def valid_pr(params: dict[str, Any]) -> float:
        model = LgbmModel(params=params, seed=seed)
        model.fit(x_train, y_train, x_valid, y_valid, feature_names=feature_names)
        scores = model.predict_proba(x_valid)
        value = float(aucpr(y_valid, scores))
        return value if value == value else -1.0

    return _grid_search(base_params, valid_pr)


def _sequential_tune_fold_residual(
    *,
    base_params: dict[str, Any],
    seed: int,
    x_train: np.ndarray,
    y_train_res: np.ndarray,
    x_valid: np.ndarray,
    y_valid_res: np.ndarray,
    y_valid_label: np.ndarray,
    epss_valid: np.ndarray,
    feature_names: list[str],
) -> dict[str, Any]:
    """Pick hyperparameters for the residual regressor by blended validation AUC-PR.

    The regressor predicts ``label - epss``; candidates are scored by the
    AUC-PR of the *blended* score (``clamp01(epss + residual)``) against the
    true binary label, since that is what the model is ultimately judged on.
    """

    def valid_pr(params: dict[str, Any]) -> float:
        model = LgbmModel(params=params, seed=seed, task="regression")
        model.fit(x_train, y_train_res, x_valid, y_valid_res, feature_names=feature_names)
        residual = model.predict_raw(x_valid)
        blended = _blend_epss_residual(epss_valid, residual)
        value = float(aucpr(y_valid_label, blended))
        return value if value == value else -1.0

    return _grid_search(base_params, valid_pr)


def _grid_search(
    base_params: dict[str, Any], valid_pr: Any
) -> dict[str, Any]:
    """Shared sequential grid search over depth / leaves / min-data-in-leaf."""
    tuned = dict(base_params)
    best_depth = max([6, 8, 12], key=lambda d: valid_pr({**tuned, "max_depth": d}))
    tuned["max_depth"] = best_depth

    best_leaves = max([31, 63, 127], key=lambda n: valid_pr({**tuned, "num_leaves": n}))
    tuned["num_leaves"] = best_leaves

    best_min_data = max([20, 50, 150], key=lambda m: valid_pr({**tuned, "min_data_in_leaf": m}))
    tuned["min_data_in_leaf"] = best_min_data

    return tuned


def train_lgbm(config_path: Path) -> str:
    """Run a deterministic training pipeline; return the run id."""
    config = _load_config(config_path)
    paths = config["paths"]
    silver_path = Path(paths["silver_dir"]) / "cve_master.parquet"
    if not silver_path.exists():
        raise FileNotFoundError(
            f"silver parquet missing at {silver_path}; run `make ingest` first"
        )

    flags = _feature_flags(config)
    bronze_dir = Path(paths.get("bronze_dir", "data/bronze"))
    holdout_cfg = load_eval_holdout_config(config)

    train_cfg = config.get("train", {})
    n_splits = int(train_cfg.get("n_splits", 5))
    embargo_days = int(train_cfg.get("embargo_days", 30))
    seed = int(train_cfg.get("seed", 42))
    raw_lgbm = dict(train_cfg.get("lgbm", {}))
    lgbm_params = {k: v for k, v in raw_lgbm.items() if k not in _NON_BOOSTER_KEYS}
    base_lgbm = {**DEFAULT_PARAMS, **lgbm_params}
    strategy = str(train_cfg.get("strategy", DEFAULT_STRATEGY)).strip().lower()
    if strategy not in SUPPORTED_STRATEGIES:
        raise ValueError(
            f"unsupported [train].strategy={strategy!r}; v0.1 only supports {sorted(SUPPORTED_STRATEGIES)}"
        )

    frame = assemble_training_frame(
        silver_path,
        bronze_dir=bronze_dir,
        include_tabular=flags["include_tabular"],
        include_temporal=flags["include_temporal"],
        include_graph=flags["include_graph"],
    )
    frame = filter_train_eval_rows(frame)
    if len(frame) < 100:
        raise RuntimeError(
            f"too few rows after right-censoring (n={len(frame)}); "
            f"ingest more data (try `--nvd-max-records 50000`)"
        )

    selection = select_eval_holdout(frame, holdout_cfg)
    holdout_frame = selection.holdout_frame if selection.holdout_frame is not None else frame.head(0)
    heldout_sha = compute_holdout_content_sha256(holdout_frame) if len(holdout_frame) > 0 else ""

    if selection.window is not None:
        candidate_train = frame.filter(pl.col("published_date") < pl.lit(selection.window.start))
    else:
        candidate_train = frame

    if (
        len(candidate_train) >= 100
        and int(candidate_train.get_column("exploited_30d").sum()) >= 5
    ):
        train_frame = candidate_train
    else:
        train_frame = frame

    if len(train_frame) < 100:
        raise RuntimeError(
            f"too few pre-holdout rows for temporal CV (n={len(train_frame)}); "
            "ingest more history before the calendar holdout window."
        )

    feature_names = _feature_names(train_frame)
    feature_matrix = train_frame.select(feature_names).to_numpy().astype(np.float32)
    labels = train_frame.get_column("exploited_30d").to_numpy().astype(np.int8)
    dates = train_frame.get_column("published_date").to_list()

    if "f_epss_score" not in feature_names:
        raise RuntimeError(
            "epss_complement strategy requires an 'f_epss_score' feature; "
            "check [features] flags and the EPSS bronze snapshots"
        )
    epss_full = train_frame.get_column("f_epss_score").to_numpy().astype(np.float64)
    residual_full = (labels.astype(np.float64) - epss_full).astype(np.float32)

    n_pos = int(labels.sum())
    if n_pos < 5:
        raise RuntimeError(
            f"too few positive labels in training window (n_pos={n_pos}); cannot fit a binary "
            "classifier. Ingest more historical data."
        )

    # Adjust n_splits / horizon so the splitter has enough span; pick a
    # horizon that fits the data window.
    span_days = (max(dates) - min(dates)).days
    horizon_days = max(30, span_days // max(n_splits + 1, 2))
    if span_days < (n_splits + 1) * horizon_days + embargo_days:
        n_splits = max(2, span_days // (horizon_days + embargo_days))

    fold_metrics: list[dict[str, float]] = []
    fold_lgbm_params: list[dict[str, Any]] = []
    last_train_idx: list[int] = []
    last_valid_idx: list[int] = []
    last_fold_params: dict[str, Any] = dict(base_lgbm)
    for train_idx, valid_idx in temporal_splits(
        dates,
        n_splits=n_splits,
        horizon_days=horizon_days,
        embargo_days=embargo_days,
    ):
        y_train = labels[train_idx]
        y_valid = labels[valid_idx]
        if y_train.sum() < 1 or y_valid.sum() < 1:
            continue
        y_train_res = residual_full[train_idx]
        y_valid_res = residual_full[valid_idx]
        epss_valid_fold = epss_full[valid_idx]
        tuned_params = _sequential_tune_fold_residual(
            base_params=base_lgbm,
            seed=seed,
            x_train=feature_matrix[train_idx],
            y_train_res=y_train_res,
            x_valid=feature_matrix[valid_idx],
            y_valid_res=y_valid_res,
            y_valid_label=y_valid,
            epss_valid=epss_valid_fold,
            feature_names=feature_names,
        )
        last_fold_params = tuned_params
        fold_lgbm_params.append(
            {
                "max_depth": tuned_params["max_depth"],
                "num_leaves": tuned_params["num_leaves"],
                "min_data_in_leaf": tuned_params["min_data_in_leaf"],
            }
        )
        fold_model = LgbmModel(params=tuned_params, seed=seed, task="regression")
        fold_model.fit(
            feature_matrix[train_idx],
            y_train_res,
            feature_matrix[valid_idx],
            y_valid_res,
            feature_names=feature_names,
        )
        residual_pred = fold_model.predict_raw(feature_matrix[valid_idx])
        blended = _blend_epss_residual(epss_valid_fold, residual_pred)
        fold_metrics.append(_row_metrics(y_valid, blended))
        last_train_idx = train_idx
        last_valid_idx = valid_idx

    if not fold_metrics:
        raise RuntimeError(
            "no usable temporal-CV fold produced predictions; check label balance."
        )

    # Final fit on train + valid of the latest fold. Residual (epss_complement)
    # models are not run through isotonic calibration: the calibrator API
    # assumes a binary-label target, but this booster predicts a signed
    # residual that is blended with EPSS by the caller, not consumed directly.
    final_model = LgbmModel(params=last_fold_params, seed=seed, task="regression")
    final_model.fit(
        feature_matrix[last_train_idx],
        residual_full[last_train_idx],
        feature_matrix[last_valid_idx],
        residual_full[last_valid_idx],
        feature_names=feature_names,
    )

    final_residual = final_model.predict_raw(feature_matrix[last_valid_idx])
    final_epss_valid = epss_full[last_valid_idx]
    final_scores = _blend_epss_residual(final_epss_valid, final_residual)
    final_metrics = _row_metrics(labels[last_valid_idx], final_scores)
    averaged = {
        k: float(np.mean([m[k] for m in fold_metrics])) for k in fold_metrics[0]
    }

    run_id = _make_run_id(silver_path, config)
    mlruns_dir = Path(paths.get("mlruns_dir", ".mlruns"))
    run_dir = mlruns_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = (run_dir / "model.pkl").resolve()
    final_model.save(artifact_path)

    metadata: dict[str, Any] = {
        "run_id": run_id,
        "model_version": MODEL_VERSION,
        "strategy": strategy,
        "task": final_model.task,
        "trained_at": datetime.now(UTC).isoformat(),
        "silver_path": str(silver_path),
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "n_rows": int(len(train_frame)),
        "n_rows_censored_total": int(len(frame)),
        "train_n_rows": int(len(train_frame)),
        "heldout_n_rows": int(len(holdout_frame)),
        "heldout_window_start": (
            selection.window.start.isoformat() if selection.window is not None else None
        ),
        "heldout_window_end": (
            selection.window.end.isoformat() if selection.window is not None else None
        ),
        "heldout_window_days": (
            selection.window.window_days if selection.window is not None else None
        ),
        "heldout_n_positives": (
            selection.window.n_positives if selection.window is not None else 0
        ),
        "heldout_content_sha256": heldout_sha,
        "n_pos": int(n_pos),
        "n_splits": n_splits,
        "horizon_days": horizon_days,
        "embargo_days": embargo_days,
        "seed": seed,
        "params": lgbm_params,
        "final_lgbm_params": last_fold_params,
        "fold_lgbm_params": fold_lgbm_params,
        "fold_metrics": fold_metrics,
        "avg_metrics": averaged,
        "final_valid_metrics": final_metrics,
        "feature_importance": final_model.feature_importance(),
        "model_meta": asdict(final_model.meta),
        "artifact": str(artifact_path),
    }
    (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, default=str))

    # Stable "latest" pointer so the serving layer doesn't need to scan.
    latest_path = mlruns_dir / "latest.json"
    latest_path.write_text(
        json.dumps(
            {"run_id": run_id, "artifact": str(artifact_path), "model_version": MODEL_VERSION},
            indent=2,
        )
    )

    return run_id


def _make_run_id(silver_path: Path, config: dict[str, Any]) -> str:
    """Deterministic run id from silver hash + config; readable timestamp suffix."""
    h = hashlib.sha256()
    h.update(silver_path.read_bytes())
    h.update(json.dumps(config, sort_keys=True, default=str).encode("utf-8"))
    digest = h.hexdigest()[:10]
    return f"run-{digest}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}"
