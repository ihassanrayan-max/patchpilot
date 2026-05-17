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
from patchpilot.features.graph import build_graph_frame
from patchpilot.features.tabular import build_tabular_frame
from patchpilot.features.temporal import build_temporal_frame_default
from patchpilot.ingest.silver import LABEL_HORIZON_DAYS, right_censor_mask
from patchpilot.models.lgbm import LgbmModel
from patchpilot.train.calibration import fit_calibrator
from patchpilot.train.temporal_cv import temporal_splits

MODEL_VERSION = "lgbm@v0.1.0"


def _load_config(config_path: Path) -> dict[str, Any]:
    """Read settings.toml into a plain dict."""
    with Path(config_path).open("rb") as fh:
        loaded: dict[str, Any] = tomllib.load(fh)
        return loaded


def assemble_training_frame(silver_path: Path) -> pl.DataFrame:
    """Materialise a deterministic feature+label frame from the silver parquet."""
    silver = pl.read_parquet(silver_path)
    tabular = build_tabular_frame(silver).drop("published_date")
    temporal = build_temporal_frame_default(silver)
    graph = build_graph_frame(silver)

    base = silver.select(
        ["cve_id", "published_date", "exploited_30d", "in_kev", "cvss_v3_base_score"]
    )
    feats = (
        base.join(tabular, on="cve_id", how="inner")
        .join(temporal, on="cve_id", how="left")
        .join(graph, on="cve_id", how="left")
    )
    feats = feats.with_columns(
        [pl.col(c).fill_null(0) for c in feats.columns if c.startswith("f_")]
    )
    return feats


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


def train_lgbm(config_path: Path) -> str:
    """Run a deterministic training pipeline; return the run id."""
    config = _load_config(config_path)
    paths = config["paths"]
    silver_path = Path(paths["silver_dir"]) / "cve_master.parquet"
    if not silver_path.exists():
        raise FileNotFoundError(
            f"silver parquet missing at {silver_path}; run `make ingest` first"
        )

    train_cfg = config.get("train", {})
    n_splits = int(train_cfg.get("n_splits", 5))
    embargo_days = int(train_cfg.get("embargo_days", 30))
    seed = int(train_cfg.get("seed", 42))
    lgbm_params = {k: v for k, v in train_cfg.get("lgbm", {}).items()}

    frame = assemble_training_frame(silver_path)
    frame = filter_train_eval_rows(frame)
    if len(frame) < 100:
        raise RuntimeError(
            f"too few rows after right-censoring (n={len(frame)}); "
            f"ingest more data (try `--nvd-max-records 5000`)"
        )

    feature_names = _feature_names(frame)
    feature_matrix = frame.select(feature_names).to_numpy().astype(np.float32)
    labels = frame.get_column("exploited_30d").to_numpy().astype(np.int8)
    dates = frame.get_column("published_date").to_list()

    n_pos = int(labels.sum())
    if n_pos < 5:
        raise RuntimeError(
            f"too few positive labels (n_pos={n_pos}); cannot fit a binary "
            "classifier. Ingest more historical data."
        )

    # Adjust n_splits / horizon so the splitter has enough span; pick a
    # horizon that fits the data window.
    span_days = (max(dates) - min(dates)).days
    horizon_days = max(30, span_days // max(n_splits + 1, 2))
    if span_days < (n_splits + 1) * horizon_days + embargo_days:
        n_splits = max(2, span_days // (horizon_days + embargo_days))

    fold_metrics: list[dict[str, float]] = []
    last_train_idx: list[int] = []
    last_valid_idx: list[int] = []
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
        fold_model = LgbmModel(params=lgbm_params, seed=seed)
        fold_model.fit(
            feature_matrix[train_idx],
            y_train,
            feature_matrix[valid_idx],
            y_valid,
            feature_names=feature_names,
        )
        scores = fold_model.predict_proba(feature_matrix[valid_idx])
        fold_metrics.append(_row_metrics(y_valid, scores))
        last_train_idx = train_idx
        last_valid_idx = valid_idx

    if not fold_metrics:
        raise RuntimeError(
            "no usable temporal-CV fold produced predictions; check label balance."
        )

    # Final fit on train + valid of the latest fold; calibrate on the held-out valid.
    final_model = LgbmModel(params=lgbm_params, seed=seed)
    final_model.fit(
        feature_matrix[last_train_idx],
        labels[last_train_idx],
        feature_matrix[last_valid_idx],
        labels[last_valid_idx],
        feature_names=feature_names,
    )
    valid_scores = final_model.predict_proba(feature_matrix[last_valid_idx])
    calibrator = fit_calibrator(valid_scores, labels[last_valid_idx], method="isotonic")
    final_model.set_calibrator(calibrator)

    final_scores = final_model.predict_proba(feature_matrix[last_valid_idx])
    final_metrics = _row_metrics(labels[last_valid_idx], final_scores)
    averaged = {
        k: float(np.mean([m[k] for m in fold_metrics])) for k in fold_metrics[0]
    }

    run_id = _make_run_id(silver_path, config)
    mlruns_dir = Path(paths.get("mlruns_dir", ".mlruns"))
    run_dir = mlruns_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = run_dir / "model.pkl"
    final_model.save(artifact_path)

    metadata: dict[str, Any] = {
        "run_id": run_id,
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(UTC).isoformat(),
        "silver_path": str(silver_path),
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "n_rows": int(len(frame)),
        "n_pos": int(n_pos),
        "n_splits": n_splits,
        "horizon_days": horizon_days,
        "embargo_days": embargo_days,
        "seed": seed,
        "params": lgbm_params,
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
