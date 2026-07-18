"""Ablation study: EPSS-only vs full classifier vs no-EPSS vs EPSS-complement.

Writes ``docs/benchmarks/ABLATIONS.md`` so model strategy decisions are
evidence-based rather than anecdotal. All four variants are scored on the
same rolling holdout using the same point-in-time EPSS column
(``f_epss_score``) that training sees — never a live/current EPSS lookup —
so the EPSS-only row is a fair baseline (see ``docs/evaluation.md``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from patchpilot.eval.compare_epss import _load_latest_model_artifact
from patchpilot.eval.metrics import auc_roc, aucpr, brier_score, precision_at_k
from patchpilot.models.lgbm import LgbmModel
from patchpilot.train.holdout import load_eval_holdout_config, select_eval_holdout
from patchpilot.train.train import assemble_training_frame, filter_train_eval_rows


def _metrics(y: np.ndarray, scores: np.ndarray, top_k: int) -> dict[str, float]:
    return {
        "auc_pr": float(aucpr(y, scores)),
        "auc_roc": float(auc_roc(y, scores)),
        "p_at_k": float(precision_at_k(y, scores, k=top_k)),
        "brier": float(brier_score(y, scores)),
    }


def _fmt(x: float) -> str:
    if x != x:
        return "n/a"
    return f"{x:.4f}"


def _fit_classifier(
    train_frame: pl.DataFrame, feature_cols: list[str], seed: int = 42
) -> LgbmModel | None:
    """Fit a plain binary classifier on ``feature_cols``; ``None`` if data is too thin."""
    if len(train_frame) < 50 or int(train_frame.get_column("exploited_30d").sum()) < 3:
        return None
    x_tr = train_frame.select(feature_cols).to_numpy().astype(np.float32)
    y_tr = train_frame.get_column("exploited_30d").to_numpy().astype(np.int8)
    n = len(y_tr)
    split = max(10, int(n * 0.8))
    model = LgbmModel(seed=seed, task="classification")
    model.fit(x_tr[:split], y_tr[:split], x_tr[split:], y_tr[split:], feature_names=feature_cols)
    return model


def run_ablations(
    *,
    silver_path: Path = Path("data/silver/cve_master.parquet"),
    bronze_dir: Path = Path("data/bronze"),
    mlruns_dir: Path = Path(".mlruns"),
    config_path: Path = Path("config/settings.toml"),
    report_path: Path = Path("docs/benchmarks/ABLATIONS.md"),
    top_k: int = 100,
) -> Path:
    """Score EPSS-only / full / no-EPSS / EPSS-complement variants; write Markdown."""
    import tomllib

    silver_path = Path(silver_path)
    report_path = Path(report_path)
    if not silver_path.exists():
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            "# PatchPilot Ablations\n\n"
            f"**Status:** unavailable — silver missing at `{silver_path}`.\n"
        )
        return report_path

    with Path(config_path).open("rb") as fh:
        config = tomllib.load(fh)
    holdout_cfg = load_eval_holdout_config(config)
    top_k_eff = int((config.get("eval") or {}).get("top_k", top_k))

    frame = assemble_training_frame(silver_path, bronze_dir=Path(bronze_dir))
    closed = filter_train_eval_rows(frame)
    selection = select_eval_holdout(closed, holdout_cfg)
    if selection.window is None or selection.holdout_frame is None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            "# PatchPilot Ablations\n\n"
            f"**Status:** unavailable — {selection.reason or 'no holdout'}.\n"
        )
        return report_path

    holdout = selection.holdout_frame
    y = holdout.get_column("exploited_30d").to_numpy().astype(np.int8)

    notes: list[str] = []

    if "f_epss_score" not in holdout.columns:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            "# PatchPilot Ablations\n\n"
            "**Status:** unavailable — holdout frame is missing the point-in-time "
            "`f_epss_score` feature; cannot compute a fair EPSS baseline.\n"
        )
        return report_path

    # Fair PIT EPSS baseline: the same point-in-time column training sees,
    # not a live/current lookup against silver (which would leak future
    # EPSS re-scoring into the "baseline" and make the comparison unfair).
    epss_scores = holdout.get_column("f_epss_score").to_numpy().astype(np.float64)
    epss_only = _metrics(y, epss_scores, top_k_eff)

    all_feature_cols = [c for c in holdout.columns if c.startswith("f_")]
    no_epss_cols = [c for c in all_feature_cols if not c.startswith("f_epss_")]
    train_frame = closed.filter(pl.col("published_date") < pl.lit(selection.window.start))

    full_metrics: dict[str, float] | None = None
    full_model = _fit_classifier(train_frame, all_feature_cols)
    if full_model is None:
        notes.append("Insufficient pre-holdout rows to train the 'full' ablation classifier.")
    else:
        x_ho = holdout.select(all_feature_cols).to_numpy().astype(np.float32)
        full_metrics = _metrics(y, full_model.predict_proba(x_ho), top_k_eff)

    no_epss_metrics: dict[str, float] | None = None
    if len(no_epss_cols) < 2:
        notes.append("Too few non-EPSS features to train a no_epss ablation model.")
    else:
        no_epss_model = _fit_classifier(train_frame, no_epss_cols)
        if no_epss_model is None:
            notes.append("Insufficient pre-holdout rows for no_epss retrain.")
        else:
            x_ho_no_epss = holdout.select(no_epss_cols).to_numpy().astype(np.float32)
            no_epss_metrics = _metrics(y, no_epss_model.predict_proba(x_ho_no_epss), top_k_eff)

    # EPSS-complement: reuse the persisted (shipped) model artifact. It is
    # only meaningful here when it was trained with strategy=epss_complement
    # (task="regression", predicting a residual added onto EPSS).
    complement_metrics: dict[str, float] | None = None
    loaded = _load_latest_model_artifact(Path(mlruns_dir))
    if loaded is None:
        notes.append("No trained model under `.mlruns/`; epss_complement ablation skipped.")
    else:
        model, meta = loaded
        strategy = str(meta.get("strategy", ""))
        model_feature_names: list[str] = list(meta.get("feature_names") or all_feature_cols)
        missing = [c for c in model_feature_names if c not in holdout.columns]
        if strategy != "epss_complement" or getattr(model, "task", "classification") != "regression":
            notes.append(
                "Latest trained artifact is not an epss_complement residual model "
                "(re-run `make train` after setting [train].strategy = 'epss_complement')."
            )
        elif missing:
            notes.append(f"Latest artifact feature mismatch with holdout columns: {missing}.")
        else:
            x_model = holdout.select(model_feature_names).to_numpy().astype(np.float32)
            residual = model.predict_raw(x_model)
            blended = np.clip(epss_scores + np.asarray(residual, dtype=np.float64), 0.0, 1.0)
            complement_metrics = _metrics(y, blended, top_k_eff)

    body = _render(
        window_start=selection.window.start,
        window_end=selection.window.end,
        n_rows=selection.window.n_rows,
        n_pos=selection.window.n_positives,
        top_k=top_k_eff,
        epss_only=epss_only,
        full=full_metrics,
        no_epss=no_epss_metrics,
        complement=complement_metrics,
        notes=notes,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(body, encoding="utf-8")
    return report_path


def _render(
    *,
    window_start: Any,
    window_end: Any,
    n_rows: int,
    n_pos: int,
    top_k: int,
    epss_only: dict[str, float],
    full: dict[str, float] | None,
    no_epss: dict[str, float] | None,
    complement: dict[str, float] | None,
    notes: list[str],
) -> str:
    def row(name: str, m: dict[str, float] | None) -> str:
        if m is None:
            return f"| {name} | n/a | n/a | n/a | n/a |"
        return (
            f"| {name} | {_fmt(m['auc_pr'])} | {_fmt(m['auc_roc'])} | "
            f"{_fmt(m['p_at_k'])} | {_fmt(m['brier'])} |"
        )

    lift_line = ""
    if complement is not None:
        lift = complement["auc_pr"] - epss_only["auc_pr"]
        lift_line = f"- **EPSS-complement lift**: delta-AUC-PR (complement - EPSS-only) = {lift:+.4f}.\n"

    notes_block = "\n".join(f"- {n}" for n in notes) if notes else "- none"
    return (
        "# PatchPilot Ablations\n\n"
        f"_Generated: {datetime.now(UTC).isoformat()}_\n\n"
        "**Status:** ok\n\n"
        "## Holdout window\n\n"
        f"- start: {window_start}\n"
        f"- end: {window_end}\n"
        f"- n rows: {n_rows}\n"
        f"- n positives: {n_pos}\n\n"
        "## Variants\n\n"
        f"| Variant | AUC-PR | AUC-ROC | P@{top_k} | Brier |\n"
        "| ------- | ------ | ------- | ----- | ----- |\n"
        f"{row('EPSS-only baseline (PIT)', epss_only)}\n"
        f"{row('Full LightGBM (label target)', full)}\n"
        f"{row('LightGBM no-EPSS features', no_epss)}\n"
        f"{row('EPSS-complement (residual blend)', complement)}\n\n"
        "## Interpretation guide\n\n"
        "- If **EPSS-only** dominates AUC-PR, PatchPilot is not yet a standalone challenger.\n"
        "- If **no-EPSS** is near chance but **full** approaches EPSS, the model is largely "
        "an EPSS residual/reranker — say so honestly.\n"
        "- If **no-EPSS** beats EPSS, non-EPSS signals are carrying value.\n"
        "- **EPSS-complement** is the strategy actually shipped in `serve/scoring.py`: "
        "`clamp01(epss + residual)`. A positive lift means the residual model adds "
        "signal on top of EPSS instead of just reproducing it.\n"
        f"{lift_line}\n"
        "## Notes\n\n"
        f"{notes_block}\n"
    )
