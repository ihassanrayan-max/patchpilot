"""Ablation study: full model vs no-EPSS features vs EPSS-only baseline.

Writes ``docs/benchmarks/ABLATIONS.md`` so model strategy decisions are
evidence-based rather than anecdotal.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from patchpilot.eval.compare_epss import _load_latest_model_artifact
from patchpilot.eval.metrics import auc_roc, aucpr, brier_score, precision_at_k
from patchpilot.models.baseline_epss import EpssBaseline
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


def run_ablations(
    *,
    silver_path: Path = Path("data/silver/cve_master.parquet"),
    bronze_dir: Path = Path("data/bronze"),
    mlruns_dir: Path = Path(".mlruns"),
    config_path: Path = Path("config/settings.toml"),
    report_path: Path = Path("docs/benchmarks/ABLATIONS.md"),
    top_k: int = 100,
) -> Path:
    """Score ablation variants on the rolling holdout and write Markdown."""
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
    cve_ids = holdout.get_column("cve_id").to_list()

    epss_scores = np.asarray(
        EpssBaseline.from_silver(silver_path).predict_proba(cve_ids), dtype=np.float64
    )
    epss_only = _metrics(y, epss_scores, top_k_eff)

    loaded = _load_latest_model_artifact(Path(mlruns_dir))
    full_metrics: dict[str, float] | None = None
    no_epss_metrics: dict[str, float] | None = None
    notes: list[str] = []

    if loaded is None:
        notes.append("No trained model under `.mlruns/`; full/no_epss ablations skipped.")
    else:
        model, meta = loaded
        feature_names: list[str] = list(meta.get("feature_names") or [])
        if not feature_names:
            feature_names = [c for c in holdout.columns if c.startswith("f_")]
        x_full = holdout.select(feature_names).to_numpy().astype(np.float32)
        full_metrics = _metrics(y, model.predict_proba(x_full), top_k_eff)

        no_epss_cols = [c for c in feature_names if not c.startswith("f_epss_")]
        if len(no_epss_cols) < 2:
            notes.append("Too few non-EPSS features to train a no_epss ablation model.")
        else:
            train_frame = closed.filter(
                pl.col("published_date") < pl.lit(selection.window.start)
            )
            if len(train_frame) < 50 or int(train_frame.get_column("exploited_30d").sum()) < 3:
                notes.append("Insufficient pre-holdout rows for no_epss retrain.")
            else:
                x_tr = train_frame.select(no_epss_cols).to_numpy().astype(np.float32)
                y_tr = train_frame.get_column("exploited_30d").to_numpy().astype(np.int8)
                ablation = LgbmModel(seed=42)
                # Fit without a valid set when data is small; still deterministic.
                n = len(y_tr)
                split = max(10, int(n * 0.8))
                ablation.fit(
                    x_tr[:split],
                    y_tr[:split],
                    x_tr[split:],
                    y_tr[split:],
                    feature_names=no_epss_cols,
                )
                x_ho = holdout.select(no_epss_cols).to_numpy().astype(np.float32)
                no_epss_metrics = _metrics(y, ablation.predict_proba(x_ho), top_k_eff)

    body = _render(
        window_start=selection.window.start,
        window_end=selection.window.end,
        n_rows=selection.window.n_rows,
        n_pos=selection.window.n_positives,
        top_k=top_k_eff,
        epss_only=epss_only,
        full=full_metrics,
        no_epss=no_epss_metrics,
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
    notes: list[str],
) -> str:
    def row(name: str, m: dict[str, float] | None) -> str:
        if m is None:
            return f"| {name} | n/a | n/a | n/a | n/a |"
        return (
            f"| {name} | {_fmt(m['auc_pr'])} | {_fmt(m['auc_roc'])} | "
            f"{_fmt(m['p_at_k'])} | {_fmt(m['brier'])} |"
        )

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
        f"{row('EPSS-only baseline', epss_only)}\n"
        f"{row('Full LightGBM', full)}\n"
        f"{row('LightGBM no-EPSS features', no_epss)}\n\n"
        "## Interpretation guide\n\n"
        "- If **EPSS-only** dominates AUC-PR, PatchPilot is not yet a standalone challenger.\n"
        "- If **no-EPSS** is near chance but **full** approaches EPSS, the model is largely "
        "an EPSS residual/reranker — say so honestly.\n"
        "- If **no-EPSS** beats EPSS, non-EPSS signals are carrying value.\n\n"
        "## Notes\n\n"
        f"{notes_block}\n"
    )
