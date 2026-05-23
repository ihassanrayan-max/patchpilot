"""Side-by-side PatchPilot vs EPSS evaluation report writer.

Loads the most recently trained model (under ``.mlruns/latest.json``),
scores it and the EPSS baseline on the same calendar hold-out slice
(``published_date >= 2025-01-01``, after right-censoring), and writes a
Markdown report with real numeric metrics. If any prerequisite is missing we
still write a clearly worded report explaining exactly why no numbers could be
computed (per the user's instruction not to fabricate).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import numpy as np
import polars as pl

from patchpilot.eval.metrics import (
    auc_roc,
    aucpr,
    brier_score,
    expected_calibration_error,
    precision_at_k,
)
from patchpilot.ingest.silver import LABEL_HORIZON_DAYS, right_censor_mask
from patchpilot.models.baseline_epss import EpssBaseline
from patchpilot.models.lgbm import LgbmModel
from patchpilot.train.holdout import HELDOUT_PUBLISHED_FROM, compute_holdout_content_sha256
from patchpilot.train.train import assemble_training_frame

DEFAULT_TOP_K = 100


def _load_latest_model_artifact(mlruns_dir: Path) -> tuple[LgbmModel, dict[str, Any]] | None:
    """Locate the latest training artifact + metadata."""
    pointer = mlruns_dir / "latest.json"
    if not pointer.exists():
        return None
    info = cast(dict[str, Any], json.loads(pointer.read_text()))
    artifact = Path(info["artifact"])
    if not artifact.exists():
        return None
    model = LgbmModel.load(artifact)
    meta_path = artifact.parent / "metadata.json"
    meta = cast(dict[str, Any], json.loads(meta_path.read_text())) if meta_path.exists() else {}
    return model, meta


def _write_empty_report(report_path: Path, reason: str) -> Path:
    """Write a clearly worded "no numbers" report when prerequisites are missing."""
    body = (
        "# PatchPilot vs EPSS - Benchmark Report\n\n"
        "**Status:** could not compute metrics.\n\n"
        f"**Reason:** {reason}\n\n"
        "Re-run `make ingest` and `make train` to materialise the inputs, "
        "then re-run `make eval`.\n"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(body)
    return report_path


def _render_markdown(
    *,
    pp: dict[str, float],
    epss: dict[str, float],
    window_start: Any,
    window_end: Any,
    n_rows: int,
    pos_rate: float,
    top_k: int,
    model_meta: dict[str, Any],
    extra_notes: str | None = None,
) -> str:
    """Render the benchmark Markdown body."""

    def _fmt(x: float) -> str:
        if x != x:  # NaN
            return "n/a"
        return f"{x:.4f}"

    return (
        "# PatchPilot vs EPSS - Benchmark Report\n\n"
        f"_Generated: {datetime.now(UTC).isoformat()}_\n\n"
        f"Model artifact: `{model_meta.get('artifact', '?')}`  \n"
        f"Model version: `{model_meta.get('model_version', '?')}`  \n"
        f"Trained at: `{model_meta.get('trained_at', '?')}`  \n"
        f"Features: {model_meta.get('n_features', '?')}\n\n"
        "## Held-out window\n\n"
        "| Field | Value |\n"
        "| ----- | ----- |\n"
        f"| start | {window_start} |\n"
        f"| end   | {window_end} |\n"
        f"| n CVEs | {n_rows} |\n"
        f"| positive rate | {pos_rate:.4f} |\n\n"
        "## Headline metrics\n\n"
        f"| Model       | AUC-PR | AUC-ROC | P@{top_k} | Brier | ECE |\n"
        "| ----------- | ------ | ------- | ----- | ----- | --- |\n"
        f"| PatchPilot  | {_fmt(pp['auc_pr'])} | {_fmt(pp['auc_roc'])} | "
        f"{_fmt(pp['p_at_k'])} | {_fmt(pp['brier'])} | {_fmt(pp['ece'])} |\n"
        f"| EPSS        | {_fmt(epss['auc_pr'])} | {_fmt(epss['auc_roc'])} | "
        f"{_fmt(epss['p_at_k'])} | {_fmt(epss['brier'])} | {_fmt(epss['ece'])} |\n\n"
        "## Notes\n\n"
        "PatchPilot scores come from the latest LightGBM run; EPSS scores come from "
        "the EPSS column of the silver `cve_master.parquet`. Both models are scored "
        "on the same **calendar hold-out slice**: CVEs with `published_date >= "
        "2025-01-01`, after applying the usual 30-day right-censoring rule so labels "
        "are observable. The label is `exploited_30d` per `PLAN.md`. Training excludes "
        "this slice; see `heldout_content_sha256` "
        "in `.mlruns/<run_id>/metadata.json`.\n\n"
        "Set `NVD_API_KEY` for faster NVD paging (0.6s between requests vs ~6.5s "
        "without a key). The CLI defaults to `--nvd-max-records 50000` and "
        "`[ingest].nvd_since` from `config/settings.toml` when `--since` is omitted.\n\n"
        "If `n CVEs` above is small or the positive rate is below "
        "1%, metrics will be noisy. Prefer a wider bronze window "
        "(earlier `[ingest].nvd_since` or higher `--nvd-max-records`) before drawing "
        "firm conclusions vs EPSS.\n"
        + (f"\n**Evaluation integrity:** {extra_notes}\n" if extra_notes else "")
    )


def _update_readme_benchmark_table(
    readme_path: Path,
    *,
    pp: dict[str, float],
    epss: dict[str, float],
    top_k: int,
) -> None:
    """Replace the README benchmark table with real numbers if found."""
    if not readme_path.exists():
        return
    text = readme_path.read_text(encoding="utf-8")
    marker = "| Model       | AUC-PR | AUC-ROC |"
    if marker not in text:
        return

    def _fmt(x: float) -> str:
        if x != x:
            return "n/a"
        return f"{x:.3f}"

    old_block_lines = []
    in_block = False
    for line in text.splitlines():
        if line.startswith(marker):
            in_block = True
        if in_block:
            old_block_lines.append(line)
            if line.startswith("| EPSS"):
                break

    new_block = (
        f"| Model       | AUC-PR | AUC-ROC | P@{top_k} | Brier | ECE |\n"
        "| ----------- | ------ | ------- | ----- | ----- | --- |\n"
        f"| PatchPilot  | {_fmt(pp['auc_pr'])} | {_fmt(pp['auc_roc'])} | "
        f"{_fmt(pp['p_at_k'])} | {_fmt(pp['brier'])} | {_fmt(pp['ece'])} |\n"
        f"| EPSS        | {_fmt(epss['auc_pr'])} | {_fmt(epss['auc_roc'])} | "
        f"{_fmt(epss['p_at_k'])} | {_fmt(epss['brier'])} | {_fmt(epss['ece'])} |"
    )
    new_text = text.replace("\n".join(old_block_lines), new_block)
    readme_path.write_text(new_text, encoding="utf-8")


def write_report(
    model_uri: str = "latest",
    report_path: Path = Path("docs/benchmarks/REPORT.md"),
    *,
    silver_path: Path = Path("data/silver/cve_master.parquet"),
    mlruns_dir: Path = Path(".mlruns"),
    top_k: int = DEFAULT_TOP_K,
    readme_path: Path = Path("README.md"),
) -> Path:
    """Score PatchPilot + EPSS on the calendar hold-out window and write Markdown."""
    _ = model_uri
    silver_path = Path(silver_path)
    mlruns_dir = Path(mlruns_dir)
    report_path = Path(report_path)

    if not silver_path.exists():
        return _write_empty_report(report_path, f"silver parquet missing at {silver_path}")

    loaded = _load_latest_model_artifact(mlruns_dir)
    if loaded is None:
        return _write_empty_report(
            report_path,
            "no trained model artifact found under .mlruns/. Run `make train` first.",
        )
    model, model_meta = loaded

    frame = assemble_training_frame(silver_path)
    today = datetime.now(UTC).date()
    cutoff = today - timedelta(days=LABEL_HORIZON_DAYS)
    closed = frame.filter(right_censor_mask(frame.get_column("published_date"), today))
    if len(closed) < 50:
        return _write_empty_report(
            report_path,
            f"only {len(closed)} closed-window rows available; insufficient for evaluation. "
            f"Most recent eligible publication: <= {cutoff}.",
        )

    holdout = closed.filter(pl.col("published_date") >= pl.lit(HELDOUT_PUBLISHED_FROM))
    if len(holdout) < 1:
        return _write_empty_report(
            report_path,
            "calendar hold-out window (published_date >= 2025-01-01) has no rows after "
            "right-censoring; ingest fresher data or wait until more CVEs leave the window.",
        )

    extra_notes: str | None = None
    expected_hash = model_meta.get("heldout_content_sha256")
    if isinstance(expected_hash, str) and expected_hash:
        actual_hash = compute_holdout_content_sha256(holdout)
        if actual_hash != expected_hash:
            extra_notes = (
                f"holdout SHA-256 mismatch — metadata `{expected_hash[:12]}…` vs "
                f"current slice `{actual_hash[:12]}…`. Refresh silver and re-run "
                "`make train` before trusting this benchmark."
            )

    if holdout.get_column("exploited_30d").sum() < 1:
        return _write_empty_report(
            report_path,
            "holdout window contains no positive labels; cannot compute ranking metrics.",
        )

    feature_names = model_meta.get("feature_names") or [
        c for c in sorted(holdout.columns) if c.startswith("f_")
    ]
    x = holdout.select(feature_names).to_numpy().astype(np.float32)
    y = holdout.get_column("exploited_30d").to_numpy().astype(np.int8)
    pp_scores = model.predict_proba(x)

    cve_ids = holdout.get_column("cve_id").to_list()
    epss_baseline = EpssBaseline.from_silver(silver_path)
    epss_scores = np.asarray(epss_baseline.predict_proba(cve_ids), dtype=np.float64)

    def _metrics(scores: np.ndarray) -> dict[str, float]:
        return {
            "auc_pr": aucpr(y, scores),
            "auc_roc": auc_roc(y, scores),
            "p_at_k": precision_at_k(y, scores, k=top_k),
            "brier": brier_score(y, scores),
            "ece": expected_calibration_error(y, scores, n_bins=10),
        }

    pp_metrics = _metrics(pp_scores)
    epss_metrics = _metrics(epss_scores)

    pos_rate = float(y.mean())
    body = _render_markdown(
        pp=pp_metrics,
        epss=epss_metrics,
        window_start=holdout.get_column("published_date").min(),
        window_end=holdout.get_column("published_date").max(),
        n_rows=len(holdout),
        pos_rate=pos_rate,
        top_k=top_k,
        model_meta=model_meta,
        extra_notes=extra_notes,
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(body)

    _update_readme_benchmark_table(
        readme_path=Path(readme_path),
        pp=pp_metrics,
        epss=epss_metrics,
        top_k=top_k,
    )

    return report_path
