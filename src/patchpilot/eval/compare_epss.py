"""Side-by-side PatchPilot vs EPSS evaluation report writer.

Scores the latest trained model and the EPSS baseline on the same rolling
closed-window holdout (most recent right-censored slice that meets configured
minimums). Writes ``docs/benchmarks/REPORT.md`` and keeps the README table
in sync.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from datetime import UTC, date, datetime, timedelta
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
from patchpilot.train.holdout import (
    HoldoutWindow,
    compute_holdout_content_sha256,
    load_eval_holdout_config,
    select_eval_holdout,
)
from patchpilot.train.train import assemble_training_frame

DEFAULT_TOP_K = 100
README_TABLE_MARKER = "| Model       | AUC-PR | AUC-ROC |"


def _load_config(config_path: Path) -> dict[str, Any]:
    with config_path.open("rb") as fh:
        return tomllib.load(fh)


def _resolve_artifact_path(mlruns_dir: Path, info: dict[str, Any]) -> Path | None:
    """Resolve artifact from ``latest.json``, tolerating cwd-relative paths."""
    raw = info.get("artifact")
    if isinstance(raw, str) and raw:
        candidate = Path(raw)
        if candidate.exists():
            return candidate
    run_id = info.get("run_id")
    if isinstance(run_id, str) and run_id:
        fallback = mlruns_dir / run_id / "model.pkl"
        if fallback.exists():
            return fallback
    return None


def _load_latest_model_artifact(mlruns_dir: Path) -> tuple[LgbmModel, dict[str, Any]] | None:
    """Locate the latest training artifact + metadata."""
    pointer = mlruns_dir / "latest.json"
    if not pointer.exists():
        return None
    info = cast(dict[str, Any], json.loads(pointer.read_text()))
    artifact = _resolve_artifact_path(mlruns_dir, info)
    if artifact is None:
        return None
    model = LgbmModel.load(artifact)
    meta_path = artifact.parent / "metadata.json"
    meta = cast(dict[str, Any], json.loads(meta_path.read_text())) if meta_path.exists() else {}
    return model, meta


def _fmt_metric(x: float) -> str:
    if x != x:
        return "n/a"
    return f"{x:.4f}"


def _fmt_readme_metric(x: float) -> str:
    if x != x:
        return "n/a"
    return f"{x:.3f}"


def _censoring_note() -> str:
    return (
        f"Rows with `published_date > today_utc - {LABEL_HORIZON_DAYS} days` are excluded "
        f"because their {LABEL_HORIZON_DAYS}-day exploitation label window has not closed."
    )


def _render_unavailable_report(
    *,
    reason: str,
    closed_n_rows: int | None = None,
    closed_start: date | None = None,
    closed_end: date | None = None,
    train_start: date | None = None,
    train_end: date | None = None,
    eval_start: date | None = None,
    eval_end: date | None = None,
    holdout_n_rows: int | None = None,
    holdout_n_positives: int | None = None,
) -> str:
    """Render an honest unavailable benchmark report."""
    def _cell(value: Any) -> str:
        return str(value) if value is not None else "n/a"

    return (
        "# PatchPilot vs EPSS - Benchmark Report\n\n"
        f"_Generated: {datetime.now(UTC).isoformat()}_\n\n"
        "**Status:** unavailable - could not compute metrics.\n\n"
        f"**Reason:** {reason}\n\n"
        "## Dataset windows\n\n"
        "| Field | Value |\n"
        "| ----- | ----- |\n"
        f"| closed rows (after censoring) | {_cell(closed_n_rows)} |\n"
        f"| closed publication range | {_cell(closed_start)} .. {_cell(closed_end)} |\n"
        f"| train publication range | {_cell(train_start)} .. {_cell(train_end)} |\n"
        f"| eval publication range | {_cell(eval_start)} .. {_cell(eval_end)} |\n"
        f"| eval rows | {_cell(holdout_n_rows)} |\n"
        f"| eval positives | {_cell(holdout_n_positives)} |\n\n"
        "## Right-censoring rule\n\n"
        f"{_censoring_note()}\n\n"
        "## Headline metrics\n\n"
        "| Model | AUC-PR | AUC-ROC | P@100 | Brier | ECE |\n"
        "| ----- | ------ | ------- | ----- | ----- | --- |\n"
        "| PatchPilot | n/a | n/a | n/a | n/a | n/a |\n"
        "| EPSS | n/a | n/a | n/a | n/a | n/a |\n\n"
        "Re-run `make ingest` and `make train` to refresh inputs, then `make eval`.\n"
    )


def _render_markdown(
    *,
    pp: dict[str, float],
    epss: dict[str, float],
    window: HoldoutWindow,
    closed_n_rows: int,
    closed_start: date,
    closed_end: date,
    train_start: date | None,
    train_end: date | None,
    top_k: int,
    model_meta: dict[str, Any],
    extra_notes: str | None = None,
) -> str:
    """Render a successful benchmark report."""
    pos_rate = window.n_positives / window.n_rows if window.n_rows else 0.0
    return (
        "# PatchPilot vs EPSS - Benchmark Report\n\n"
        f"_Generated: {datetime.now(UTC).isoformat()}_\n\n"
        "**Status:** ok - metrics computed.\n\n"
        f"Model artifact: `{model_meta.get('artifact', '?')}`  \n"
        f"Model version: `{model_meta.get('model_version', '?')}`  \n"
        f"Trained at: `{model_meta.get('trained_at', '?')}`  \n"
        f"Features: {model_meta.get('n_features', '?')}\n\n"
        "## Dataset windows\n\n"
        "| Field | Value |\n"
        "| ----- | ----- |\n"
        f"| closed rows (after censoring) | {closed_n_rows} |\n"
        f"| closed publication range | {closed_start} .. {closed_end} |\n"
        f"| train publication range | {train_start} .. {train_end} |\n"
        f"| eval publication range | {window.start} .. {window.end} |\n"
        f"| eval window length | {window.window_days} days |\n"
        f"| eval rows | {window.n_rows} |\n"
        f"| eval positives | {window.n_positives} |\n"
        f"| eval positive rate | {pos_rate:.4f} |\n\n"
        "## Right-censoring rule\n\n"
        f"{_censoring_note()}\n\n"
        "## Headline metrics\n\n"
        f"| Model | AUC-PR | AUC-ROC | P@{top_k} | Brier | ECE |\n"
        "| ----- | ------ | ------- | ----- | ----- | --- |\n"
        f"| PatchPilot | {_fmt_metric(pp['auc_pr'])} | {_fmt_metric(pp['auc_roc'])} | "
        f"{_fmt_metric(pp['p_at_k'])} | {_fmt_metric(pp['brier'])} | {_fmt_metric(pp['ece'])} |\n"
        f"| EPSS | {_fmt_metric(epss['auc_pr'])} | {_fmt_metric(epss['auc_roc'])} | "
        f"{_fmt_metric(epss['p_at_k'])} | {_fmt_metric(epss['brier'])} | {_fmt_metric(epss['ece'])} |\n\n"
        "## Notes\n\n"
        "PatchPilot scores come from the latest trained artifact (EPSS-complement: "
        "`clamp01(epss + residual)` when the strategy is active); EPSS scores come "
        "from the same point-in-time `f_epss_score` feature used at training time "
        "(not a live/current lookup), so the comparison is a fair head-to-head. "
        "Both models are scored on the same rolling closed-window holdout selected "
        "by `select_eval_holdout` (most recent right-censored slice meeting configured minimums). "
        "The label is `exploited_30d` per `PLAN.md`. Training excludes this slice; "
        "see `heldout_content_sha256` in `.mlruns/<run_id>/metadata.json`.\n"
        + (f"\n**Evaluation integrity:** {extra_notes}\n" if extra_notes else "")
    )


def _replace_readme_benchmark_block(readme_path: Path, new_block: str) -> None:
    if not readme_path.exists():
        return
    text = readme_path.read_text(encoding="utf-8")
    if README_TABLE_MARKER not in text:
        return

    old_block_lines: list[str] = []
    in_block = False
    for line in text.splitlines():
        if line.startswith(README_TABLE_MARKER):
            in_block = True
        if in_block:
            old_block_lines.append(line)
            if line.startswith("| EPSS"):
                break

    readme_path.write_text(text.replace("\n".join(old_block_lines), new_block), encoding="utf-8")


def _sync_readme_unavailable(readme_path: Path, *, top_k: int) -> None:
    block = (
        f"| Model       | AUC-PR | AUC-ROC | P@{top_k} | Brier | ECE |\n"
        "| ----------- | ------ | ------- | ----- | ----- | --- |\n"
        "| PatchPilot  | n/a | n/a | n/a | n/a | n/a |\n"
        "| EPSS        | n/a | n/a | n/a | n/a | n/a |"
    )
    _replace_readme_benchmark_block(readme_path, block)


def _sync_readme_metrics(
    readme_path: Path,
    *,
    pp: dict[str, float],
    epss: dict[str, float],
    top_k: int,
) -> None:
    block = (
        f"| Model       | AUC-PR | AUC-ROC | P@{top_k} | Brier | ECE |\n"
        "| ----------- | ------ | ------- | ----- | ----- | --- |\n"
        f"| PatchPilot  | {_fmt_readme_metric(pp['auc_pr'])} | {_fmt_readme_metric(pp['auc_roc'])} | "
        f"{_fmt_readme_metric(pp['p_at_k'])} | {_fmt_readme_metric(pp['brier'])} | {_fmt_readme_metric(pp['ece'])} |\n"
        f"| EPSS        | {_fmt_readme_metric(epss['auc_pr'])} | {_fmt_readme_metric(epss['auc_roc'])} | "
        f"{_fmt_readme_metric(epss['p_at_k'])} | {_fmt_readme_metric(epss['brier'])} | {_fmt_readme_metric(epss['ece'])} |"
    )
    _replace_readme_benchmark_block(readme_path, block)


def _write_unavailable_report(
    report_path: Path,
    readme_path: Path,
    *,
    reason: str,
    top_k: int,
    closed: pl.DataFrame | None = None,
    window: HoldoutWindow | None = None,
) -> Path:
    closed_n_rows = len(closed) if closed is not None else None
    closed_start = closed.get_column("published_date").min() if closed is not None and len(closed) else None
    closed_end = closed.get_column("published_date").max() if closed is not None and len(closed) else None
    train_start = closed_start
    train_end = (
        window.start - timedelta(days=1)
        if window is not None and closed is not None and len(closed)
        else None
    )
    body = _render_unavailable_report(
        reason=reason,
        closed_n_rows=closed_n_rows,
        closed_start=closed_start if isinstance(closed_start, date) else None,
        closed_end=closed_end if isinstance(closed_end, date) else None,
        train_start=train_start if isinstance(train_start, date) else None,
        train_end=train_end if isinstance(train_end, date) else None,
        eval_start=window.start if window is not None else None,
        eval_end=window.end if window is not None else None,
        holdout_n_rows=window.n_rows if window is not None else None,
        holdout_n_positives=window.n_positives if window is not None else None,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(body, encoding="utf-8")
    _sync_readme_unavailable(readme_path, top_k=top_k)
    return report_path


def write_report(
    model_uri: str = "latest",
    report_path: Path = Path("docs/benchmarks/REPORT.md"),
    *,
    silver_path: Path = Path("data/silver/cve_master.parquet"),
    mlruns_dir: Path = Path(".mlruns"),
    top_k: int | None = None,
    readme_path: Path = Path("README.md"),
    config_path: Path = Path("config/settings.toml"),
) -> Path:
    """Score PatchPilot + EPSS on the rolling holdout window and write Markdown."""
    _ = model_uri
    silver_path = Path(silver_path)
    mlruns_dir = Path(mlruns_dir)
    report_path = Path(report_path)
    readme_path = Path(readme_path)
    config_path = Path(config_path)

    config = _load_config(config_path) if config_path.exists() else {}
    eval_cfg = config.get("eval") or {}
    top_k_eff = int(top_k if top_k is not None else eval_cfg.get("top_k", DEFAULT_TOP_K))
    holdout_cfg = load_eval_holdout_config(config)

    if not silver_path.exists():
        return _write_unavailable_report(
            report_path,
            readme_path,
            reason=f"silver parquet missing at {silver_path}",
            top_k=top_k_eff,
        )

    loaded = _load_latest_model_artifact(mlruns_dir)
    if loaded is None:
        return _write_unavailable_report(
            report_path,
            readme_path,
            reason="no trained model artifact found under .mlruns/. Run `make train` first.",
            top_k=top_k_eff,
        )
    model, model_meta = loaded

    bronze_dir = silver_path.parent.parent / "bronze"
    frame = assemble_training_frame(silver_path, bronze_dir=bronze_dir)
    today = datetime.now(UTC).date()
    closed = frame.filter(right_censor_mask(frame.get_column("published_date"), today))

    selection = select_eval_holdout(closed, holdout_cfg)
    if selection.window is None or selection.holdout_frame is None:
        return _write_unavailable_report(
            report_path,
            readme_path,
            reason=selection.reason or "rolling holdout could not be selected",
            top_k=top_k_eff,
            closed=closed,
        )

    window = selection.window
    holdout = selection.holdout_frame

    extra_notes: str | None = None
    expected_hash = model_meta.get("heldout_content_sha256")
    if isinstance(expected_hash, str) and expected_hash:
        actual_hash = compute_holdout_content_sha256(holdout)
        if actual_hash != expected_hash:
            extra_notes = (
                f"holdout SHA-256 mismatch - metadata `{expected_hash[:12]}...` vs "
                f"current slice `{actual_hash[:12]}...`. Refresh silver and re-run "
                "`make train` before trusting this benchmark."
            )

    feature_names = model_meta.get("feature_names") or [
        c for c in sorted(holdout.columns) if c.startswith("f_")
    ]
    x = holdout.select(feature_names).to_numpy().astype(np.float32)
    y = holdout.get_column("exploited_30d").to_numpy().astype(np.int8)

    # Fair PIT EPSS baseline: score the EPSS column with the *same*
    # point-in-time snapshot used for training/PatchPilot features
    # (`f_epss_score`), not a live/current lookup against silver. The two
    # can disagree for CVEs whose EPSS score moved after publication, which
    # previously made the "EPSS" row of this report an easier target than
    # what PatchPilot actually trained against.
    if "f_epss_score" in holdout.columns:
        epss_scores = holdout.get_column("f_epss_score").to_numpy().astype(np.float64)
    else:
        cve_ids = holdout.get_column("cve_id").to_list()
        epss_baseline = EpssBaseline.from_silver(silver_path)
        epss_scores = np.asarray(epss_baseline.predict_proba(cve_ids), dtype=np.float64)

    strategy = str(model_meta.get("strategy", ""))
    model_task = str(getattr(model, "task", model_meta.get("task", "classification")))
    if strategy == "epss_complement" and model_task == "regression":
        residual = model.predict_raw(x)
        pp_scores = np.clip(epss_scores + np.asarray(residual, dtype=np.float64), 0.0, 1.0)
    else:
        pp_scores = model.predict_proba(x)

    def _metrics(scores: np.ndarray) -> dict[str, float]:
        return {
            "auc_pr": aucpr(y, scores),
            "auc_roc": auc_roc(y, scores),
            "p_at_k": precision_at_k(y, scores, k=top_k_eff),
            "brier": brier_score(y, scores),
            "ece": expected_calibration_error(y, scores, n_bins=10),
        }

    pp_metrics = _metrics(pp_scores)
    epss_metrics = _metrics(epss_scores)

    if strategy == "epss_complement" and model_task == "regression":
        lift = pp_metrics["auc_pr"] - epss_metrics["auc_pr"]
        lift_note = (
            f"EPSS-complement strategy active: PatchPilot = clamp01(EPSS + residual). "
            f"Lift over EPSS on this holdout is delta-AUC-PR = {lift:+.4f} "
            f"({'above' if lift > 0 else 'at or below'} the EPSS-only baseline)."
        )
        extra_notes = f"{extra_notes} {lift_note}" if extra_notes else lift_note

    train_rows = closed.filter(pl.col("published_date") < pl.lit(window.start))
    train_start = train_rows.get_column("published_date").min() if len(train_rows) else None
    train_end = train_rows.get_column("published_date").max() if len(train_rows) else None
    closed_start_raw = closed.get_column("published_date").min()
    closed_end_raw = closed.get_column("published_date").max()
    if not isinstance(closed_start_raw, date) or not isinstance(closed_end_raw, date):
        return _write_unavailable_report(
            report_path,
            readme_path,
            reason="could not determine closed publication date range",
            top_k=top_k_eff,
            closed=closed,
        )

    body = _render_markdown(
        pp=pp_metrics,
        epss=epss_metrics,
        window=window,
        closed_n_rows=len(closed),
        closed_start=closed_start_raw,
        closed_end=closed_end_raw,
        train_start=train_start if isinstance(train_start, date) else None,
        train_end=train_end if isinstance(train_end, date) else None,
        top_k=top_k_eff,
        model_meta=model_meta,
        extra_notes=extra_notes,
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(body, encoding="utf-8")
    _sync_readme_metrics(
        readme_path,
        pp=pp_metrics,
        epss=epss_metrics,
        top_k=top_k_eff,
    )
    return report_path


def assert_benchmark_gate(
    report_path: Path = Path("docs/benchmarks/REPORT.md"),
    *,
    config_path: Path = Path("config/settings.toml"),
) -> None:
    """Exit with code 1 when the report lacks metrics or fails the AUC-PR margin."""
    report_path = Path(report_path)
    config_path = Path(config_path)
    body = report_path.read_text(encoding="utf-8")
    if "could not compute metrics" in body or "**Status:** unavailable" in body:
        print(f"benchmark gate: no metrics in {report_path}", file=sys.stderr)
        raise SystemExit(1)

    def _parse_auc_pr(model: str) -> float | None:
        match = re.search(rf"\| {re.escape(model)}\s+\| ([0-9.]+)", body)
        if match is None:
            return None
        return float(match.group(1))

    pp_auc_pr = _parse_auc_pr("PatchPilot")
    epss_auc_pr = _parse_auc_pr("EPSS")
    if pp_auc_pr is None or epss_auc_pr is None:
        print("benchmark gate: could not parse headline AUC-PR values", file=sys.stderr)
        raise SystemExit(1)

    with config_path.open("rb") as fh:
        eval_cfg = tomllib.load(fh).get("eval") or {}
    margin_raw = eval_cfg.get("auc_pr_margin", 1.0)
    margin = float(margin_raw)
    gap = epss_auc_pr - pp_auc_pr
    if gap > margin:
        print(
            "benchmark gate failed: EPSS AUC-PR "
            f"({epss_auc_pr:.4f}) exceeds PatchPilot ({pp_auc_pr:.4f}) "
            f"by {gap:.4f} > margin {margin:.4f}",
            file=sys.stderr,
        )
        raise SystemExit(1)
