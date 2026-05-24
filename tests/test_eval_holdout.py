"""Tests for rolling holdout selection and fixture-based eval reports."""

from __future__ import annotations

import os
from datetime import date, timedelta
from pathlib import Path

import polars as pl
import pyarrow.parquet as pq

from patchpilot.eval.compare_epss import write_report
from patchpilot.train.holdout import EvalHoldoutConfig, select_eval_holdout
from patchpilot.train.train import train_lgbm


def _closed_rows(start: date, n_days: int, *, positive_every: int = 25) -> pl.DataFrame:
    rows: list[dict[str, object]] = []
    for offset in range(n_days):
        pub = start + timedelta(days=offset)
        positive = offset % positive_every == 0
        rows.append(
            {
                "cve_id": f"CVE-2024-{offset:05d}",
                "published_date": pub,
                "last_modified_date": pub + timedelta(days=1),
                "cvss_v3_base_score": 7.5,
                "cvss_v3_severity": "HIGH",
                "cvss_v3_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe_ids": ["CWE-79"],
                "vendor_count": 1,
                "product_count": 1,
                "description_len": 100,
                "ref_has_exploit": False,
                "ref_has_patch": True,
                "epss_score": 0.15,
                "epss_percentile": 0.40,
                "epss_snapshot_date": pub,
                "in_kev": positive,
                "kev_date_added": pub + timedelta(days=5) if positive else None,
                "exploited_30d": positive,
            }
        )
    return pl.DataFrame(rows)


def test_select_eval_holdout_picks_most_recent_window() -> None:
    closed = _closed_rows(date(2024, 1, 1), 200, positive_every=20)
    cfg = EvalHoldoutConfig(holdout_days=90, min_rows=50, min_positives=1, min_holdout_days=14)
    selection = select_eval_holdout(closed, cfg)

    assert selection.window is not None
    assert selection.holdout_frame is not None
    assert selection.reason is None
    assert selection.window.end == date(2024, 7, 18)
    assert selection.window.n_rows >= 50
    assert selection.window.n_positives >= 1


def test_select_eval_holdout_reports_reason_when_too_sparse() -> None:
    closed = _closed_rows(date(2024, 1, 1), 10, positive_every=100)
    cfg = EvalHoldoutConfig(holdout_days=90, min_rows=50, min_positives=1, min_holdout_days=14)
    selection = select_eval_holdout(closed, cfg)

    assert selection.window is None
    assert selection.reason is not None
    assert "minimums" in selection.reason


def test_write_report_fixture_produces_numeric_metrics(tmp_path: Path) -> None:
    """End-to-end: synthetic silver + train + eval yields numeric REPORT/README."""
    data_dir = tmp_path / "data"
    silver_dir = data_dir / "silver"
    bronze_dir = data_dir / "bronze"
    silver_dir.mkdir(parents=True)
    bronze_dir.mkdir(parents=True)

    silver = _closed_rows(date(2023, 6, 1), 220, positive_every=18)
    silver_path = silver_dir / "cve_master.parquet"
    silver.write_parquet(silver_path)

    epss = silver.select(
        pl.col("cve_id"),
        pl.col("epss_score"),
        pl.col("epss_percentile"),
        pl.col("published_date").alias("snapshot_date"),
    )
    epss_dir = bronze_dir / "epss"
    epss_dir.mkdir(parents=True)
    pq.write_table(epss.to_arrow(), epss_dir / "2024-01-01.parquet")

    config_path = tmp_path / "settings.toml"
    config_path.write_text(
        """
[paths]
data_dir = "data"
bronze_dir = "data/bronze"
silver_dir = "data/silver"
gold_dir = "data/gold"
mlruns_dir = ".mlruns"
reports_dir = "docs/benchmarks"

[features]
include_tabular = true
include_temporal = true
include_graph = false

[train]
n_splits = 2
embargo_days = 30
seed = 42

[train.lgbm]
objective = "binary"
learning_rate = 0.1
num_leaves = 15
min_data_in_leaf = 20
n_estimators = 50

[eval]
top_k = 10
holdout_days = 60
min_holdout_rows = 40
min_holdout_positives = 1
min_holdout_days = 14
auc_pr_margin = 1.0
""".strip(),
        encoding="utf-8",
    )

    readme_path = tmp_path / "README.md"
    readme_path.write_text(
        "| Model       | AUC-PR | AUC-ROC | P@100 | Brier | ECE |\n"
        "| ----------- | ------ | ------- | ----- | ----- | --- |\n"
        "| PatchPilot  | n/a | n/a | n/a | n/a | n/a |\n"
        "| EPSS        | n/a | n/a | n/a | n/a | n/a |\n",
        encoding="utf-8",
    )
    report_path = tmp_path / "docs" / "benchmarks" / "REPORT.md"

    original_cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        train_lgbm(config_path)
        write_report(
            report_path=report_path,
            silver_path=silver_path,
            mlruns_dir=Path(".mlruns"),
            readme_path=readme_path,
            config_path=config_path,
        )
    finally:
        os.chdir(original_cwd)

    report = report_path.read_text(encoding="utf-8")
    readme = readme_path.read_text(encoding="utf-8")

    assert "**Status:** ok" in report
    assert "eval rows" in report
    assert "eval positives" in report
    assert "Right-censoring rule" in report
    assert "| PatchPilot |" in report
    assert "n/a" not in report.split("Headline metrics")[1].split("PatchPilot")[1][:80]

    assert "| PatchPilot  |" in readme
    assert "n/a" not in readme.split("| PatchPilot")[1].split("\n")[0]
