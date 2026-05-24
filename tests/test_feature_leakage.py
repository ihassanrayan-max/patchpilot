"""Regression tests for point-in-time feature construction (no future leakage)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import polars as pl
import pyarrow.parquet as pq
import pytest

from patchpilot.features.graph import build_graph_frame
from patchpilot.features.point_in_time import (
    assemble_feature_frame,
    build_graph_frame_per_row,
    build_temporal_frame_per_row,
    join_epss_as_of,
    load_epss_history,
)
from patchpilot.features.tabular import TABULAR_FEATURE_COLUMNS
from patchpilot.features.temporal import build_temporal_frame_default
from patchpilot.train.train import assemble_training_frame


def _silver_frame() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "published_date": [date(2024, 6, 1), date(2024, 6, 15), date(2024, 1, 15)],
            "last_modified_date": [date(2024, 6, 2), date(2024, 6, 16), date(2024, 2, 1)],
            "cvss_v3_base_score": [9.8, 5.5, 7.0],
            "cvss_v3_severity": ["CRITICAL", "MEDIUM", "HIGH"],
            "cvss_v3_vector": ["AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/...", "AV:N/..."],
            "cwe_ids": [["CWE-79"], ["CWE-22"], ["CWE-22"]],
            "vendor_count": [1, 1, 1],
            "product_count": [1, 1, 1],
            "description_len": [100, 80, 90],
            "ref_has_exploit": [True, False, False],
            "ref_has_patch": [True, True, False],
            "epss_score": [0.90, 0.10, 0.50],
            "epss_percentile": [0.99, 0.20, 0.60],
            "epss_snapshot_date": [date(2024, 12, 1), date(2024, 12, 1), date(2024, 12, 1)],
            "in_kev": [True, False, False],
            "kev_date_added": [date(2024, 6, 5), None, None],
            "exploited_30d": [True, False, False],
        }
    )


def test_tabular_features_exclude_leaky_kev_and_epss_columns() -> None:
    """Tabular projection must not include current KEV or EPSS snapshot columns."""
    tabular_cols = set(TABULAR_FEATURE_COLUMNS)
    assert "f_in_kev_prior" not in tabular_cols
    assert "f_epss_score" not in tabular_cols
    assert "f_epss_percentile" not in tabular_cols
    assert "f_epss_percentile_x_in_kev" not in tabular_cols


def test_temporal_per_row_excludes_future_publications() -> None:
    """Earlier CVEs must not see later CVEs in same-month publication counts."""
    silver = _silver_frame()
    per_row = build_temporal_frame_per_row(silver).sort("cve_id")
    leaky = build_temporal_frame_default(silver).sort("cve_id")

    june_early_per_row = int(
        per_row.filter(pl.col("cve_id") == "CVE-2024-0001")["f_cves_published_same_month"][0]
    )
    june_early_leaky = int(
        leaky.filter(pl.col("cve_id") == "CVE-2024-0001")["f_cves_published_same_month"][0]
    )

    assert june_early_per_row == 1
    assert june_early_leaky == 2
    assert june_early_per_row < june_early_leaky


def test_graph_per_row_excludes_future_cwe_popularity() -> None:
    """CWE popularity for an early CVE must ignore later CVEs sharing the same CWE."""
    silver = _silver_frame()
    per_row = build_graph_frame_per_row(silver).sort("cve_id")
    leaky = build_graph_frame(silver).sort("cve_id")

    jan_per_row = per_row.filter(pl.col("cve_id") == "CVE-2024-0003")
    jan_leaky = leaky.filter(pl.col("cve_id") == "CVE-2024-0003")

    assert int(jan_per_row["f_max_cwe_popularity"][0]) == 1
    assert int(jan_leaky["f_max_cwe_popularity"][0]) == 2
    assert int(jan_per_row["f_max_cwe_popularity"][0]) < int(jan_leaky["f_max_cwe_popularity"][0])


def test_epss_as_of_uses_snapshot_on_or_before_publication(tmp_path: Path) -> None:
    """EPSS features must come from the latest snapshot not after publication."""
    silver = _silver_frame()
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir()
    early = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "epss_score": [0.01, 0.02],
            "epss_percentile": [0.10, 0.20],
            "snapshot_date": [date(2024, 1, 1), date(2024, 1, 1)],
        }
    )
    late = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "epss_score": [0.91, 0.92, 0.93],
            "epss_percentile": [0.91, 0.92, 0.93],
            "snapshot_date": [date(2024, 12, 1), date(2024, 12, 1), date(2024, 12, 1)],
        }
    )
    pq.write_table(early.to_arrow(), epss_dir / "2024-01-01.parquet")
    pq.write_table(late.to_arrow(), epss_dir / "2024-12-01.parquet")

    history = load_epss_history(epss_dir)
    joined = join_epss_as_of(silver, history).sort("cve_id")

    row = joined.filter(pl.col("cve_id") == "CVE-2024-0001")
    assert float(row["f_epss_score"][0]) == pytest.approx(0.01)
    assert float(row["f_epss_percentile"][0]) == pytest.approx(0.10)

    june_row = joined.filter(pl.col("cve_id") == "CVE-2024-0002")
    assert float(june_row["f_epss_score"][0]) == pytest.approx(0.02)


def test_assemble_training_frame_has_no_leaky_feature_columns(tmp_path: Path) -> None:
    """Training frame must not expose current KEV membership as a model feature."""
    silver_path = tmp_path / "silver" / "cve_master.parquet"
    silver_path.parent.mkdir(parents=True)
    _silver_frame().write_parquet(silver_path)

    epss_dir = tmp_path / "bronze" / "epss"
    epss_dir.mkdir(parents=True)
    epss = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "epss_score": [0.05],
            "epss_percentile": [0.15],
            "snapshot_date": [date(2024, 1, 1)],
        }
    )
    pq.write_table(epss.to_arrow(), epss_dir / "2024-01-01.parquet")

    frame = assemble_training_frame(silver_path, bronze_dir=tmp_path / "bronze")
    feature_cols = {c for c in frame.columns if c.startswith("f_")}

    assert "f_in_kev_prior" not in feature_cols
    assert "f_epss_percentile_x_in_kev" not in feature_cols
    assert "f_epss_score" in feature_cols
    assert "f_epss_percentile" in feature_cols


def test_point_in_time_vs_live_scoring_epss_differ_when_snapshots_are_newer() -> None:
    """Live scoring may use current EPSS; training must not for pre-snapshot CVEs."""
    silver = _silver_frame()
    train_feats = assemble_feature_frame(silver, point_in_time=True)
    score_feats = assemble_feature_frame(silver, point_in_time=False)

    train_early = train_feats.filter(pl.col("cve_id") == "CVE-2024-0001")
    score_early = score_feats.filter(pl.col("cve_id") == "CVE-2024-0001")

    assert float(train_early["f_epss_score"][0]) == 0.0
    assert float(score_early["f_epss_score"][0]) == pytest.approx(0.90)
