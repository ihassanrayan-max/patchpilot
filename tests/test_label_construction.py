"""Label construction tests for ``exploited_30d``.

Verifies the silver builder implements the rule from ``PLAN.md`` exactly:

    exploited_30d(cve) := (cve.cve_id in CISA_KEV)
                          AND (KEV.date_added <= cve.published_date + 30 days)

and that the right-censoring mask correctly excludes recent publications.
"""

from __future__ import annotations

from datetime import date, timedelta

import polars as pl
import pytest

from patchpilot.ingest.silver import (
    LABEL_HORIZON_DAYS,
    build_cve_master,
    label_exploited_30d_frame,
    right_censor_mask,
)


@pytest.fixture()
def kev_frame() -> pl.DataFrame:
    """Fixture: tiny KEV frame with a known date for one CVE."""
    return pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "date_added": [date(2024, 1, 15), date(2024, 6, 1)],
        }
    )


def test_exploited_30d_true_when_in_kev_within_window(kev_frame: pl.DataFrame) -> None:
    """KEV entry dated 14d after publication -> exploited_30d=True."""
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "published_date": [date(2024, 1, 1)],
        }
    )
    out = label_exploited_30d_frame(df, kev_frame)
    assert out["in_kev"].to_list() == [True]
    assert out["exploited_30d"].to_list() == [True]
    assert out["kev_date_added"].to_list() == [date(2024, 1, 15)]


def test_exploited_30d_false_when_kev_after_30_days(kev_frame: pl.DataFrame) -> None:
    """KEV entry added 31 days after publication -> exploited_30d=False."""
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0002"],
            "published_date": [date(2024, 5, 1)],
        }
    )
    out = label_exploited_30d_frame(df, kev_frame)
    assert out["in_kev"].to_list() == [True]
    assert out["exploited_30d"].to_list() == [False]


def test_exploited_30d_false_when_not_in_kev(kev_frame: pl.DataFrame) -> None:
    """Unknown CVE -> in_kev=False, exploited_30d=False."""
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-9999"],
            "published_date": [date(2024, 1, 1)],
        }
    )
    out = label_exploited_30d_frame(df, kev_frame)
    assert out["in_kev"].to_list() == [False]
    assert out["exploited_30d"].to_list() == [False]
    assert out["kev_date_added"].to_list() == [None]


def test_exploited_30d_boundary_at_exactly_30_days(kev_frame: pl.DataFrame) -> None:
    """Boundary: KEV.date_added == published + 30d is INSIDE the window (<=)."""
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "published_date": [date(2024, 1, 15) - timedelta(days=30)],
        }
    )
    out = label_exploited_30d_frame(df, kev_frame)
    assert out["exploited_30d"].to_list() == [True]


def test_label_horizon_constant_matches_plan() -> None:
    """Sanity guard: PLAN.md fixes the horizon at 30 days."""
    assert LABEL_HORIZON_DAYS == 30


def test_right_censor_mask_excludes_recent() -> None:
    """Right-censoring excludes rows published within the horizon of today."""
    today = date(2024, 5, 31)
    published = pl.Series(
        [
            date(2024, 1, 1),
            date(2024, 5, 1),
            date(2024, 5, 30),
        ]
    )
    mask = right_censor_mask(published, today).to_list()
    assert mask == [True, True, False]


def test_build_cve_master_columns_and_label(kev_frame: pl.DataFrame) -> None:
    """End-to-end silver build produces the contract schema + correct label."""
    nvd = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-9999"],
            "published_date": [date(2024, 1, 1), date(2024, 1, 1), date(2024, 1, 1)],
            "last_modified_date": [date(2024, 2, 1), date(2024, 6, 2), date(2024, 1, 5)],
            "cvss_v3_base_score": [9.8, 5.5, None],
            "cvss_v3_severity": ["CRITICAL", "MEDIUM", None],
            "cvss_v3_vector": ["AV:N/...", "AV:N/...", None],
            "cwe_ids": [["CWE-79"], ["CWE-22"], None],
            "vendor_count": [1, 2, 0],
            "product_count": [3, 4, 0],
            "description_len": [120, 80, 0],
            "ref_has_exploit": [True, False, False],
            "ref_has_patch": [True, True, False],
        }
    )
    epss = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "epss_score": [0.42],
            "epss_percentile": [0.95],
            "snapshot_date": [date(2024, 1, 10)],
        }
    )

    master = build_cve_master(nvd, kev_frame, epss)
    expected_columns = {
        "cve_id",
        "published_date",
        "last_modified_date",
        "cvss_v3_base_score",
        "cvss_v3_severity",
        "cvss_v3_vector",
        "cwe_ids",
        "vendor_count",
        "product_count",
        "description_len",
        "ref_has_exploit",
        "ref_has_patch",
        "epss_score",
        "epss_percentile",
        "epss_snapshot_date",
        "in_kev",
        "kev_date_added",
        "exploited_30d",
    }
    assert set(master.columns) == expected_columns

    labels = dict(zip(master["cve_id"].to_list(), master["exploited_30d"].to_list(), strict=True))
    assert labels["CVE-2024-0001"] is True
    assert labels["CVE-2024-0002"] is False
    assert labels["CVE-2024-9999"] is False

    in_kev = dict(zip(master["cve_id"].to_list(), master["in_kev"].to_list(), strict=True))
    assert in_kev == {
        "CVE-2024-0001": True,
        "CVE-2024-0002": True,
        "CVE-2024-9999": False,
    }
