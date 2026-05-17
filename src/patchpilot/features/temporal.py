"""Temporal features over CVE publication history.

All features are computed point-in-time anchored at ``as_of`` so no row
sees information from after its own publication date. We deliberately
keep this small but useful: monthly/weekly counts in the recent window,
plus a row-level "days since publication" helper.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import polars as pl

TEMPORAL_FEATURE_COLUMNS: list[str] = [
    "cve_id",
    "f_cve_year",
    "f_cve_month",
    "f_cve_weekday",
    "f_age_days",
    "f_cves_published_same_week",
    "f_cves_published_same_month",
]


def build_temporal_frame(silver: pl.DataFrame, as_of: date) -> pl.DataFrame:
    """Pure transformation; never reads information past ``as_of``."""
    visible = silver.filter(pl.col("published_date") <= as_of)

    # Bucket each visible CVE into year+week / year+month for counting.
    bucketed = visible.with_columns(
        pl.col("published_date").dt.year().alias("_year"),
        pl.col("published_date").dt.week().alias("_week"),
        pl.col("published_date").dt.month().alias("_month"),
    )

    weekly = bucketed.group_by(["_year", "_week"]).len().rename({"len": "_cnt_week"})
    monthly = bucketed.group_by(["_year", "_month"]).len().rename({"len": "_cnt_month"})

    joined = (
        bucketed.join(weekly, on=["_year", "_week"], how="left")
        .join(monthly, on=["_year", "_month"], how="left")
    )

    return joined.select(
        pl.col("cve_id"),
        pl.col("_year").cast(pl.Int32).alias("f_cve_year"),
        pl.col("_month").cast(pl.Int32).alias("f_cve_month"),
        pl.col("published_date").dt.weekday().cast(pl.Int32).alias("f_cve_weekday"),
        ((pl.lit(as_of) - pl.col("published_date")).dt.total_days())
        .cast(pl.Int32)
        .alias("f_age_days"),
        pl.col("_cnt_week").cast(pl.Int32).alias("f_cves_published_same_week"),
        pl.col("_cnt_month").cast(pl.Int32).alias("f_cves_published_same_month"),
    )


def build_temporal_features(silver_path: Path, as_of: date, out_path: Path) -> Path:
    """Materialize point-in-time temporal features."""
    silver_path = Path(silver_path)
    out_path = Path(out_path)
    silver = pl.read_parquet(silver_path)
    features = build_temporal_frame(silver, as_of=as_of)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    features.write_parquet(out_path, compression="zstd")
    return out_path


def build_temporal_frame_default(silver: pl.DataFrame) -> pl.DataFrame:
    """Use the most recent ``published_date`` (or today) as ``as_of``.

    Helper for training: we want features as if "today" is the day of the
    latest CVE in the silver frame. The temporal-cv splitter restricts
    which rows enter each fold so this does not leak.
    """
    raw_max = silver.get_column("published_date").max()
    anchor = raw_max if isinstance(raw_max, date) else date.today()
    return build_temporal_frame(silver, as_of=anchor)
