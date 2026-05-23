"""Tabular features derived directly from ``cve_master.parquet`` columns.

Pure, deterministic projection of silver columns into numeric/boolean
features the model can consume. The label and any time-series state
belong in other feature modules; this one only touches per-row signals.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

SEVERITY_RANK: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

TABULAR_FEATURE_COLUMNS: list[str] = [
    "cve_id",
    "published_date",
    "f_cvss_v3_base_score",
    "f_cvss_v3_severity_rank",
    "f_cvss_av_network",
    "f_cvss_au_none",
    "f_cwe_count",
    "f_vendor_count",
    "f_product_count",
    "f_description_len",
    "f_ref_has_exploit",
    "f_ref_has_patch",
    "f_epss_score",
    "f_epss_percentile",
    "f_in_kev_prior",
    "f_epss_percentile_x_in_kev",
]


def build_tabular_frame(silver: pl.DataFrame) -> pl.DataFrame:
    """Pure polars transformation: silver -> tabular features."""
    vector = pl.col("cvss_v3_vector").fill_null("")
    severity = pl.col("cvss_v3_severity").fill_null("UNKNOWN")
    sev_rank = severity.replace_strict(SEVERITY_RANK, default=0).cast(pl.Int32)

    return silver.select(
        pl.col("cve_id"),
        pl.col("published_date"),
        pl.col("cvss_v3_base_score").cast(pl.Float32).fill_null(0.0).alias("f_cvss_v3_base_score"),
        sev_rank.alias("f_cvss_v3_severity_rank"),
        vector.str.contains("AV:N").cast(pl.Int8).alias("f_cvss_av_network"),
        vector.str.contains("Au:N").cast(pl.Int8).alias("f_cvss_au_none"),
        pl.col("cwe_ids").list.len().fill_null(0).cast(pl.Int32).alias("f_cwe_count"),
        pl.col("vendor_count").cast(pl.Int32).alias("f_vendor_count"),
        pl.col("product_count").cast(pl.Int32).alias("f_product_count"),
        pl.col("description_len").cast(pl.Int32).alias("f_description_len"),
        pl.col("ref_has_exploit").cast(pl.Int8).alias("f_ref_has_exploit"),
        pl.col("ref_has_patch").cast(pl.Int8).alias("f_ref_has_patch"),
        pl.col("epss_score").cast(pl.Float32).fill_null(0.0).alias("f_epss_score"),
        pl.col("epss_percentile").cast(pl.Float32).fill_null(0.0).alias("f_epss_percentile"),
        pl.col("in_kev").cast(pl.Int8).alias("f_in_kev_prior"),
        (
            pl.col("epss_percentile").cast(pl.Float32).fill_null(0.0)
            * pl.col("in_kev").cast(pl.Float32)
        ).alias("f_epss_percentile_x_in_kev"),
    )


def build_tabular_features(silver_path: Path, out_path: Path) -> Path:
    """Materialize tabular features as a Parquet file."""
    silver_path = Path(silver_path)
    out_path = Path(out_path)
    silver = pl.read_parquet(silver_path)
    features = build_tabular_frame(silver)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    features.write_parquet(out_path, compression="zstd")
    return out_path
