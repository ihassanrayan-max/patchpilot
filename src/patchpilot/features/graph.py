"""Graph features over the CVE <-> CWE co-occurrence relation.

We deliberately ship a small, deterministic, label-free set: each CWE id
gets a "popularity" count derived from the silver frame, and each CVE
inherits its maximum and mean CWE popularity. Vendor-graph features
require richer NVD CPE projections than the bronze layer carries today;
they live in the Phase 6 backlog.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import polars as pl

GRAPH_FEATURE_COLUMNS: list[str] = [
    "cve_id",
    "f_max_cwe_popularity",
    "f_mean_cwe_popularity",
    "f_cwe_distinct_count",
]


def build_graph_frame_as_of(silver: pl.DataFrame, as_of: date) -> pl.DataFrame:
    """Build CWE-popularity features using only CVEs visible on or before ``as_of``."""
    visible = silver.filter(pl.col("published_date") <= as_of)
    exploded = (
        visible.select(["cve_id", "cwe_ids"])
        .with_columns(pl.col("cwe_ids").fill_null([]))
        .explode("cwe_ids")
        .rename({"cwe_ids": "cwe_id"})
    )

    popularity = (
        exploded.filter(pl.col("cwe_id").is_not_null())
        .group_by("cwe_id")
        .len()
        .rename({"len": "cwe_popularity"})
    )

    joined = exploded.join(popularity, on="cwe_id", how="left")
    aggregated = joined.group_by("cve_id").agg(
        pl.col("cwe_popularity").fill_null(0).max().alias("f_max_cwe_popularity"),
        pl.col("cwe_popularity").fill_null(0).mean().alias("f_mean_cwe_popularity"),
        pl.col("cwe_id").drop_nulls().n_unique().alias("f_cwe_distinct_count"),
    )

    return aggregated.with_columns(
        pl.col("f_max_cwe_popularity").fill_null(0).cast(pl.Int32),
        pl.col("f_mean_cwe_popularity").fill_null(0.0).cast(pl.Float32),
        pl.col("f_cwe_distinct_count").cast(pl.Int32),
    )


def build_graph_frame(silver: pl.DataFrame) -> pl.DataFrame:
    """Build CWE-popularity over the full silver frame (live scoring helper)."""
    raw_max = silver.get_column("published_date").max()
    anchor = raw_max if isinstance(raw_max, date) else date.today()
    return build_graph_frame_as_of(silver, as_of=anchor)


def build_graph_features(silver_path: Path, out_path: Path) -> Path:
    """Materialize CWE-graph features as a Parquet file."""
    silver_path = Path(silver_path)
    out_path = Path(out_path)
    silver = pl.read_parquet(silver_path)
    features = build_graph_frame(silver)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    features.write_parquet(out_path, compression="zstd")
    return out_path
