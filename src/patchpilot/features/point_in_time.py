"""Point-in-time feature joins for training and evaluation.

Training/eval rows must only see information available on or before each
CVE's ``published_date``. Serving uses :func:`assemble_scoring_frame` in
``patchpilot.train.train`` with a live ``as_of`` anchor instead.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import polars as pl

from patchpilot.features.graph import build_graph_frame_as_of
from patchpilot.features.tabular import build_tabular_frame
from patchpilot.features.temporal import build_temporal_frame_as_of


def load_epss_history(bronze_epss_dir: Path) -> pl.DataFrame:
    """Load and concatenate every EPSS bronze snapshot under ``bronze_epss_dir``."""
    bronze_epss_dir = Path(bronze_epss_dir)
    files = sorted(bronze_epss_dir.glob("*.parquet"))
    if not files:
        return pl.DataFrame(
            schema={
                "cve_id": pl.Utf8,
                "epss_score": pl.Float32,
                "epss_percentile": pl.Float32,
                "snapshot_date": pl.Date,
            }
        )
    return pl.concat([pl.read_parquet(p) for p in files], how="vertical_relaxed")


def join_epss_as_of(silver: pl.DataFrame, epss_history: pl.DataFrame) -> pl.DataFrame:
    """Attach EPSS features using the latest snapshot on or before publication."""
    keys = silver.select(["cve_id", "published_date"])
    if len(epss_history) == 0:
        if "epss_score" in silver.columns and "epss_snapshot_date" in silver.columns:
            return silver.select(
                "cve_id",
                pl.when(
                    pl.col("epss_snapshot_date").is_not_null()
                    & (pl.col("epss_snapshot_date") <= pl.col("published_date"))
                )
                .then(pl.col("epss_score").fill_null(0.0))
                .otherwise(0.0)
                .cast(pl.Float32)
                .alias("f_epss_score"),
                pl.when(
                    pl.col("epss_snapshot_date").is_not_null()
                    & (pl.col("epss_snapshot_date") <= pl.col("published_date"))
                )
                .then(pl.col("epss_percentile").fill_null(0.0))
                .otherwise(0.0)
                .cast(pl.Float32)
                .alias("f_epss_percentile"),
            )
        return keys.select(
            "cve_id",
            pl.lit(0.0).cast(pl.Float32).alias("f_epss_score"),
            pl.lit(0.0).cast(pl.Float32).alias("f_epss_percentile"),
        )

    joined = keys.join(epss_history, on="cve_id", how="left")
    eligible = joined.filter(
        pl.col("snapshot_date").is_null() | (pl.col("snapshot_date") <= pl.col("published_date"))
    )
    best = (
        eligible.sort(["cve_id", "published_date", "snapshot_date"])
        .group_by(["cve_id", "published_date"])
        .agg(
            pl.col("epss_score").last().alias("f_epss_score"),
            pl.col("epss_percentile").last().alias("f_epss_percentile"),
        )
    )
    return best.with_columns(
        pl.col("f_epss_score").fill_null(0.0).cast(pl.Float32),
        pl.col("f_epss_percentile").fill_null(0.0).cast(pl.Float32),
    )


def join_epss_current(silver: pl.DataFrame) -> pl.DataFrame:
    """Attach current silver EPSS columns for live scoring (not for train/eval)."""
    return silver.select(
        "cve_id",
        pl.col("epss_score").fill_null(0.0).cast(pl.Float32).alias("f_epss_score"),
        pl.col("epss_percentile").fill_null(0.0).cast(pl.Float32).alias("f_epss_percentile"),
    )


def _unique_publication_dates(silver: pl.DataFrame) -> list[date]:
    raw = silver.get_column("published_date").unique().sort()
    return [d for d in raw.to_list() if isinstance(d, date)]


def build_temporal_frame_per_row(silver: pl.DataFrame) -> pl.DataFrame:
    """Temporal features with ``as_of = published_date`` for each CVE row."""
    if len(silver) == 0:
        return pl.DataFrame(
            schema={
                "cve_id": pl.Utf8,
                "f_cve_year": pl.Int32,
                "f_cve_month": pl.Int32,
                "f_cve_weekday": pl.Int32,
                "f_age_days": pl.Int32,
                "f_cves_published_same_week": pl.Int32,
                "f_cves_published_same_month": pl.Int32,
            }
        )
    chunks: list[pl.DataFrame] = []
    for as_of in _unique_publication_dates(silver):
        cves = silver.filter(pl.col("published_date") == as_of).select("cve_id")
        feat = build_temporal_frame_as_of(silver, as_of=as_of)
        chunks.append(feat.join(cves, on="cve_id", how="inner"))
    return pl.concat(chunks, how="vertical_relaxed")


def build_graph_frame_per_row(silver: pl.DataFrame) -> pl.DataFrame:
    """CWE popularity features with ``as_of = published_date`` for each CVE row."""
    if len(silver) == 0:
        return pl.DataFrame(
            schema={
                "cve_id": pl.Utf8,
                "f_max_cwe_popularity": pl.Int32,
                "f_mean_cwe_popularity": pl.Float32,
                "f_cwe_distinct_count": pl.Int32,
            }
        )
    chunks: list[pl.DataFrame] = []
    for as_of in _unique_publication_dates(silver):
        cves = silver.filter(pl.col("published_date") == as_of).select("cve_id")
        feat = build_graph_frame_as_of(silver, as_of=as_of)
        chunks.append(feat.join(cves, on="cve_id", how="inner"))
    return pl.concat(chunks, how="vertical_relaxed")


def assemble_feature_frame(
    silver: pl.DataFrame,
    *,
    bronze_dir: Path | None = None,
    include_tabular: bool = True,
    include_temporal: bool = True,
    include_graph: bool = False,
    point_in_time: bool = True,
    as_of: date | None = None,
) -> pl.DataFrame:
    """Join tabular, EPSS, temporal, and optional graph features onto ``silver`` rows."""
    base = silver.select(
        ["cve_id", "published_date", "exploited_30d", "in_kev", "cvss_v3_base_score"]
    )

    if include_tabular:
        tabular = build_tabular_frame(silver).drop("published_date")
        feats = base.join(tabular, on="cve_id", how="inner")
    else:
        feats = base

    if point_in_time:
        epss_dir = (Path(bronze_dir) / "epss") if bronze_dir is not None else None
        epss_history = load_epss_history(epss_dir) if epss_dir is not None else pl.DataFrame()
        epss_feats = join_epss_as_of(silver, epss_history)
    else:
        epss_feats = join_epss_current(silver)

    feats = feats.join(epss_feats, on="cve_id", how="left")

    if include_temporal:
        if point_in_time:
            temporal = build_temporal_frame_per_row(silver)
        else:
            anchor = as_of
            if anchor is None:
                raw_max = silver.get_column("published_date").max()
                anchor = raw_max if isinstance(raw_max, date) else date.today()
            temporal = build_temporal_frame_as_of(silver, as_of=anchor)
        feats = feats.join(temporal, on="cve_id", how="left")

    if include_graph:
        if point_in_time:
            graph = build_graph_frame_per_row(silver)
        else:
            anchor = as_of
            if anchor is None:
                raw_max = silver.get_column("published_date").max()
                anchor = raw_max if isinstance(raw_max, date) else date.today()
            graph = build_graph_frame_as_of(silver, as_of=anchor)
        feats = feats.join(graph, on="cve_id", how="left")

    return feats.with_columns(
        [pl.col(c).fill_null(0) for c in feats.columns if c.startswith("f_")]
    )
