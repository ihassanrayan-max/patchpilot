"""Bronze -> silver join: build ``data/silver/cve_master.parquet``.

Joins the bronze NVD frame with KEV (for ``in_kev``, ``kev_date_added``
and the ``exploited_30d`` label) and an EPSS snapshot (for
``epss_score``, ``epss_percentile``, ``epss_snapshot_date``).

The label rule (see ``PLAN.md``) is implemented in :func:`label_exploited_30d`
and is the only authoritative implementation in the repo.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from typing import cast

import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq

from patchpilot.ingest.epss import latest_epss_snapshot
from patchpilot.ingest.kev import load_kev_bronze
from patchpilot.ingest.nvd import load_nvd_bronze
from patchpilot.validate.schemas import cve_master_schema

LABEL_HORIZON_DAYS = 30


def label_exploited_30d(
    cve_id: pl.Expr,
    published_date: pl.Expr,
    kev_lookup: dict[str, date],
    horizon_days: int = LABEL_HORIZON_DAYS,
) -> pl.Expr:
    """Vectorised polars expression evaluating ``exploited_30d``.

    Defined exactly per ``PLAN.md``::

        exploited_30d(cve) := cve.id in KEV
                              AND KEV.date_added <= cve.published + 30d

    The lookup ``{cve_id -> kev_date_added}`` is materialised by
    :func:`build_cve_master`; rows whose ``cve_id`` is absent from KEV
    label as ``False``.
    """
    _ = cve_id, published_date, kev_lookup, horizon_days
    raise NotImplementedError("use label_exploited_30d_frame instead")


def label_exploited_30d_frame(
    df: pl.DataFrame,
    kev: pl.DataFrame,
    *,
    horizon_days: int = LABEL_HORIZON_DAYS,
) -> pl.DataFrame:
    """Attach ``in_kev``, ``kev_date_added`` and ``exploited_30d`` columns.

    Pure polars; deterministic; no I/O. ``df`` must contain ``cve_id`` and
    ``published_date``; ``kev`` must contain ``cve_id`` and ``date_added``.
    """
    if "cve_id" not in df.columns or "published_date" not in df.columns:
        raise ValueError("df must have columns 'cve_id' and 'published_date'")
    if "cve_id" not in kev.columns or "date_added" not in kev.columns:
        raise ValueError("kev must have columns 'cve_id' and 'date_added'")

    kev_keyed = kev.select(
        pl.col("cve_id"),
        pl.col("date_added").alias("kev_date_added"),
    ).unique(subset=["cve_id"], keep="first")

    joined = df.join(kev_keyed, on="cve_id", how="left")
    horizon = pl.duration(days=horizon_days)
    return joined.with_columns(
        pl.col("kev_date_added").is_not_null().alias("in_kev"),
        (
            pl.col("kev_date_added").is_not_null()
            & (pl.col("kev_date_added") <= (pl.col("published_date") + horizon))
        ).alias("exploited_30d"),
    )


def build_cve_master(
    nvd: pl.DataFrame,
    kev: pl.DataFrame,
    epss: pl.DataFrame | None,
    *,
    horizon_days: int = LABEL_HORIZON_DAYS,
) -> pl.DataFrame:
    """Build the silver ``cve_master`` frame from bronze inputs.

    ``epss`` may be ``None`` if a snapshot was not ingested; in that case
    the EPSS columns are filled with nulls but the schema is preserved.
    """
    base = nvd.select(
        [
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
        ]
    ).with_columns(
        pl.col("vendor_count").cast(pl.Int32),
        pl.col("product_count").cast(pl.Int32),
        pl.col("description_len").cast(pl.Int32),
        pl.col("ref_has_exploit").cast(pl.Boolean),
        pl.col("ref_has_patch").cast(pl.Boolean),
    )

    if epss is not None and len(epss) > 0:
        epss_keyed = epss.select(
            pl.col("cve_id"),
            pl.col("epss_score").cast(pl.Float32),
            pl.col("epss_percentile").cast(pl.Float32),
            pl.col("snapshot_date").alias("epss_snapshot_date"),
        ).unique(subset=["cve_id"], keep="last")
        base = base.join(epss_keyed, on="cve_id", how="left")
    else:
        base = base.with_columns(
            pl.lit(None, dtype=pl.Float32).alias("epss_score"),
            pl.lit(None, dtype=pl.Float32).alias("epss_percentile"),
            pl.lit(None, dtype=pl.Date).alias("epss_snapshot_date"),
        )

    labelled = label_exploited_30d_frame(base, kev, horizon_days=horizon_days)
    ordered = labelled.select([f.name for f in cve_master_schema()])
    return ordered.sort("published_date")


def write_cve_master(df: pl.DataFrame, out_path: Path) -> Path:
    """Write the silver frame as a parquet matching :func:`cve_master_schema`."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    table = df.to_arrow().cast(cve_master_schema())
    pq.write_table(table, out_path, compression="zstd")
    return out_path


def build_silver(
    bronze_dir: Path,
    silver_path: Path,
    *,
    epss_snapshot: date | None = None,
    horizon_days: int = LABEL_HORIZON_DAYS,
) -> Path:
    """Read bronze, build silver, and persist parquet at ``silver_path``."""
    bronze_dir = Path(bronze_dir)
    nvd = load_nvd_bronze(bronze_dir / "nvd")
    kev = load_kev_bronze(bronze_dir / "kev")

    epss: pl.DataFrame | None = None
    if epss_snapshot is not None:
        epss_path = bronze_dir / "epss" / f"{epss_snapshot.isoformat()}.parquet"
        if epss_path.exists():
            table = pq.read_table(epss_path)
            epss = cast(pl.DataFrame, pl.from_arrow(cast(pa.Table, table)))
    if epss is None:
        candidate = latest_epss_snapshot(bronze_dir / "epss")
        if candidate is not None:
            table = pq.read_table(candidate)
            epss = cast(pl.DataFrame, pl.from_arrow(cast(pa.Table, table)))

    master = build_cve_master(nvd, kev, epss, horizon_days=horizon_days)
    return write_cve_master(master, silver_path)


def right_censor_mask(
    published: pl.Series,
    today: date,
    *,
    horizon_days: int = LABEL_HORIZON_DAYS,
) -> pl.Series:
    """Return a boolean mask of rows safe to use for train/eval.

    True means the 30-day exploitation window for the CVE has closed
    (``published_date <= today - horizon_days``) and the row may be
    used for training and evaluation. False means the row is right-
    censored and should be excluded.
    """
    cutoff = today - timedelta(days=horizon_days)
    return published <= cutoff
