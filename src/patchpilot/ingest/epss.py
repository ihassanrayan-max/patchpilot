"""EPSS score ingestion from FIRST.org daily CSV.

EPSS is both a feature input and the baseline benchmark for evaluation.
We download the gzipped daily CSV, parse, and persist a per-snapshot
bronze Parquet file. Snapshots are immutable so the local cache is a
deterministic substitute for a network fetch.
"""

from __future__ import annotations

import gzip
import io
from datetime import date
from pathlib import Path
from typing import cast

import httpx
import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq

from patchpilot.ingest.kev import IngestError
from patchpilot.validate.schemas import epss_schema

EPSS_URL_TEMPLATE = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"
_TIMEOUT = httpx.Timeout(120.0, connect=15.0)


def fetch_epss_csv(snapshot: date, cache_path: Path | None = None) -> bytes:
    """Download the EPSS daily CSV (gzipped) for ``snapshot`` as raw bytes.

    When ``cache_path`` exists it is returned directly.
    """
    if cache_path is not None and cache_path.exists():
        return cache_path.read_bytes()

    url = EPSS_URL_TEMPLATE.format(date=snapshot.isoformat())
    try:
        response = httpx.get(url, timeout=_TIMEOUT, follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise IngestError(f"failed to fetch EPSS snapshot {snapshot}: {exc}") from exc

    blob = response.content
    if cache_path is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(blob)
    return blob


def parse_epss_csv(blob: bytes, snapshot: date) -> pl.DataFrame:
    """Parse the EPSS daily CSV (with header comment) into a bronze frame.

    The official format prefixes the CSV with a ``#model_version,...`` comment
    line followed by the column header ``cve,epss,percentile``.
    """
    if not blob:
        raise IngestError("EPSS CSV payload was empty")

    if blob[:2] == b"\x1f\x8b":
        text = gzip.decompress(blob).decode("utf-8")
    else:
        text = blob.decode("utf-8")

    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    if not lines:
        raise IngestError("EPSS CSV contained no data lines")

    header = lines[0].lower().split(",")
    if header[:3] != ["cve", "epss", "percentile"]:
        raise IngestError(f"unexpected EPSS header: {header}")

    df = pl.read_csv(io.BytesIO("\n".join(lines).encode("utf-8")))
    df = df.rename({"cve": "cve_id", "epss": "epss_score", "percentile": "epss_percentile"})
    df = df.with_columns(
        pl.col("cve_id").cast(pl.Utf8),
        pl.col("epss_score").cast(pl.Float32),
        pl.col("epss_percentile").cast(pl.Float32),
        pl.lit(snapshot).alias("snapshot_date").cast(pl.Date),
    )
    df = df.select(["cve_id", "epss_score", "epss_percentile", "snapshot_date"])
    return df.unique(subset=["cve_id"], keep="first")


def ingest_epss(
    snapshot: date,
    out_dir: Path,
    cache_dir: Path | None = None,
) -> Path:
    """Download an EPSS snapshot and write bronze Parquet under ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_path: Path | None = None
    if cache_dir is not None:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = cache_dir / f"epss_scores-{snapshot.isoformat()}.csv.gz"

    blob = fetch_epss_csv(snapshot, cache_path=cache_path)
    df = parse_epss_csv(blob, snapshot)
    table = df.to_arrow().cast(epss_schema())
    out_path = out_dir / f"{snapshot.isoformat()}.parquet"
    pq.write_table(table, out_path, compression="zstd")
    return out_path


def load_epss_snapshot(snapshot: date, bronze_dir: Path) -> Path:
    """Locate a previously ingested EPSS snapshot Parquet file."""
    path = Path(bronze_dir) / f"{snapshot.isoformat()}.parquet"
    if not path.exists():
        raise FileNotFoundError(f"EPSS snapshot not found at {path}")
    return path


def load_epss_frame(snapshot: date, bronze_dir: Path) -> pl.DataFrame:
    """Read an EPSS snapshot back as a polars frame."""
    path = load_epss_snapshot(snapshot, bronze_dir)
    table = pq.read_table(path)
    return cast(pl.DataFrame, pl.from_arrow(cast(pa.Table, table)))


def latest_epss_snapshot(bronze_dir: Path) -> Path | None:
    """Return the newest EPSS bronze parquet by filename, or ``None``."""
    bronze_dir = Path(bronze_dir)
    if not bronze_dir.exists():
        return None
    files = sorted(bronze_dir.glob("*.parquet"))
    return files[-1] if files else None
