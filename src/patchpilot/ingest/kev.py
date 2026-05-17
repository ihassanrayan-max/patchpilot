"""CISA Known Exploited Vulnerabilities (KEV) catalog ingestion.

The KEV catalog is the source of truth for the ``exploited_30d`` label.
We download the official JSON catalog, project it to a flat schema and
persist a bronze Parquet file.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq

from patchpilot.validate.schemas import kev_schema

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TIMEOUT = httpx.Timeout(60.0, connect=15.0)


class IngestError(RuntimeError):
    """Raised when a public data source is unreachable or malformed."""


def fetch_kev_catalog(url: str = KEV_URL, cache_path: Path | None = None) -> dict[str, Any]:
    """Download the KEV catalog JSON.

    If ``cache_path`` is provided and exists on disk, it is read instead of
    making a network request. After a successful network fetch the payload
    is written to ``cache_path`` for reproducibility.
    """
    if cache_path is not None and cache_path.exists():
        return cast(dict[str, Any], json.loads(cache_path.read_text(encoding="utf-8")))

    try:
        response = httpx.get(url, timeout=_TIMEOUT, follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise IngestError(f"failed to fetch KEV catalog at {url}: {exc}") from exc

    payload = cast(dict[str, Any], response.json())
    if cache_path is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(payload), encoding="utf-8")
    return payload


def _parse_date(value: str | None) -> date | None:
    """Parse a YYYY-MM-DD string from KEV; returns ``None`` if missing/invalid."""
    if not value:
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_kev_payload(payload: dict[str, Any]) -> pl.DataFrame:
    """Project a KEV JSON payload to the bronze KEV schema."""
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise IngestError("KEV payload missing 'vulnerabilities' list")

    rows: list[dict[str, Any]] = []
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cveID")
        date_added = _parse_date(entry.get("dateAdded"))
        if not cve_id or date_added is None:
            continue
        rows.append(
            {
                "cve_id": str(cve_id),
                "vendor_project": entry.get("vendorProject"),
                "product": entry.get("product"),
                "vulnerability_name": entry.get("vulnerabilityName"),
                "date_added": date_added,
                "short_description": entry.get("shortDescription"),
                "required_action": entry.get("requiredAction"),
                "due_date": _parse_date(entry.get("dueDate")),
                "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse"),
                "notes": entry.get("notes"),
            }
        )

    if not rows:
        raise IngestError("KEV payload contained no usable vulnerabilities")

    df = pl.DataFrame(
        rows,
        schema={
            "cve_id": pl.Utf8,
            "vendor_project": pl.Utf8,
            "product": pl.Utf8,
            "vulnerability_name": pl.Utf8,
            "date_added": pl.Date,
            "short_description": pl.Utf8,
            "required_action": pl.Utf8,
            "due_date": pl.Date,
            "known_ransomware_campaign_use": pl.Utf8,
            "notes": pl.Utf8,
        },
    )
    return df.unique(subset=["cve_id"], keep="first").sort("date_added")


def ingest_kev(
    out_dir: Path,
    url: str = KEV_URL,
    cache_dir: Path | None = None,
) -> Path:
    """Download the CISA KEV catalog and write bronze Parquet.

    ``cache_dir`` (optional) holds the raw JSON snapshot so the same
    ingest is reproducible offline.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_path = (cache_dir / "kev.json") if cache_dir is not None else None
    if cache_path is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)

    payload = fetch_kev_catalog(url=url, cache_path=cache_path)
    df = parse_kev_payload(payload)
    table = df.to_arrow().cast(kev_schema())
    out_path = out_dir / "kev.parquet"
    pq.write_table(table, out_path, compression="zstd")
    return out_path


def load_kev_bronze(bronze_dir: Path) -> pl.DataFrame:
    """Load the bronze KEV parquet."""
    path = Path(bronze_dir) / "kev.parquet"
    if not path.exists():
        raise FileNotFoundError(f"KEV bronze parquet not found at {path}")
    table = pq.read_table(path)
    return cast(pl.DataFrame, pl.from_arrow(cast(pa.Table, table)))
