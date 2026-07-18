"""NVD CVE 2.0 feed ingestion.

We use the public NVD REST API at ``services.nvd.nist.gov/rest/json/cves/2.0``
to fetch CVE records since a given ``pubStartDate`` and project them to a
flat bronze Parquet row.

Notes / honesty:

* The NVD API is rate-limited (about 5 requests / 30 seconds without an API key).
  Without ``NVD_API_KEY``, callers should use a conservative sleep between pages
  (see ``_DEFAULT_SLEEP_UNKEYED``). With an API key, NIST allows higher throughput;
  PatchPilot defaults to ``_DEFAULT_SLEEP_KEYED`` between pages when a key is supplied.
* The flag ``max_records`` caps total CVE rows pulled (default 50k); widen or shrink
  as needed for your rate budget.
* If the API is unreachable we raise ``IngestError`` -- we never invent
  rows. If a local cache JSON exists it is used in preference to the
  network so tests and offline iteration are deterministic.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import httpx
import polars as pl
import pyarrow.parquet as pq

from patchpilot.ingest.kev import IngestError
from patchpilot.validate.schemas import nvd_bronze_schema

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_PAGE_SIZE = 200
_DEFAULT_MAX_RECORDS = 50000
_DEFAULT_SLEEP_UNKEYED = 6.5
_DEFAULT_SLEEP_KEYED = 0.6
_TIMEOUT = httpx.Timeout(60.0, connect=15.0)


def resolve_nvd_sleep_seconds(api_key: str | None, sleep_seconds: float | None = None) -> float:
    """Return sleep between NVD pages; explicit ``sleep_seconds`` wins."""
    if sleep_seconds is not None:
        return sleep_seconds
    return _DEFAULT_SLEEP_KEYED if (api_key and api_key.strip()) else _DEFAULT_SLEEP_UNKEYED


def _parse_iso_datetime(value: str | None) -> date | None:
    """Parse NVD's ISO 8601 datetimes (``...Z`` / ``+00:00``) to a date."""
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        try:
            return datetime.strptime(value[:10], "%Y-%m-%d").date()
        except ValueError:
            return None


def _cpe_vendor_product_version(
    cpe_uri: str,
) -> tuple[str | None, str | None, str | None]:
    """Extract ``(vendor, product, version)`` from a CPE 2.3 URI."""
    parts = cpe_uri.split(":")
    if len(parts) < 5 or parts[0] != "cpe":
        return None, None, None
    vendor = parts[3] or None
    product = parts[4] or None
    version = parts[5] if len(parts) > 5 else None
    if version in {None, "", "*", "-"}:
        version = None
    return vendor, product, version


def _cpe_vendor_product(cpe_uri: str) -> tuple[str | None, str | None]:
    """Extract ``(vendor, product)`` from a CPE 2.3 URI."""
    vendor, product, _version = _cpe_vendor_product_version(cpe_uri)
    return vendor, product


def parse_nvd_record(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a single NVD ``vulnerabilities[i]`` entry to a flat bronze row.

    Returns ``None`` for records that are missing required fields
    (e.g. rejected CVEs without a publication date).
    """
    cve = raw.get("cve") if "cve" in raw else raw
    if not isinstance(cve, dict):
        return None

    cve_id = cve.get("id")
    published = _parse_iso_datetime(cve.get("published"))
    last_modified = _parse_iso_datetime(cve.get("lastModified"))
    if not cve_id or published is None or last_modified is None:
        return None
    if last_modified < published:
        last_modified = published

    descriptions = cve.get("descriptions") or []
    description = ""
    for desc in descriptions:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            description = str(desc.get("value") or "")
            break

    cvss_base: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if not entries:
            continue
        primary = None
        for entry in entries:
            if isinstance(entry, dict) and entry.get("type") == "Primary":
                primary = entry
                break
        primary = primary or (entries[0] if isinstance(entries[0], dict) else None)
        if primary is None:
            continue
        data = primary.get("cssvData") or primary.get("cvssData") or {}
        base_value = data.get("baseScore")
        if base_value is None:
            cvss_base = None
        else:
            try:
                cvss_base = float(base_value)
            except (TypeError, ValueError):
                cvss_base = None
        sev = data.get("baseSeverity")
        cvss_severity = str(sev).upper() if sev else None
        vec = data.get("vectorString")
        cvss_vector = str(vec) if vec else None
        if cvss_base is not None:
            break

    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description", []) if isinstance(weakness, dict) else []:
            value = desc.get("value") if isinstance(desc, dict) else None
            if isinstance(value, str) and value.startswith("CWE-"):
                cwe_ids.append(value)
    cwe_ids = sorted(set(cwe_ids))

    vendors: set[str] = set()
    products: set[str] = set()
    versions: set[str] = set()
    for cfg in cve.get("configurations") or []:
        if not isinstance(cfg, dict):
            continue
        for node in cfg.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict):
                    continue
                cpe = match.get("criteria") or match.get("cpe23Uri")
                if not isinstance(cpe, str):
                    continue
                vendor, product, version = _cpe_vendor_product_version(cpe)
                if vendor:
                    vendors.add(vendor)
                if product:
                    products.add(product)
                if version:
                    versions.add(version)

    ref_has_exploit = False
    ref_has_patch = False
    for ref in cve.get("references") or []:
        if not isinstance(ref, dict):
            continue
        tags = {str(t).lower() for t in (ref.get("tags") or [])}
        if "exploit" in tags:
            ref_has_exploit = True
        if "patch" in tags:
            ref_has_patch = True

    return {
        "cve_id": str(cve_id),
        "published_date": published,
        "last_modified_date": last_modified,
        "cvss_v3_base_score": cvss_base,
        "cvss_v3_severity": cvss_severity,
        "cvss_v3_vector": cvss_vector,
        "cwe_ids": cwe_ids or None,
        "vendor_count": len(vendors),
        "product_count": len(products),
        "description": description,
        "description_len": len(description),
        "ref_has_exploit": ref_has_exploit,
        "ref_has_patch": ref_has_patch,
        "vendors": sorted(vendors) or None,
        "products": sorted(products) or None,
        "versions": sorted(versions) or None,
    }


def fetch_nvd_page(
    *,
    pub_start: datetime,
    pub_end: datetime,
    start_index: int,
    page_size: int,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Fetch one NVD page over ``[pub_start, pub_end]``."""
    params: dict[str, str | int] = {
        "pubStartDate": pub_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": pub_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "startIndex": start_index,
        "resultsPerPage": page_size,
    }
    headers: dict[str, str] = {"user-agent": "patchpilot/0.1 (+github.com/patchpilot)"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = httpx.get(NVD_API_URL, params=params, headers=headers, timeout=_TIMEOUT)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise IngestError(f"NVD fetch failed at startIndex={start_index}: {exc}") from exc
    return cast(dict[str, Any], response.json())


def iter_nvd_records(
    since: date,
    *,
    until: date | None = None,
    page_size: int = _DEFAULT_PAGE_SIZE,
    max_records: int = _DEFAULT_MAX_RECORDS,
    sleep_seconds: float | None = None,
    api_key: str | None = None,
    cache_path: Path | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream NVD vulnerability entries since ``since``.

    Honours the public NVD 120-day window per request and caps the total
    record count via ``max_records``. When ``sleep_seconds`` is omitted,
    chooses keyed vs un-keyed pacing via :func:`resolve_nvd_sleep_seconds`.
    When ``cache_path`` exists we replay cached pages instead of network calls.
    """
    if cache_path is not None and cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if not isinstance(cached, dict):
            raise IngestError(f"NVD cache at {cache_path} is malformed")
        items = cached.get("vulnerabilities") or []
        yield from items[:max_records]
        return

    sleep_eff = resolve_nvd_sleep_seconds(api_key, sleep_seconds)

    today = datetime.now(UTC)
    until_dt = datetime.combine(until or today.date(), datetime.min.time(), tzinfo=UTC)
    start_dt = datetime.combine(since, datetime.min.time(), tzinfo=UTC)

    collected_total = 0
    aggregated_vulns: list[dict[str, Any]] = []

    window_start = start_dt
    while window_start < until_dt and collected_total < max_records:
        window_end = min(window_start + timedelta(days=119), until_dt)
        start_index = 0
        while collected_total < max_records:
            page = fetch_nvd_page(
                pub_start=window_start,
                pub_end=window_end,
                start_index=start_index,
                page_size=page_size,
                api_key=api_key,
            )
            vulns = page.get("vulnerabilities") or []
            total_results = int(page.get("totalResults") or 0)
            if not vulns:
                break
            for entry in vulns:
                if collected_total >= max_records:
                    break
                aggregated_vulns.append(entry)
                yield entry
                collected_total += 1
            start_index += len(vulns)
            if start_index >= total_results:
                break
            time.sleep(sleep_eff)
        window_start = window_end + timedelta(seconds=1)
        time.sleep(sleep_eff)

    if cache_path is not None and aggregated_vulns:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps({"vulnerabilities": aggregated_vulns}, default=str),
            encoding="utf-8",
        )


def ingest_nvd(
    since: date,
    out_dir: Path,
    *,
    until: date | None = None,
    page_size: int = _DEFAULT_PAGE_SIZE,
    max_records: int = _DEFAULT_MAX_RECORDS,
    sleep_seconds: float | None = None,
    api_key: str | None = None,
    cache_dir: Path | None = None,
) -> Path:
    """Download NVD CVE records and write a bronze Parquet file.

    The file is named by ``since.isoformat()`` and overwritten on re-run.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_path: Path | None = None
    if cache_dir is not None:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = cache_dir / f"nvd_{since.isoformat()}.json"

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in iter_nvd_records(
        since,
        until=until,
        page_size=page_size,
        max_records=max_records,
        sleep_seconds=sleep_seconds,
        api_key=api_key,
        cache_path=cache_path,
    ):
        parsed = parse_nvd_record(raw)
        if parsed is None:
            continue
        if parsed["cve_id"] in seen:
            continue
        seen.add(cast(str, parsed["cve_id"]))
        rows.append(parsed)

    if not rows:
        raise IngestError(
            "NVD ingest returned zero usable records; check connectivity, "
            "the --since value, or supply --cache-dir with prefetched JSON."
        )

    df = pl.DataFrame(
        rows,
        schema={
            "cve_id": pl.Utf8,
            "published_date": pl.Date,
            "last_modified_date": pl.Date,
            "cvss_v3_base_score": pl.Float32,
            "cvss_v3_severity": pl.Utf8,
            "cvss_v3_vector": pl.Utf8,
            "cwe_ids": pl.List(pl.Utf8),
            "vendor_count": pl.Int32,
            "product_count": pl.Int32,
            "description": pl.Utf8,
            "description_len": pl.Int32,
            "ref_has_exploit": pl.Boolean,
            "ref_has_patch": pl.Boolean,
            "vendors": pl.List(pl.Utf8),
            "products": pl.List(pl.Utf8),
            "versions": pl.List(pl.Utf8),
        },
    )
    table = df.to_arrow().cast(nvd_bronze_schema())
    out_path = out_dir / f"{since.isoformat()}.parquet"
    pq.write_table(table, out_path, compression="zstd")
    return out_path


def load_nvd_bronze(bronze_dir: Path) -> pl.DataFrame:
    """Load and concatenate every NVD bronze parquet under ``bronze_dir``."""
    bronze_dir = Path(bronze_dir)
    files = sorted(bronze_dir.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"no NVD bronze parquets under {bronze_dir}")
    frames = [pl.read_parquet(p) for p in files]
    combined = pl.concat(frames, how="vertical_relaxed")
    return combined.unique(subset=["cve_id"], keep="last")
