"""Lightweight schema and value checks that gate bronze -> silver promotion.

We deliberately avoid the full Great Expectations runtime here: it is heavy,
slow to start, and brings little additional safety over what the pyarrow
schema plus a handful of value-range assertions already give us. The
function name ``validate_cve_master`` matches the Phase 1 contract; the
implementation is fast and dependency-light.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from patchpilot.validate.schemas import cve_master_schema

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _check(condition: bool, errors: list[str], message: str) -> None:
    """Append ``message`` to ``errors`` when ``condition`` is false."""
    if not condition:
        errors.append(message)


def validate_cve_master(parquet_path: Path) -> bool:
    """Validate the silver ``cve_master.parquet`` against the schema contract.

    Writes a JSON validation result alongside the parquet under
    ``data/validation/cve_master.json`` and returns ``True`` only when every
    expectation passes. Never raises on failed expectations -- callers
    should branch on the return value.
    """
    parquet_path = Path(parquet_path)
    errors: list[str] = []

    if not parquet_path.exists():
        errors.append(f"missing parquet: {parquet_path}")
        _write_result(parquet_path, errors, n_rows=0)
        return False

    table = pq.read_table(parquet_path)
    expected = cve_master_schema()

    _check(
        list(table.schema.names) == list(expected.names),
        errors,
        f"column order mismatch: {table.schema.names} vs {expected.names}",
    )

    for field in expected:
        if field.name not in table.schema.names:
            errors.append(f"missing column: {field.name}")
            continue
        got = table.schema.field(field.name).type
        if got != field.type:
            errors.append(
                f"column {field.name} dtype {got} != expected {field.type}"
            )

    if errors:
        _write_result(parquet_path, errors, n_rows=table.num_rows)
        return False

    df = table.to_pandas()
    n = len(df)

    _check(
        df["cve_id"].notna().all() and df["cve_id"].map(lambda x: bool(_CVE_RE.match(str(x)))).all(),
        errors,
        "cve_id must be non-null and match CVE-YYYY-NNNN+",
    )
    _check(df["cve_id"].is_unique, errors, "cve_id must be unique")

    _check(
        df["published_date"].notna().all() and df["last_modified_date"].notna().all(),
        errors,
        "published_date and last_modified_date must be non-null",
    )
    if df["published_date"].notna().all() and df["last_modified_date"].notna().all():
        _check(
            (df["last_modified_date"] >= df["published_date"]).all(),
            errors,
            "last_modified_date must be >= published_date",
        )

    cvss = df["cvss_v3_base_score"].dropna()
    if not cvss.empty:
        _check(
            float(cvss.min()) >= 0.0 and float(cvss.max()) <= 10.0,
            errors,
            f"cvss_v3_base_score out of [0,10]: min={cvss.min()} max={cvss.max()}",
        )

    sev = df["cvss_v3_severity"].dropna()
    if not sev.empty:
        bad = set(sev.unique()) - _SEVERITIES
        _check(not bad, errors, f"unexpected cvss_v3_severity values: {bad}")

    for col in ("vendor_count", "product_count", "description_len"):
        _check(
            df[col].notna().all() and (df[col] >= 0).all(),
            errors,
            f"{col} must be non-null and >= 0",
        )

    for col in ("ref_has_exploit", "ref_has_patch", "in_kev", "exploited_30d"):
        _check(df[col].notna().all(), errors, f"{col} must be non-null")

    epss = df["epss_score"].dropna()
    if not epss.empty:
        _check(
            float(epss.min()) >= 0.0 and float(epss.max()) <= 1.0,
            errors,
            f"epss_score out of [0,1]: min={epss.min()} max={epss.max()}",
        )
    epp = df["epss_percentile"].dropna()
    if not epp.empty:
        _check(
            float(epp.min()) >= 0.0 and float(epp.max()) <= 1.0,
            errors,
            f"epss_percentile out of [0,1]: min={epp.min()} max={epp.max()}",
        )

    in_kev_count = int(df["in_kev"].sum())
    kev_dates_count = int(df["kev_date_added"].notna().sum())
    _check(
        in_kev_count == kev_dates_count,
        errors,
        f"kev_date_added must be non-null iff in_kev (in_kev={in_kev_count} dates={kev_dates_count})",
    )

    cwe_col = df["cwe_ids"].dropna()
    bad_cwe: list[str] = []
    for row in cwe_col:
        if row is None:
            continue
        for item in row:
            if item is not None and not _CWE_RE.match(str(item)):
                bad_cwe.append(str(item))
    _check(not bad_cwe, errors, f"invalid CWE ids: {bad_cwe[:5]}")

    _write_result(parquet_path, errors, n_rows=n)
    return not errors


def _write_result(parquet_path: Path, errors: list[str], n_rows: int) -> None:
    """Persist a JSON validation result for auditing."""
    out_dir = parquet_path.parent.parent / "validation"
    out_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "parquet": str(parquet_path),
        "n_rows": n_rows,
        "n_errors": len(errors),
        "errors": errors,
        "validated_at": datetime.now(UTC).isoformat(),
        "passed": not errors,
    }
    (out_dir / "cve_master.json").write_text(json.dumps(payload, indent=2))
