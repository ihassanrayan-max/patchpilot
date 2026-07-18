"""Authoritative pyarrow schemas for bronze/silver Parquet tables.

These schemas are the single source of truth for the on-disk contract
documented in ``PLAN.md``. Every reader/writer must round-trip against
them; deviations break downstream phases.
"""

from __future__ import annotations

from typing import Any

import pyarrow as pa


def cve_master_schema() -> pa.Schema:
    """Return the pyarrow schema for ``data/silver/cve_master.parquet``.

    Column order, dtypes and nullability match the contract table in
    ``PLAN.md`` exactly. Do not reorder.
    """
    return pa.schema(
        [
            pa.field("cve_id", pa.string(), nullable=False),
            pa.field("published_date", pa.date32(), nullable=False),
            pa.field("last_modified_date", pa.date32(), nullable=False),
            pa.field("cvss_v3_base_score", pa.float32(), nullable=True),
            pa.field("cvss_v3_severity", pa.string(), nullable=True),
            pa.field("cvss_v3_vector", pa.string(), nullable=True),
            pa.field("cwe_ids", pa.list_(pa.string()), nullable=True),
            pa.field("vendor_count", pa.int32(), nullable=False),
            pa.field("product_count", pa.int32(), nullable=False),
            pa.field("description_len", pa.int32(), nullable=False),
            pa.field("ref_has_exploit", pa.bool_(), nullable=False),
            pa.field("ref_has_patch", pa.bool_(), nullable=False),
            pa.field("epss_score", pa.float32(), nullable=True),
            pa.field("epss_percentile", pa.float32(), nullable=True),
            pa.field("epss_snapshot_date", pa.date32(), nullable=True),
            pa.field("in_kev", pa.bool_(), nullable=False),
            pa.field("kev_date_added", pa.date32(), nullable=True),
            pa.field("exploited_30d", pa.bool_(), nullable=False),
        ]
    )


def kev_schema() -> pa.Schema:
    """Return the pyarrow schema for ``data/bronze/kev/kev.parquet``."""
    return pa.schema(
        [
            pa.field("cve_id", pa.string(), nullable=False),
            pa.field("vendor_project", pa.string(), nullable=True),
            pa.field("product", pa.string(), nullable=True),
            pa.field("vulnerability_name", pa.string(), nullable=True),
            pa.field("date_added", pa.date32(), nullable=False),
            pa.field("short_description", pa.string(), nullable=True),
            pa.field("required_action", pa.string(), nullable=True),
            pa.field("due_date", pa.date32(), nullable=True),
            pa.field("known_ransomware_campaign_use", pa.string(), nullable=True),
            pa.field("notes", pa.string(), nullable=True),
        ]
    )


def epss_schema() -> pa.Schema:
    """Return the pyarrow schema for ``data/bronze/epss/<date>.parquet``."""
    return pa.schema(
        [
            pa.field("cve_id", pa.string(), nullable=False),
            pa.field("epss_score", pa.float32(), nullable=False),
            pa.field("epss_percentile", pa.float32(), nullable=False),
            pa.field("snapshot_date", pa.date32(), nullable=False),
        ]
    )


def nvd_bronze_schema() -> pa.Schema:
    """Return the pyarrow schema for ``data/bronze/nvd/*.parquet``.

    A flat per-CVE projection of the NVD CVE 2.0 record sufficient to
    derive every silver column.
    """
    return pa.schema(
        [
            pa.field("cve_id", pa.string(), nullable=False),
            pa.field("published_date", pa.date32(), nullable=False),
            pa.field("last_modified_date", pa.date32(), nullable=False),
            pa.field("cvss_v3_base_score", pa.float32(), nullable=True),
            pa.field("cvss_v3_severity", pa.string(), nullable=True),
            pa.field("cvss_v3_vector", pa.string(), nullable=True),
            pa.field("cwe_ids", pa.list_(pa.string()), nullable=True),
            pa.field("vendor_count", pa.int32(), nullable=False),
            pa.field("product_count", pa.int32(), nullable=False),
            pa.field("description", pa.string(), nullable=False),
            pa.field("description_len", pa.int32(), nullable=False),
            pa.field("ref_has_exploit", pa.bool_(), nullable=False),
            pa.field("ref_has_patch", pa.bool_(), nullable=False),
            pa.field("vendors", pa.list_(pa.string()), nullable=True),
            pa.field("products", pa.list_(pa.string()), nullable=True),
            pa.field("versions", pa.list_(pa.string()), nullable=True),
        ]
    )


def schema_to_polars(schema: pa.Schema) -> dict[str, Any]:
    """Translate a pyarrow schema to a polars dtype dict.

    Used by writers to coerce a polars frame to the on-disk dtypes
    before serialising to parquet. Returns ``Any`` typed values to
    avoid leaking polars types into module signatures.
    """
    import polars as pl

    out: dict[str, Any] = {}
    for field in schema:
        t = field.type
        if pa.types.is_list(t):
            out[field.name] = pl.List(pl.Utf8)
        elif pa.types.is_string(t):
            out[field.name] = pl.Utf8
        elif pa.types.is_date32(t):
            out[field.name] = pl.Date
        elif pa.types.is_float32(t):
            out[field.name] = pl.Float32
        elif pa.types.is_int32(t):
            out[field.name] = pl.Int32
        elif pa.types.is_boolean(t):
            out[field.name] = pl.Boolean
        else:
            raise TypeError(f"Unmapped pyarrow type for column {field.name}: {t}")
    return out
