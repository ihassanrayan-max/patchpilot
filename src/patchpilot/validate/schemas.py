"""Authoritative pyarrow schemas for bronze/silver/gold Parquet tables.

These functions return ``pyarrow.Schema`` objects describing the contract
documented in ``PLAN.md``. They are intentionally typed as ``object`` here
to keep the Phase 0 stub free of pyarrow-version-specific generics; Phase 1
returns concrete ``pa.Schema`` instances.
"""

from __future__ import annotations

from typing import Any


def cve_master_schema() -> Any:
    """Return the pyarrow schema for ``data/silver/cve_master.parquet``.

    Inputs:  none.
    Outputs: ``pyarrow.Schema`` matching the schema contract in ``PLAN.md``.
    Invariants: column order and dtypes match the contract exactly; deviating
                breaks every downstream phase.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")


def kev_schema() -> Any:
    """Return the pyarrow schema for ``data/bronze/kev/kev.parquet``.

    Inputs:  none.
    Outputs: ``pyarrow.Schema``.
    Invariants: column order and dtypes pinned.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")


def epss_schema() -> Any:
    """Return the pyarrow schema for ``data/bronze/epss/<date>.parquet``.

    Inputs:  none.
    Outputs: ``pyarrow.Schema``.
    Invariants: column order and dtypes pinned.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")
