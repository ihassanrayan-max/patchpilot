"""Great Expectations suites that gate bronze → silver promotion.

Implemented in: Phase 1.
"""

from __future__ import annotations

from pathlib import Path


def validate_cve_master(parquet_path: Path) -> bool:
    """Run the Great Expectations suite for ``cve_master.parquet``.

    Inputs:  ``parquet_path`` — path to the silver Parquet to validate.
    Outputs: ``True`` if the suite passes, ``False`` otherwise.
    Invariants: no side effects other than writing a validation result under
                ``data/validation/``; never raises on failed expectations.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")
