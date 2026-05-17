"""CISA Known Exploited Vulnerabilities (KEV) catalog ingestion.

The KEV catalog drives the ``exploited_30d`` label. All functions in this
module are Phase 1 stubs.
"""

from __future__ import annotations

from pathlib import Path


def ingest_kev(out_dir: Path) -> Path:
    """Download the latest CISA KEV catalog JSON and write bronze Parquet.

    Inputs:  ``out_dir`` — directory under ``data/bronze/kev/`` to write to.
    Outputs: absolute path to the written Parquet file.
    Invariants: idempotent on the latest catalog version; no network under tests.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")
