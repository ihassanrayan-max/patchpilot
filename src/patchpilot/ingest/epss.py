"""EPSS score ingestion from FIRST.org daily CSV.

EPSS is both a feature input and the baseline benchmark for evaluation. All
functions in this module are Phase 1 stubs.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path


def ingest_epss(snapshot: date, out_dir: Path) -> Path:
    """Download the FIRST.org EPSS daily CSV for ``snapshot`` and write bronze Parquet.

    Inputs:  ``snapshot`` — EPSS snapshot date to fetch (UTC).
             ``out_dir`` — directory under ``data/bronze/epss/`` to write to.
    Outputs: absolute path to the written Parquet file.
    Invariants: idempotent on ``(snapshot, out_dir)``; no network under tests.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")


def load_epss_snapshot(snapshot: date, bronze_dir: Path) -> Path:
    """Locate a previously ingested EPSS snapshot Parquet file.

    Inputs:  ``snapshot`` — EPSS snapshot date.
             ``bronze_dir`` — bronze EPSS directory.
    Outputs: path to the matching Parquet file.
    Invariants: raises ``FileNotFoundError`` if missing.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")
