"""Prefect flow that runs the daily NVD/EPSS/KEV ingestion.

Implemented in: Phase 1.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path


def daily_ingest_flow(target_date: date, data_dir: Path) -> None:
    """Run the daily ingestion flow for ``target_date``.

    Inputs:  ``target_date`` — UTC date to ingest (NVD modified feed, EPSS
                                snapshot, KEV catalog).
             ``data_dir``   — root ``data/`` directory.
    Outputs: none; side effects under ``data/bronze/`` and ``data/silver/``.
    Invariants: idempotent on ``(target_date, data_dir)``.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")
