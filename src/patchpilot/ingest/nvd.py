"""NVD CVE feed ingestion.

Downloads NVD JSON feeds and lands them as bronze Parquet for downstream
silver/feature processing. All functions in this module are Phase 1 stubs.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path


def ingest_nvd(since: date, out_dir: Path) -> Path:
    """Download NVD JSON feeds since ``since`` and write a bronze Parquet file.

    Inputs:  ``since`` — earliest ``publishedDate`` to fetch (inclusive).
             ``out_dir`` — directory under ``data/bronze/nvd/`` to write to.
    Outputs: absolute path to the written Parquet file.
    Invariants: idempotent on ``(since, out_dir)``; no network calls under tests.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")


def parse_nvd_record(raw: dict[str, object]) -> dict[str, object]:
    """Parse a single NVD CVE JSON record into a flat dict matching the bronze schema.

    Inputs:  ``raw`` — a single ``cve`` element from an NVD feed.
    Outputs: flat dict with keys defined in ``docs/data-sources.md``.
    Invariants: pure; no I/O.
    Implemented in: Phase 1.
    """
    raise NotImplementedError("Phase 1")
