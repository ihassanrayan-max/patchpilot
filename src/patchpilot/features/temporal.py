"""Temporal features (rolling counts, recency windows) over CVE history.

Implemented in: Phase 2.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path


def build_temporal_features(silver_path: Path, as_of: date, out_path: Path) -> Path:
    """Materialize point-in-time temporal features anchored at ``as_of``.

    Inputs:  ``silver_path`` — path to ``data/silver/cve_master.parquet``.
             ``as_of``       — anchor date; no information after this date
                                may enter the features (no future leakage).
             ``out_path``    — destination Parquet under ``data/gold/``.
    Outputs: absolute path to the written Parquet file.
    Invariants: strict point-in-time correctness; deterministic.
    Implemented in: Phase 2.
    """
    raise NotImplementedError("Phase 2")
