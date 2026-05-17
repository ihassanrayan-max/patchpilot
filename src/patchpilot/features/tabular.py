"""Tabular features derived directly from ``cve_master.parquet`` columns.

Implemented in: Phase 2.
"""

from __future__ import annotations

from pathlib import Path


def build_tabular_features(silver_path: Path, out_path: Path) -> Path:
    """Materialize tabular features as a Parquet file.

    Inputs:  ``silver_path`` — path to ``data/silver/cve_master.parquet``.
             ``out_path``    — destination under ``data/gold/features_tabular.parquet``.
    Outputs: absolute path to the written Parquet file.
    Invariants: deterministic; pure transformation of silver columns; no labels.
    Implemented in: Phase 2.
    """
    raise NotImplementedError("Phase 2")
