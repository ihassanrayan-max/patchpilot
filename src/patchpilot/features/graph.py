"""Graph features over the CVE ↔ CPE ↔ CWE bipartite/co-occurrence graph.

Implemented in: Phase 2.
"""

from __future__ import annotations

from pathlib import Path


def build_graph_features(silver_path: Path, out_path: Path) -> Path:
    """Materialize graph-derived features (e.g. vendor/CWE neighborhood stats).

    Inputs:  ``silver_path`` — path to ``data/silver/cve_master.parquet``.
             ``out_path``    — destination Parquet under ``data/gold/``.
    Outputs: absolute path to the written Parquet file.
    Invariants: pure; deterministic; no external network or label leakage.
    Implemented in: Phase 2.
    """
    raise NotImplementedError("Phase 2")
