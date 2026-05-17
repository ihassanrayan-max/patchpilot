"""EPSS-as-baseline model: a thin adapter that exposes EPSS scores via the
common predict interface so evaluation code can treat it identically to
PatchPilot's challenger.

Implemented in: Phase 2.
"""

from __future__ import annotations

from typing import Any


class EpssBaseline:
    """Adapter that returns the EPSS daily score as ``predict_proba``.

    Invariants: stateless; reads its scores from a snapshot Parquet path
                supplied at construction time.
    Implemented in: Phase 2.
    """

    def __init__(self, snapshot_path: Any) -> None:
        """Construct from the EPSS snapshot Parquet path. Phase 2."""
        raise NotImplementedError("Phase 2")

    def predict_proba(self, cve_ids: list[str]) -> list[float]:
        """Return the EPSS probability for each ``cve_id`` in order.

        Inputs:  ``cve_ids`` — list of CVE identifiers.
        Outputs: list of floats in [0, 1] aligned with ``cve_ids``;
                 ``0.0`` for unknown CVE ids.
        Invariants: pure; no I/O after construction.
        Implemented in: Phase 2.
        """
        raise NotImplementedError("Phase 2")
