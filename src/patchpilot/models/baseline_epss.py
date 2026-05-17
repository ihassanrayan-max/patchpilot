"""EPSS-as-baseline model.

A thin lookup model that returns the EPSS daily score as its predicted
probability for ``exploited_30d``. This shares the ``predict_proba``
interface with the LightGBM challenger so evaluation code can treat
them identically.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import polars as pl


class EpssBaseline:
    """Lookup-table baseline that exposes EPSS scores via ``predict_proba``.

    Construct either from a parquet snapshot (one row per CVE with
    ``cve_id``, ``epss_score``, ``epss_percentile``) or from an in-memory
    mapping. ``predict_proba`` returns the EPSS score for known CVEs and
    ``0.0`` for unknown ids.
    """

    def __init__(self, snapshot_path: Path | str | None = None) -> None:
        """Construct from an EPSS snapshot parquet path (or empty if ``None``)."""
        self._scores: dict[str, float] = {}
        self._percentiles: dict[str, float] = {}
        if snapshot_path is not None:
            path = Path(snapshot_path)
            if not path.exists():
                raise FileNotFoundError(f"EPSS snapshot not found at {path}")
            df = pl.read_parquet(path)
            self._load_frame(df)

    @classmethod
    def from_silver(cls, silver_path: Path | str) -> EpssBaseline:
        """Build a baseline from the EPSS columns of the silver frame."""
        instance = cls.__new__(cls)
        instance._scores = {}
        instance._percentiles = {}
        df = pl.read_parquet(Path(silver_path))
        keep = df.select(["cve_id", "epss_score", "epss_percentile"]).filter(
            pl.col("epss_score").is_not_null()
        )
        instance._load_frame(
            keep.rename({"cve_id": "cve_id", "epss_score": "epss_score", "epss_percentile": "epss_percentile"})
        )
        return instance

    @classmethod
    def from_mapping(
        cls, scores: dict[str, float], percentiles: dict[str, float] | None = None
    ) -> EpssBaseline:
        """Build a baseline from in-memory dicts (useful for tests)."""
        instance = cls.__new__(cls)
        instance._scores = dict(scores)
        instance._percentiles = dict(percentiles or {})
        return instance

    def _load_frame(self, df: pl.DataFrame) -> None:
        """Populate the lookup dicts from a polars frame."""
        score_col = "epss_score" if "epss_score" in df.columns else "epss"
        pct_col = "epss_percentile" if "epss_percentile" in df.columns else "percentile"
        for row in df.iter_rows(named=True):
            cve = str(row["cve_id"])
            try:
                self._scores[cve] = float(row[score_col])
            except (TypeError, ValueError):
                continue
            try:
                self._percentiles[cve] = float(row[pct_col])
            except (TypeError, ValueError):
                self._percentiles[cve] = 0.0

    def predict_proba(self, cve_ids: list[str]) -> list[float]:
        """Return EPSS scores in [0,1] aligned with ``cve_ids``; 0.0 for unknowns."""
        return [float(self._scores.get(cve, 0.0)) for cve in cve_ids]

    def predict_percentile(self, cve_ids: list[str]) -> list[float]:
        """Return EPSS percentiles in [0,1] aligned with ``cve_ids``."""
        return [float(self._percentiles.get(cve, 0.0)) for cve in cve_ids]

    def predict_proba_array(self, cve_ids: list[str]) -> np.ndarray:
        """Numpy-typed convenience wrapper for the eval harness."""
        return np.asarray(self.predict_proba(cve_ids), dtype=np.float32)

    def known(self, cve_id: str) -> bool:
        """Return whether ``cve_id`` exists in the loaded snapshot."""
        return cve_id in self._scores

    def __len__(self) -> int:
        """Number of CVEs in the lookup table."""
        return len(self._scores)
