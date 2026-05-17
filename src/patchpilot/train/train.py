"""End-to-end training entry point: features → CV → fit → calibrate → MLflow log.

Implemented in: Phase 2.
"""

from __future__ import annotations

from pathlib import Path


def train_lgbm(config_path: Path) -> str:
    """Run a deterministic training pipeline and log to MLflow.

    Inputs:  ``config_path`` — path to ``config/settings.toml``.
    Outputs: MLflow run id of the logged run.
    Invariants: deterministic given the same config and the same silver/gold
                Parquet inputs; produces an MLflow run under ``.mlruns``.
    Implemented in: Phase 2.
    """
    raise NotImplementedError("Phase 2")
