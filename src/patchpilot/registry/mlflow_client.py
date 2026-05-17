"""Thin wrappers around the MLflow tracking client pinned to the local file backend.

Implemented in: Phase 2/4.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def get_tracking_uri(mlruns_dir: Path) -> str:
    """Return the ``file://`` tracking URI for the local MLflow backend.

    Inputs:  ``mlruns_dir`` — directory that holds MLflow runs (``.mlruns``).
    Outputs: a ``file://`` URI string.
    Invariants: pure; no I/O.
    Implemented in: Phase 2.
    """
    raise NotImplementedError("Phase 2")


def load_latest_model(experiment_name: str) -> Any:
    """Return the latest finished MLflow run's model from ``experiment_name``.

    Inputs:  ``experiment_name`` — MLflow experiment.
    Outputs: a loaded pyfunc model.
    Invariants: raises if no successful runs exist.
    Implemented in: Phase 4.
    """
    raise NotImplementedError("Phase 4")
