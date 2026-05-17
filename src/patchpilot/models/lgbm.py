"""LightGBM challenger model wrapper.

Implemented in: Phase 2.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class LgbmModel:
    """LightGBM binary classifier predicting ``exploited_30d``.

    Invariants: deterministic for fixed ``seed`` and fixed feature matrix.
    Implemented in: Phase 2.
    """

    def __init__(self, params: dict[str, Any], seed: int = 42) -> None:
        """Initialize with LightGBM hyperparameters. Phase 2."""
        raise NotImplementedError("Phase 2")

    def fit(self, x_train: Any, y_train: Any, x_valid: Any, y_valid: Any) -> None:
        """Fit the LightGBM model with early stopping on the validation fold.

        Inputs:  ``x_train``/``x_valid`` — feature frames (pandas/polars).
                 ``y_train``/``y_valid`` — binary label arrays.
        Outputs: none; mutates internal booster.
        Invariants: deterministic for fixed seed.
        Implemented in: Phase 2.
        """
        raise NotImplementedError("Phase 2")

    def predict_proba(self, x: Any) -> Any:
        """Return calibrated/uncalibrated probability of ``exploited_30d``.

        Inputs:  ``x`` — feature frame.
        Outputs: numpy/polars array of floats in [0, 1].
        Invariants: shape matches ``x.shape[0]``.
        Implemented in: Phase 2.
        """
        raise NotImplementedError("Phase 2")

    def save(self, path: Path) -> None:
        """Persist the booster + metadata to ``path``. Phase 2."""
        raise NotImplementedError("Phase 2")

    @classmethod
    def load(cls, path: Path) -> LgbmModel:
        """Load a previously saved model from ``path``. Phase 2."""
        raise NotImplementedError("Phase 2")
