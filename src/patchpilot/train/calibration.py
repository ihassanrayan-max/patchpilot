"""Probability calibration (isotonic / Platt) for the LightGBM challenger.

A thin wrapper around scikit-learn's ``IsotonicRegression`` and
``LogisticRegression``. Each returned calibrator exposes a ``.predict(scores)``
method returning calibrated probabilities; callers do not need to care
which underlying class was used.
"""

from __future__ import annotations

from typing import Any, Literal

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression


class _SigmoidCalibrator:
    """Wrap ``LogisticRegression`` with a ``.predict(scores)`` interface."""

    def __init__(self) -> None:
        """Lazy-init the underlying logistic regression."""
        self._lr = LogisticRegression()

    def fit(self, scores: np.ndarray, labels: np.ndarray) -> _SigmoidCalibrator:
        """Fit ``LogisticRegression(scores -> labels)``."""
        self._lr.fit(np.asarray(scores).reshape(-1, 1), np.asarray(labels))
        return self

    def predict(self, scores: np.ndarray) -> np.ndarray:
        """Return calibrated probabilities for ``scores``."""
        return np.asarray(self._lr.predict_proba(np.asarray(scores).reshape(-1, 1))[:, 1])


def fit_calibrator(
    scores: Any,
    labels: Any,
    method: Literal["isotonic", "sigmoid"] = "isotonic",
) -> Any:
    """Fit a probability calibrator on validation predictions.

    Returns an object exposing ``.predict(scores) -> probabilities``.
    Degenerate inputs (all-same labels) return an identity calibrator so
    downstream code never crashes.
    """
    scores = np.asarray(scores, dtype=np.float64).ravel()
    labels = np.asarray(labels, dtype=np.int8).ravel()
    if len(scores) == 0 or len(np.unique(labels)) < 2:
        return _IdentityCalibrator()

    if method == "isotonic":
        cal = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        cal.fit(scores, labels)
        return cal
    if method == "sigmoid":
        return _SigmoidCalibrator().fit(scores, labels)
    raise ValueError(f"unknown calibration method: {method!r}")


class _IdentityCalibrator:
    """Pass-through calibrator used when calibration is impossible."""

    def predict(self, scores: np.ndarray) -> np.ndarray:
        """Return ``scores`` clipped to [0, 1]."""
        return np.clip(np.asarray(scores, dtype=np.float64), 0.0, 1.0)
