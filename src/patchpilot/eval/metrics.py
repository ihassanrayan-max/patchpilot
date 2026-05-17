"""Ranking, calibration, and threshold-free metrics used in the EPSS comparison.

Implemented in: Phase 3.
"""

from __future__ import annotations

from typing import Any


def aucpr(y_true: Any, y_score: Any) -> float:
    """Area under the precision-recall curve.

    Inputs:  ``y_true`` — binary labels. ``y_score`` — predicted probabilities.
    Outputs: float in [0, 1].
    Invariants: pure; deterministic.
    Implemented in: Phase 3.
    """
    raise NotImplementedError("Phase 3")


def auc_roc(y_true: Any, y_score: Any) -> float:
    """Area under the ROC curve. Phase 3."""
    raise NotImplementedError("Phase 3")


def precision_at_k(y_true: Any, y_score: Any, k: int) -> float:
    """Precision among the top-``k`` ranked items. Phase 3."""
    raise NotImplementedError("Phase 3")


def brier_score(y_true: Any, y_score: Any) -> float:
    """Mean squared error between predicted probabilities and labels. Phase 3."""
    raise NotImplementedError("Phase 3")


def expected_calibration_error(y_true: Any, y_score: Any, n_bins: int = 10) -> float:
    """Expected Calibration Error with equal-width probability bins. Phase 3."""
    raise NotImplementedError("Phase 3")
