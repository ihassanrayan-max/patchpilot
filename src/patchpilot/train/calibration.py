"""Probability calibration (isotonic / Platt) for the LightGBM challenger.

Implemented in: Phase 2.
"""

from __future__ import annotations

from typing import Any, Literal


def fit_calibrator(
    scores: Any,
    labels: Any,
    method: Literal["isotonic", "sigmoid"] = "isotonic",
) -> Any:
    """Fit a probability calibrator on held-out validation predictions.

    Inputs:  ``scores`` — uncalibrated model scores in [0, 1].
             ``labels`` — binary ground truth.
             ``method`` — ``"isotonic"`` or ``"sigmoid"``.
    Outputs: a fitted calibrator with ``.predict(scores)`` returning calibrated
             probabilities.
    Invariants: monotone non-decreasing for isotonic.
    Implemented in: Phase 2.
    """
    raise NotImplementedError("Phase 2")
