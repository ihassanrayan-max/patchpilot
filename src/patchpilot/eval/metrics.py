"""Ranking, calibration and threshold-free metrics for evaluation.

All functions are pure and deterministic; they operate on numpy arrays so
the same code can score the LightGBM challenger or the EPSS baseline.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    roc_auc_score,
)


def _as_arrays(y_true: Any, y_score: Any) -> tuple[np.ndarray, np.ndarray]:
    """Coerce inputs to aligned 1-D float arrays."""
    yt = np.asarray(y_true, dtype=np.int8).ravel()
    ys = np.asarray(y_score, dtype=np.float64).ravel()
    if yt.shape != ys.shape:
        raise ValueError(f"shape mismatch: y_true={yt.shape}, y_score={ys.shape}")
    return yt, ys


def aucpr(y_true: Any, y_score: Any) -> float:
    """Area under the precision-recall curve."""
    yt, ys = _as_arrays(y_true, y_score)
    if len(np.unique(yt)) < 2:
        return float("nan")
    return float(average_precision_score(yt, ys))


def auc_roc(y_true: Any, y_score: Any) -> float:
    """Area under the ROC curve."""
    yt, ys = _as_arrays(y_true, y_score)
    if len(np.unique(yt)) < 2:
        return float("nan")
    return float(roc_auc_score(yt, ys))


def precision_at_k(y_true: Any, y_score: Any, k: int) -> float:
    """Precision among the top-``k`` ranked items."""
    yt, ys = _as_arrays(y_true, y_score)
    if k <= 0:
        return float("nan")
    k = min(k, len(ys))
    if k == 0:
        return float("nan")
    top_indices = np.argsort(-ys)[:k]
    return float(yt[top_indices].sum()) / float(k)


def brier_score(y_true: Any, y_score: Any) -> float:
    """Mean squared error between predicted probabilities and binary labels."""
    yt, ys = _as_arrays(y_true, y_score)
    if len(yt) == 0:
        return float("nan")
    return float(brier_score_loss(yt, np.clip(ys, 0.0, 1.0)))


def expected_calibration_error(y_true: Any, y_score: Any, n_bins: int = 10) -> float:
    """Expected Calibration Error with equal-width probability bins."""
    yt, ys = _as_arrays(y_true, y_score)
    if len(yt) == 0:
        return float("nan")
    ys = np.clip(ys, 0.0, 1.0)
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(yt)
    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        mask = (ys >= lo) & (ys <= hi if i == n_bins - 1 else ys < hi)
        if not mask.any():
            continue
        bin_conf = ys[mask].mean()
        bin_acc = yt[mask].mean()
        ece += abs(bin_conf - bin_acc) * (mask.sum() / n)
    return float(ece)
