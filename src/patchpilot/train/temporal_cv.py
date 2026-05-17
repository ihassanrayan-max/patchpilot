"""Time-based forward-chaining cross-validation splitter.

Implemented in: Phase 2.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date


def temporal_splits(
    dates: list[date],
    n_splits: int,
    horizon_days: int,
    embargo_days: int,
) -> Iterator[tuple[list[int], list[int]]]:
    """Yield ``(train_idx, valid_idx)`` index pairs respecting time order.

    Inputs:  ``dates`` — per-row publication dates aligned with the dataset.
             ``n_splits`` — number of forward-chaining folds.
             ``horizon_days`` — validation horizon length in days.
             ``embargo_days`` — gap between train end and validation start to
                                prevent label leakage from the 30-day window.
    Outputs: iterator of ``(train_idx, valid_idx)`` row-index lists.
    Invariants: ``max(train_idx_dates) + embargo_days <= min(valid_idx_dates)``;
                no row appears in both splits within a fold.
    Implemented in: Phase 2.
    """
    raise NotImplementedError("Phase 2")
