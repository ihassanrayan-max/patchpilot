"""Temporal cross-validation correctness tests.

Ensures the splitter:
* never overlaps train and valid sets within a fold,
* leaves at least ``embargo_days`` between train end and valid start,
* respects the chronological order across folds.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from patchpilot.train.temporal_cv import temporal_splits


def _make_dates(n: int, start: date = date(2022, 1, 1)) -> list[date]:
    """Synthesise ``n`` sequential daily dates starting at ``start``."""
    return [start + timedelta(days=i) for i in range(n)]


def test_temporal_splits_basic_shapes_and_no_overlap() -> None:
    """Three folds, 30d horizon, 30d embargo: each fold is non-empty and disjoint."""
    dates = _make_dates(365)
    folds = list(temporal_splits(dates, n_splits=3, horizon_days=30, embargo_days=30))
    assert len(folds) == 3
    for train_idx, valid_idx in folds:
        assert train_idx
        assert valid_idx
        assert set(train_idx).isdisjoint(set(valid_idx))


def test_temporal_splits_embargo_respected() -> None:
    """``max(train_dates) + embargo <= min(valid_dates)`` holds for every fold."""
    dates = _make_dates(365)
    embargo = 30
    folds = list(temporal_splits(dates, n_splits=3, horizon_days=30, embargo_days=embargo))
    for train_idx, valid_idx in folds:
        train_dates = [dates[i] for i in train_idx]
        valid_dates = [dates[i] for i in valid_idx]
        gap = (min(valid_dates) - max(train_dates)).days
        assert gap > embargo, f"embargo violated: gap={gap}"


def test_temporal_splits_forward_chaining() -> None:
    """Later folds train on a strict superset of earlier folds' training data."""
    dates = _make_dates(365)
    folds = list(temporal_splits(dates, n_splits=4, horizon_days=20, embargo_days=10))
    prev_train: set[int] | None = None
    for train_idx, _ in folds:
        if prev_train is not None:
            assert prev_train.issubset(set(train_idx))
        prev_train = set(train_idx)


def test_temporal_splits_rejects_insufficient_span() -> None:
    """Asking for n_splits*horizon greater than the date span raises."""
    with pytest.raises(ValueError):
        list(temporal_splits(_make_dates(30), n_splits=5, horizon_days=30, embargo_days=30))


def test_temporal_splits_validates_arguments() -> None:
    """Non-positive split/horizon and negative embargo raise immediately."""
    with pytest.raises(ValueError):
        list(temporal_splits(_make_dates(10), n_splits=0, horizon_days=1, embargo_days=0))
    with pytest.raises(ValueError):
        list(temporal_splits(_make_dates(10), n_splits=1, horizon_days=0, embargo_days=0))
    with pytest.raises(ValueError):
        list(temporal_splits(_make_dates(10), n_splits=1, horizon_days=1, embargo_days=-1))
    with pytest.raises(ValueError):
        list(temporal_splits([], n_splits=1, horizon_days=1, embargo_days=0))
