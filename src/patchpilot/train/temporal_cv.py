"""Time-based forward-chaining cross-validation splitter.

Implements an embargoed expanding-window scheme:

* sort rows by date,
* fix ``n_splits`` validation windows of ``horizon_days`` each, anchored
  at evenly spaced dates near the tail of the dataset,
* training set for fold ``i`` is every row whose date is at most
  ``valid_start_i - embargo_days``.

The embargo prevents the 30-day label horizon from leaking into the
training set (a row labelled "exploited within 30 days" cannot be known
until 30 days after its publication).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date, timedelta


def temporal_splits(
    dates: list[date],
    n_splits: int,
    horizon_days: int,
    embargo_days: int,
) -> Iterator[tuple[list[int], list[int]]]:
    """Yield ``(train_idx, valid_idx)`` index pairs respecting time order.

    Raises ``ValueError`` for nonsensical inputs.
    """
    if n_splits < 1:
        raise ValueError("n_splits must be >= 1")
    if horizon_days < 1:
        raise ValueError("horizon_days must be >= 1")
    if embargo_days < 0:
        raise ValueError("embargo_days must be >= 0")
    if not dates:
        raise ValueError("dates must be non-empty")

    indexed = sorted(enumerate(dates), key=lambda pair: pair[1])
    first = indexed[0][1]
    last = indexed[-1][1]
    span_days = (last - first).days
    if span_days < n_splits * horizon_days + embargo_days:
        raise ValueError(
            f"insufficient date span ({span_days}d) for "
            f"n_splits={n_splits} horizon={horizon_days}d embargo={embargo_days}d"
        )

    valid_block_total = n_splits * horizon_days
    valid_block_start = last - timedelta(days=valid_block_total - 1)

    for fold in range(n_splits):
        valid_start = valid_block_start + timedelta(days=fold * horizon_days)
        valid_end = valid_start + timedelta(days=horizon_days - 1)
        train_cutoff = valid_start - timedelta(days=embargo_days + 1)

        train_idx: list[int] = []
        valid_idx: list[int] = []
        for original_index, d in indexed:
            if d <= train_cutoff:
                train_idx.append(original_index)
            elif valid_start <= d <= valid_end:
                valid_idx.append(original_index)

        if not train_idx or not valid_idx:
            continue
        yield train_idx, valid_idx
