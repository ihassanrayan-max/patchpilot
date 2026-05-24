"""Rolling closed-window holdout selection for training and benchmarking."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

import polars as pl

# Deprecated fixed calendar cutoff; kept for backward-compatible imports only.
HELDOUT_PUBLISHED_FROM = date(2025, 1, 1)


@dataclass(frozen=True)
class EvalHoldoutConfig:
    """Configuration for the rolling evaluation holdout window."""

    holdout_days: int = 90
    min_rows: int = 50
    min_positives: int = 1
    min_holdout_days: int = 14


@dataclass(frozen=True)
class HoldoutWindow:
    """A selected evaluation window over right-censored CVE rows."""

    start: date
    end: date
    n_rows: int
    n_positives: int
    window_days: int


@dataclass(frozen=True)
class HoldoutSelection:
    """Result of attempting to pick a rolling holdout slice."""

    window: HoldoutWindow | None
    holdout_frame: pl.DataFrame | None
    reason: str | None = None


def load_eval_holdout_config(config: dict[str, Any]) -> EvalHoldoutConfig:
    """Read holdout settings from a parsed settings.toml dict."""
    eval_cfg = config.get("eval") or {}
    return EvalHoldoutConfig(
        holdout_days=int(eval_cfg.get("holdout_days", 90)),
        min_rows=int(eval_cfg.get("min_holdout_rows", 50)),
        min_positives=int(eval_cfg.get("min_holdout_positives", 1)),
        min_holdout_days=int(eval_cfg.get("min_holdout_days", 14)),
    )


def _window_day_candidates(cfg: EvalHoldoutConfig) -> list[int]:
    """Return decreasing holdout lengths to try, longest first."""
    candidates: list[int] = []
    days = cfg.holdout_days
    while True:
        candidates.append(days)
        if days <= cfg.min_holdout_days:
            break
        next_days = max(cfg.min_holdout_days, days // 2)
        if next_days == days:
            break
        days = next_days
    return candidates


def select_eval_holdout(
    closed: pl.DataFrame,
    cfg: EvalHoldoutConfig,
) -> HoldoutSelection:
    """Pick the most recent closed window that meets row/positive minimums.

    The window is always anchored at the latest right-censored ``published_date``.
    If the configured ``holdout_days`` window is too sparse, shorter windows are
    tried down to ``min_holdout_days``.
    """
    if len(closed) == 0:
        return HoldoutSelection(
            window=None,
            holdout_frame=None,
            reason="no closed-window rows available after right-censoring",
        )

    max_date_raw = closed.get_column("published_date").max()
    if not isinstance(max_date_raw, date):
        return HoldoutSelection(
            window=None,
            holdout_frame=None,
            reason="could not determine the latest closed publication date",
        )
    max_date = max_date_raw

    best_attempt: tuple[int, int, int] | None = None
    for window_days in _window_day_candidates(cfg):
        start = max_date - timedelta(days=window_days - 1)
        subset = closed.filter(
            (pl.col("published_date") >= pl.lit(start))
            & (pl.col("published_date") <= pl.lit(max_date))
        )
        n_rows = len(subset)
        n_pos = int(subset.get_column("exploited_30d").sum()) if n_rows else 0
        best_attempt = (window_days, n_rows, n_pos)

        if n_rows >= cfg.min_rows and n_pos >= cfg.min_positives:
            window = HoldoutWindow(
                start=start,
                end=max_date,
                n_rows=n_rows,
                n_positives=n_pos,
                window_days=window_days,
            )
            return HoldoutSelection(window=window, holdout_frame=subset, reason=None)

    assert best_attempt is not None
    window_days, n_rows, n_pos = best_attempt
    return HoldoutSelection(
        window=None,
        holdout_frame=None,
        reason=(
            f"no rolling holdout window met minimums "
            f"(need >= {cfg.min_rows} rows and >= {cfg.min_positives} positives; "
            f"best attempt was last {window_days}d with n={n_rows}, positives={n_pos})"
        ),
    )


def compute_holdout_content_sha256(frame: pl.DataFrame) -> str:
    """Stable SHA-256 over CVE ids, publication dates, and labels."""
    cols = ["cve_id", "published_date", "exploited_30d"]
    missing = [c for c in cols if c not in frame.columns]
    if missing:
        raise ValueError(f"holdout hash requires columns {cols}; missing {missing}")
    canonical = frame.select(cols).sort("cve_id")
    lines = ["cve_id,published_date,exploited_30d"]
    for cve_id, pub, exploited in canonical.iter_rows():
        pub_s = pub.isoformat() if hasattr(pub, "isoformat") else str(pub)
        lines.append(f"{cve_id},{pub_s},{int(bool(exploited))}")
    payload = "\n".join(lines).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
