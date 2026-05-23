"""Calendar holdout window shared by training and EPSS benchmarking."""

from __future__ import annotations

import hashlib
from datetime import date

import polars as pl

HELDOUT_PUBLISHED_FROM = date(2025, 1, 1)


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
