"""Ingestion: download bronze CVE/exploit data from NVD, EPSS, and CISA KEV.

Implemented in: Phase 1.
"""

from __future__ import annotations

__all__: list[str] = ["nvd", "epss", "kev", "silver"]
