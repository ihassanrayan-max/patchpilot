"""PatchPilot: predict 30-day CVE exploitation and rank SBOM vulnerabilities.

Ranks CycloneDX SBOM vulnerabilities via an EPSS-complement blend (a
LightGBM residual on top of point-in-time EPSS, falling back to EPSS alone
when no model/features are available). See ``PLAN.md`` for the schema/API/
CLI contract and ``PATCHPILOT_MASTER_ROADMAP.md`` for current project status.
"""

from __future__ import annotations

__version__: str = "0.1.0"
__all__: list[str] = ["__version__"]
