"""CycloneDX SBOM parsing helpers.

Implemented in: Phase 4.
"""

from __future__ import annotations

from typing import Any


def parse_cyclonedx(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a CycloneDX 1.5 JSON SBOM into a list of component dicts.

    Inputs:  ``sbom`` — CycloneDX 1.5 JSON document.
    Outputs: list of dicts with keys ``purl``, ``name``, ``version``, ``type``.
    Invariants: tolerant of missing optional fields; raises ``ValueError`` on
                non-CycloneDX inputs (``bomFormat != 'CycloneDX'``).
    Implemented in: Phase 4.
    """
    raise NotImplementedError("Phase 4")


def cves_for_components(components: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Resolve a list of components to candidate ``(component_purl, cve_id)`` pairs.

    Inputs:  ``components`` — output of ``parse_cyclonedx``.
    Outputs: list of ``(purl, cve_id)`` tuples (one per affected CVE).
    Invariants: uses local silver CVE↔CPE/PURL mappings only — no network calls.
    Implemented in: Phase 4.
    """
    raise NotImplementedError("Phase 4")
