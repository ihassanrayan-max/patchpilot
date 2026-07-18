"""CycloneDX SBOM parsing helpers and CVE candidate resolution.

Resolution order (highest confidence first):

1. Direct ``vulnerabilities[].id`` references attached to the component
   (CycloneDX inline VEX style) → ``match_method=inline_vex``.
2. Product + version equality against bronze NVD ``products``/``versions``
   → ``match_method=product_version_exact``.
3. Product-name-only match when version is missing or NVD versions are empty
   → ``match_method=product_name`` (higher false-positive risk).

This is intentionally conservative: version *ranges* from CPE
``versionStartIncluding`` / ``versionEndExcluding`` are not yet modeled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import polars as pl

from patchpilot.ingest.nvd import load_nvd_bronze

_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<name>[^@?]+)(?:@(?P<version>[^?]+))?")


@dataclass(frozen=True)
class ComponentCveMatch:
    """One component→CVE association with explicit match metadata."""

    purl: str
    cve_id: str
    match_method: str
    match_confidence: str
    match_reason: str


def parse_cyclonedx(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    """Project a CycloneDX 1.4/1.5 JSON SBOM into a list of component dicts.

    Raises ``ValueError`` on non-CycloneDX inputs (``bomFormat`` mismatch).
    Tolerant of missing optional fields. Also surfaces any inline VEX
    ``vulnerabilities[].id`` attached at the SBOM root, attaching them to
    components via ``affects[].ref``.
    """
    if not isinstance(sbom, dict):
        raise ValueError("SBOM must be a JSON object")
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("non-CycloneDX SBOM (bomFormat != 'CycloneDX')")
    spec_version = str(sbom.get("specVersion") or "")
    if not spec_version:
        raise ValueError("CycloneDX SBOM missing 'specVersion'")

    raw_components = sbom.get("components") or []
    if not isinstance(raw_components, list):
        raise ValueError("'components' must be a list")

    components: list[dict[str, Any]] = []
    bom_ref_index: dict[str, int] = {}
    for entry in raw_components:
        if not isinstance(entry, dict):
            continue
        bom_ref = entry.get("bom-ref")
        purl = entry.get("purl")
        if not purl and isinstance(bom_ref, str) and bom_ref.startswith("pkg:"):
            purl = bom_ref
        if not purl:
            purl = _purl_from_name_version(entry.get("name"), entry.get("version"))
        component: dict[str, Any] = {
            "purl": purl,
            "name": entry.get("name"),
            "version": entry.get("version"),
            "type": entry.get("type") or "library",
            "bom_ref": bom_ref or purl,
            "cve_ids": [],
        }
        if component["bom_ref"]:
            bom_ref_index[str(component["bom_ref"])] = len(components)
        components.append(component)

    for vuln in sbom.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        cve_id = _coerce_cve_id(vuln.get("id"))
        if not cve_id:
            continue
        for affect in vuln.get("affects") or []:
            ref = affect.get("ref") if isinstance(affect, dict) else None
            if isinstance(ref, str) and ref in bom_ref_index:
                idx = bom_ref_index[ref]
                if cve_id not in components[idx]["cve_ids"]:
                    components[idx]["cve_ids"].append(cve_id)

    return components


def _purl_from_name_version(name: str | None, version: str | None) -> str | None:
    """Best-effort synthetic purl from ``name@version`` for components missing one."""
    if not name:
        return None
    if version:
        return f"pkg:generic/{name}@{version}"
    return f"pkg:generic/{name}"


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _coerce_cve_id(value: Any) -> str | None:
    """Return a normalised CVE id (``CVE-YYYY-NNNN``) or ``None``."""
    if isinstance(value, str):
        m = _CVE_RE.search(value.upper())
        if m:
            return m.group(0)
    return None


def parse_purl(purl: str) -> dict[str, str | None]:
    """Parse a purl like ``pkg:pypi/foo@1.2.3`` to ``{type, name, version}``."""
    m = _PURL_RE.match(purl)
    if not m:
        return {"type": None, "name": None, "version": None}
    return {
        "type": m.group("type"),
        "name": m.group("name"),
        "version": m.group("version"),
    }


def cves_for_components(
    components: list[dict[str, Any]],
    *,
    nvd_bronze_dir: Path | None = None,
) -> list[ComponentCveMatch]:
    """Resolve components to :class:`ComponentCveMatch` candidates."""
    matches: list[ComponentCveMatch] = []
    seen: set[tuple[str, str]] = set()

    for component in components:
        purl = str(component.get("purl") or component.get("name") or "")
        for cve in component.get("cve_ids") or []:
            key = (purl, str(cve))
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                ComponentCveMatch(
                    purl=purl,
                    cve_id=str(cve),
                    match_method="inline_vex",
                    match_confidence="high",
                    match_reason="CycloneDX vulnerabilities[].id attached via affects.ref",
                )
            )

    if nvd_bronze_dir is None:
        return matches

    try:
        nvd = load_nvd_bronze(Path(nvd_bronze_dir))
    except FileNotFoundError:
        return matches

    product_index = _build_product_index(nvd)
    for component in components:
        purl = str(component.get("purl") or "")
        parsed = parse_purl(purl)
        name = (parsed.get("name") or component.get("name") or "").lower()
        version = parsed.get("version") or component.get("version")
        version_s = str(version).lower() if version else None
        if not name:
            continue
        for entry in product_index.get(name, []):
            cve_id = entry["cve_id"]
            key = (purl, cve_id)
            if key in seen:
                continue
            versions = entry.get("versions") or []
            versions_l = {v.lower() for v in versions}
            if version_s and versions_l and version_s in versions_l:
                method = "product_version_exact"
                confidence = "medium"
                reason = (
                    f"product '{name}' with version '{version_s}' matched NVD CPE versions"
                )
            elif version_s and versions_l and version_s not in versions_l:
                # Version present on both sides but no equality → skip (reduce FP).
                continue
            else:
                method = "product_name"
                confidence = "low"
                reason = (
                    f"product '{name}' matched NVD products without version equality "
                    "(higher false-positive risk)"
                )
            seen.add(key)
            matches.append(
                ComponentCveMatch(
                    purl=purl,
                    cve_id=cve_id,
                    match_method=method,
                    match_confidence=confidence,
                    match_reason=reason,
                )
            )

    return matches


def _build_product_index(nvd: pl.DataFrame) -> dict[str, list[dict[str, Any]]]:
    """Build lowercased product → [{cve_id, versions}] index from bronze NVD."""
    if "products" not in nvd.columns:
        return {}
    has_versions = "versions" in nvd.columns
    select_cols = ["cve_id", "products"] + (["versions"] if has_versions else [])
    exploded = (
        nvd.select(select_cols)
        .with_columns(pl.col("products").fill_null([]))
        .explode("products")
        .rename({"products": "product"})
        .filter(pl.col("product").is_not_null())
        .with_columns(pl.col("product").str.to_lowercase())
    )
    index: dict[str, list[dict[str, Any]]] = {}
    for row in exploded.iter_rows(named=True):
        product = cast(str, row["product"])
        versions_raw = row.get("versions") if has_versions else None
        versions: list[str] = []
        if isinstance(versions_raw, list):
            versions = [str(v) for v in versions_raw if v is not None]
        index.setdefault(product, []).append(
            {"cve_id": cast(str, row["cve_id"]), "versions": versions}
        )
    return index
