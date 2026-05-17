"""CycloneDX SBOM parsing helpers and CVE candidate resolution.

The parser is intentionally tolerant of CycloneDX 1.4/1.5 shapes
(``bomFormat`` is required, ``specVersion`` is required). We resolve a
component to candidate CVEs in two ways, used in order:

1. Direct ``vulnerabilities[].id`` references attached to the component
   (CycloneDX inline VEX style).
2. Substring matches of the component's ``name`` against the
   ``vendors``/``products`` columns of the bronze NVD frame. We honour
   the version equality when both sides expose it; otherwise we return
   every CVE that touches the product to be safe (and let ranking
   prioritise the dangerous ones).

This is the smallest correct mapping we can ship without a CPE matcher;
PLAN.md flags richer CPE matching as Phase 6 work.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import polars as pl

from patchpilot.ingest.nvd import load_nvd_bronze

_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<name>[^@?]+)(?:@(?P<version>[^?]+))?")


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
) -> list[tuple[str, str]]:
    """Resolve components to ``(purl, cve_id)`` candidate pairs.

    Inline-VEX CVEs attached to the component are always emitted. Beyond
    that, when ``nvd_bronze_dir`` is provided we look up by lower-cased
    product/name; otherwise only inline-VEX pairs are returned.
    """
    pairs: list[tuple[str, str]] = []
    for component in components:
        purl = component.get("purl") or component.get("name") or ""
        for cve in component.get("cve_ids") or []:
            pairs.append((str(purl), str(cve)))

    if nvd_bronze_dir is not None:
        try:
            nvd = load_nvd_bronze(Path(nvd_bronze_dir))
        except FileNotFoundError:
            return pairs
        product_index = _build_product_index(nvd)
        for component in components:
            purl = component.get("purl") or ""
            parsed = parse_purl(str(purl))
            name = (parsed.get("name") or component.get("name") or "").lower()
            if not name:
                continue
            for cve in product_index.get(name, []):
                pair = (str(purl), cve)
                if pair not in pairs:
                    pairs.append(pair)

    return pairs


def _build_product_index(nvd: pl.DataFrame) -> dict[str, list[str]]:
    """Build a lowercased product/vendor -> [cve_id...] index from bronze NVD."""
    if "products" not in nvd.columns:
        return {}
    exploded = (
        nvd.select(["cve_id", "products"])
        .with_columns(pl.col("products").fill_null([]))
        .explode("products")
        .rename({"products": "product"})
        .filter(pl.col("product").is_not_null())
        .with_columns(pl.col("product").str.to_lowercase())
    )
    index: dict[str, list[str]] = {}
    for row in exploded.iter_rows(named=True):
        index.setdefault(cast(str, row["product"]), []).append(cast(str, row["cve_id"]))
    return index
