"""CycloneDX SBOM parser tests."""

from __future__ import annotations

import pytest

from patchpilot.serve.sbom import (
    cves_for_components,
    parse_cyclonedx,
    parse_purl,
)


def test_parse_cyclonedx_accepts_basic_15_sbom() -> None:
    """A minimal CycloneDX 1.5 SBOM produces one component dict per entry."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "foo", "version": "1.2.3", "purl": "pkg:pypi/foo@1.2.3"},
            {"type": "library", "name": "bar", "version": "0.9", "purl": "pkg:npm/bar@0.9"},
        ],
    }
    components = parse_cyclonedx(sbom)
    assert len(components) == 2
    assert components[0]["purl"] == "pkg:pypi/foo@1.2.3"
    assert components[1]["name"] == "bar"
    assert all(c["cve_ids"] == [] for c in components)


def test_parse_cyclonedx_rejects_non_cyclonedx() -> None:
    """A wrong bomFormat raises ``ValueError``."""
    with pytest.raises(ValueError):
        parse_cyclonedx({"bomFormat": "SPDX", "specVersion": "1.5"})


def test_parse_cyclonedx_requires_spec_version() -> None:
    """Missing specVersion raises ``ValueError``."""
    with pytest.raises(ValueError):
        parse_cyclonedx({"bomFormat": "CycloneDX"})


def test_parse_cyclonedx_propagates_inline_vex() -> None:
    """Inline ``vulnerabilities[].id`` is attached to the matching component."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": "pkg:pypi/openssl@3.0.0", "name": "openssl", "version": "3.0.0"},
            {"bom-ref": "pkg:pypi/foo@1.0", "name": "foo", "version": "1.0"},
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-1234",
                "affects": [{"ref": "pkg:pypi/openssl@3.0.0"}],
            }
        ],
    }
    components = parse_cyclonedx(sbom)
    by_name = {c["name"]: c for c in components}
    assert by_name["openssl"]["cve_ids"] == ["CVE-2024-1234"]
    assert by_name["foo"]["cve_ids"] == []


def test_parse_purl_extracts_type_name_version() -> None:
    """``parse_purl`` returns type/name/version split."""
    parts = parse_purl("pkg:pypi/foo@1.2.3")
    assert parts == {"type": "pypi", "name": "foo", "version": "1.2.3"}


def test_parse_purl_handles_missing_version() -> None:
    """A purl without ``@version`` yields ``version=None``."""
    parts = parse_purl("pkg:npm/bar")
    assert parts == {"type": "npm", "name": "bar", "version": None}


def test_parse_purl_returns_none_for_invalid_string() -> None:
    """A non-purl string yields all-None fields."""
    parts = parse_purl("definitely not a purl")
    assert parts == {"type": None, "name": None, "version": None}


def test_cves_for_components_returns_inline_vex_pairs_without_bronze() -> None:
    """Without a bronze NVD dir we still surface inline-VEX (purl, cve) pairs."""
    components = parse_cyclonedx(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"bom-ref": "pkg:pypi/foo@1.0", "name": "foo", "version": "1.0"}],
            "vulnerabilities": [
                {"id": "CVE-2024-0001", "affects": [{"ref": "pkg:pypi/foo@1.0"}]},
            ],
        }
    )
    pairs = cves_for_components(components)
    assert pairs == [("pkg:pypi/foo@1.0", "CVE-2024-0001")]
