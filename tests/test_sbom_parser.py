"""CycloneDX SBOM parser tests."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import polars as pl
import pyarrow.parquet as pq
import pytest

from patchpilot.serve.sbom import (
    cves_for_components,
    parse_cyclonedx,
    parse_purl,
)
from patchpilot.validate.schemas import nvd_bronze_schema


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
    """Without a bronze NVD dir we still surface inline-VEX matches."""
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
    assert len(pairs) == 1
    assert pairs[0].purl == "pkg:pypi/foo@1.0"
    assert pairs[0].cve_id == "CVE-2024-0001"
    assert pairs[0].match_method == "inline_vex"
    assert pairs[0].match_confidence == "high"


def test_cves_for_components_version_exact_match(tmp_path: Path) -> None:
    """Product+version equality yields medium-confidence product_version_exact."""
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()
    nvd = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-1111", "CVE-2024-2222"],
            "published_date": [date(2024, 1, 1), date(2024, 1, 2)],
            "last_modified_date": [date(2024, 1, 2), date(2024, 1, 3)],
            "cvss_v3_base_score": [9.8, 5.0],
            "cvss_v3_severity": ["CRITICAL", "MEDIUM"],
            "cvss_v3_vector": ["AV:N", "AV:N"],
            "cwe_ids": [["CWE-79"], ["CWE-22"]],
            "vendor_count": [1, 1],
            "product_count": [1, 1],
            "description": ["a", "b"],
            "description_len": [1, 1],
            "ref_has_exploit": [False, False],
            "ref_has_patch": [True, True],
            "vendors": [["openssl"], ["openssl"]],
            "products": [["openssl"], ["openssl"]],
            "versions": [["3.0.0"], ["3.0.1"]],
        }
    )
    pq.write_table(nvd.to_arrow().cast(nvd_bronze_schema()), nvd_dir / "2024-01-01.parquet")

    components = parse_cyclonedx(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "3.0.0",
                    "purl": "pkg:generic/openssl@3.0.0",
                }
            ],
        }
    )
    matches = cves_for_components(components, nvd_bronze_dir=nvd_dir)
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2024-1111"
    assert matches[0].match_method == "product_version_exact"
    assert matches[0].match_confidence == "medium"


def test_cves_for_components_skips_version_mismatch(tmp_path: Path) -> None:
    """When both sides have versions and they disagree, do not emit the CVE."""
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()
    nvd = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-3333"],
            "published_date": [date(2024, 1, 1)],
            "last_modified_date": [date(2024, 1, 2)],
            "cvss_v3_base_score": [9.8],
            "cvss_v3_severity": ["CRITICAL"],
            "cvss_v3_vector": ["AV:N"],
            "cwe_ids": [["CWE-79"]],
            "vendor_count": [1],
            "product_count": [1],
            "description": ["a"],
            "description_len": [1],
            "ref_has_exploit": [False],
            "ref_has_patch": [True],
            "vendors": [["openssl"]],
            "products": [["openssl"]],
            "versions": [["1.1.1"]],
        }
    )
    pq.write_table(nvd.to_arrow().cast(nvd_bronze_schema()), nvd_dir / "2024-01-01.parquet")
    components = parse_cyclonedx(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "openssl",
                    "version": "3.0.0",
                    "purl": "pkg:generic/openssl@3.0.0",
                }
            ],
        }
    )
    assert cves_for_components(components, nvd_bronze_dir=nvd_dir) == []
