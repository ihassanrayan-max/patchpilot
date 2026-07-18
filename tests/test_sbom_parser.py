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
    """``parse_purl`` returns type/namespace/name/version split (no namespace)."""
    parts = parse_purl("pkg:pypi/foo@1.2.3")
    assert parts == {"type": "pypi", "namespace": None, "name": "foo", "version": "1.2.3"}


def test_parse_purl_handles_missing_version() -> None:
    """A purl without ``@version`` yields ``version=None``."""
    parts = parse_purl("pkg:npm/bar")
    assert parts == {"type": "npm", "namespace": None, "name": "bar", "version": None}


def test_parse_purl_returns_none_for_invalid_string() -> None:
    """A non-purl string yields all-None fields."""
    parts = parse_purl("definitely not a purl")
    assert parts == {"type": None, "namespace": None, "name": None, "version": None}


def test_parse_purl_extracts_namespace_type_name_version() -> None:
    """``pkg:type/namespace/name@version`` splits namespace from name correctly."""
    parts = parse_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
    assert parts == {
        "type": "maven",
        "namespace": "org.apache.commons",
        "name": "commons-lang3",
        "version": "3.12.0",
    }


def test_parse_purl_handles_scoped_npm_namespace() -> None:
    """A scoped npm package (``@scope/name``) is namespace + name, not CPE ranges."""
    parts = parse_purl("pkg:npm/%40babel/core@7.20.0")
    assert parts == {
        "type": "npm",
        "namespace": "@babel",
        "name": "core",
        "version": "7.20.0",
    }


def test_parse_purl_strips_qualifiers_and_subpath() -> None:
    """Qualifiers (``?arch=...``) and subpath (``#...``) are discarded, not part of version."""
    parts = parse_purl("pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie#a/b")
    assert parts == {
        "type": "deb",
        "namespace": "debian",
        "name": "curl",
        "version": "7.50.3-1",
    }


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


def test_cves_for_components_product_name_low_confidence_when_no_version(
    tmp_path: Path,
) -> None:
    """No version on either side falls back to low-confidence ``product_name``."""
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()
    nvd = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-4444"],
            "published_date": [date(2024, 1, 1)],
            "last_modified_date": [date(2024, 1, 2)],
            "cvss_v3_base_score": [7.5],
            "cvss_v3_severity": ["HIGH"],
            "cvss_v3_vector": ["AV:N"],
            "cwe_ids": [["CWE-79"]],
            "vendor_count": [1],
            "product_count": [1],
            "description": ["a"],
            "description_len": [1],
            "ref_has_exploit": [False],
            "ref_has_patch": [True],
            "vendors": [["acme"]],
            "products": [["widget"]],
            "versions": [[]],
        }
    )
    pq.write_table(nvd.to_arrow().cast(nvd_bronze_schema()), nvd_dir / "2024-01-01.parquet")
    components = parse_cyclonedx(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "widget", "purl": "pkg:generic/widget"},
            ],
        }
    )
    matches = cves_for_components(components, nvd_bronze_dir=nvd_dir)
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2024-4444"
    assert matches[0].match_method == "product_name"
    assert matches[0].match_confidence == "low"


def test_cves_for_components_missing_bronze_dir_falls_back_to_inline_vex_only(
    tmp_path: Path,
) -> None:
    """A nonexistent bronze NVD dir must not crash; inline VEX matches still surface."""
    missing_dir = tmp_path / "does-not-exist"
    components = parse_cyclonedx(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"bom-ref": "pkg:pypi/foo@1.0", "name": "foo", "version": "1.0"},
            ],
            "vulnerabilities": [
                {"id": "CVE-2024-0001", "affects": [{"ref": "pkg:pypi/foo@1.0"}]},
            ],
        }
    )
    matches = cves_for_components(components, nvd_bronze_dir=missing_dir)
    assert len(matches) == 1
    assert matches[0].match_method == "inline_vex"


def test_cves_for_components_unreadable_bronze_corpus_falls_back_to_inline_vex_only(
    tmp_path: Path,
) -> None:
    """A present-but-schema-inconsistent bronze corpus must degrade, not crash."""
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()
    # Two parquet files with incompatible column sets/lengths (real-world drift
    # between ingestion snapshots) must not blow up ranking.
    pl.DataFrame({"cve_id": ["CVE-2024-9999"], "products": [["widget"]]}).write_parquet(
        nvd_dir / "a.parquet"
    )
    pl.DataFrame({"cve_id": ["CVE-2024-8888"], "other_col": [1]}).write_parquet(
        nvd_dir / "b.parquet"
    )

    components = parse_cyclonedx(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"bom-ref": "pkg:pypi/foo@1.0", "name": "foo", "version": "1.0"},
            ],
            "vulnerabilities": [
                {"id": "CVE-2024-0001", "affects": [{"ref": "pkg:pypi/foo@1.0"}]},
            ],
        }
    )
    matches = cves_for_components(components, nvd_bronze_dir=nvd_dir)
    assert len(matches) == 1
    assert matches[0].match_method == "inline_vex"
