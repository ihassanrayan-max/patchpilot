"""FastAPI integration tests with injectable model/silver paths."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.fixtures.build import build_fixture_tree, write_fixture_settings


@pytest.fixture()
def trained_env(tmp_path: Path) -> Path:
    """Build fixtures, train a model, and return the workspace root."""
    from patchpilot.train.train import train_lgbm

    paths = build_fixture_tree(tmp_path)
    write_fixture_settings(tmp_path)
    original = Path.cwd()
    try:
        os.chdir(tmp_path)
        train_lgbm(tmp_path / "settings.toml")
    finally:
        os.chdir(original)
    assert paths["silver"].exists()
    assert (tmp_path / ".mlruns" / "latest.json").exists()
    return tmp_path


def _client_for(root: Path) -> TestClient:
    from patchpilot.serve import api as api_mod

    api_mod.STATE.load(
        mlruns_dir=root / ".mlruns",
        silver_path=root / "data" / "silver" / "cve_master.parquet",
        bronze_nvd_dir=root / "data" / "bronze" / "nvd",
    )
    return TestClient(api_mod.app)


def test_healthz_and_model_info(trained_env: Path) -> None:
    client = _client_for(trained_env)
    health = client.get("/healthz")
    assert health.status_code == 200
    body = health.json()
    assert body["status"] == "ok"
    assert body["model_version"] is not None

    info = client.get("/model/info")
    assert info.status_code == 200
    assert info.json()["n_features"] is not None


def test_score_known_and_unknown_cves(trained_env: Path) -> None:
    client = _client_for(trained_env)
    resp = client.post(
        "/score",
        json={"cve_ids": ["CVE-2023-0001", "CVE-2099-99999"]},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert len(payload["results"]) == 2
    by_id = {r["cve_id"]: r for r in payload["results"]}
    assert by_id["CVE-2099-99999"]["probability"] == 0.0
    assert 0.0 <= by_id["CVE-2023-0001"]["probability"] <= 1.0


def test_score_rejects_empty_batch(trained_env: Path) -> None:
    client = _client_for(trained_env)
    resp = client.post("/score", json={"cve_ids": []})
    assert resp.status_code == 422


def test_rank_inline_vex_includes_match_metadata(trained_env: Path) -> None:
    client = _client_for(trained_env)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "bom-ref": "pkg:generic/openssl@3.0.0",
                "name": "openssl",
                "version": "3.0.0",
                "purl": "pkg:generic/openssl@3.0.0",
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2023-0001",
                "affects": [{"ref": "pkg:generic/openssl@3.0.0"}],
            }
        ],
    }
    resp = client.post("/rank", json={"sbom": sbom})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert items
    assert items[0]["match_method"] == "inline_vex"
    assert items[0]["match_confidence"] == "high"
    assert "match_reason" in items[0]


def test_rank_rejects_non_cyclonedx(trained_env: Path) -> None:
    client = _client_for(trained_env)
    resp = client.post(
        "/rank",
        json={"sbom": {"bomFormat": "SPDX", "specVersion": "2.3"}},
    )
    assert resp.status_code == 422


def test_degraded_mode_without_model(tmp_path: Path) -> None:
    """API still serves when no model artifact exists (EPSS fallback / zeros).

    ``/healthz`` must honestly report ``degraded`` (silver present, model
    missing) rather than claiming full ``ok`` readiness.
    """
    from patchpilot.serve import api as api_mod

    build_fixture_tree(tmp_path)
    api_mod.STATE.load(
        mlruns_dir=tmp_path / "missing-mlruns",
        silver_path=tmp_path / "data" / "silver" / "cve_master.parquet",
        bronze_nvd_dir=tmp_path / "data" / "bronze" / "nvd",
    )
    client = TestClient(api_mod.app)
    health = client.get("/healthz").json()
    assert health["status"] == "degraded"
    assert health["model_version"] is None
    scored = client.post("/score", json={"cve_ids": ["CVE-2023-0001"]})
    assert scored.status_code == 200
    assert scored.json()["model_version"] == "unavailable"


def test_healthz_degraded_when_silver_missing(tmp_path: Path) -> None:
    """No silver at all (fresh checkout, no ingest yet) is also ``degraded``."""
    from patchpilot.serve import api as api_mod

    api_mod.STATE.load(
        mlruns_dir=tmp_path / "missing-mlruns",
        silver_path=tmp_path / "data" / "silver" / "cve_master.parquet",
        bronze_nvd_dir=tmp_path / "data" / "bronze" / "nvd",
    )
    client = TestClient(api_mod.app)
    health = client.get("/healthz").json()
    assert health["status"] == "degraded"


def test_readyz_200_when_silver_present(trained_env: Path) -> None:
    """``/readyz`` is 200 once silver is present, regardless of model."""
    client = _client_for(trained_env)
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["silver_present"] is True


def test_readyz_503_when_silver_missing(tmp_path: Path) -> None:
    """``/readyz`` is 503 when silver is missing, even without a model."""
    from patchpilot.serve import api as api_mod

    api_mod.STATE.load(
        mlruns_dir=tmp_path / "missing-mlruns",
        silver_path=tmp_path / "data" / "silver" / "cve_master.parquet",
        bronze_nvd_dir=tmp_path / "data" / "bronze" / "nvd",
    )
    client = TestClient(api_mod.app)
    resp = client.get("/readyz")
    assert resp.status_code == 503


def test_rank_sbom_helper_used_by_cli_matches_route(trained_env: Path) -> None:
    """The extracted ``rank_sbom`` helper (shared with the CLI) matches the route."""
    from patchpilot.serve import api as api_mod

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "bom-ref": "pkg:generic/openssl@3.0.0",
                "name": "openssl",
                "version": "3.0.0",
                "purl": "pkg:generic/openssl@3.0.0",
            }
        ],
        "vulnerabilities": [
            {"id": "CVE-2023-0001", "affects": [{"ref": "pkg:generic/openssl@3.0.0"}]}
        ],
    }
    client = _client_for(trained_env)
    direct = api_mod.rank_sbom(api_mod.STATE, sbom)
    routed = client.post("/rank", json={"sbom": sbom}).json()
    assert [i.cve_id for i in direct.items] == [i["cve_id"] for i in routed["items"]]
