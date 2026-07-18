"""Fixture-based end-to-end: silver → train → eval → API smoke (no network)."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi.testclient import TestClient

from patchpilot.eval.compare_epss import assert_benchmark_gate, write_report
from patchpilot.train.train import train_lgbm
from tests.fixtures.build import build_fixture_tree, write_fixture_settings


def test_fixture_e2e_train_eval_api(tmp_path: Path) -> None:
    """Prove the core pipeline on frozen synthetic data without live NVD/EPSS."""
    build_fixture_tree(tmp_path)
    config_path = write_fixture_settings(tmp_path)
    report_path = tmp_path / "docs" / "benchmarks" / "REPORT.md"
    readme_path = tmp_path / "README.md"
    readme_path.write_text(
        "| Model       | AUC-PR | AUC-ROC | P@100 | Brier | ECE |\n"
        "| ----------- | ------ | ------- | ----- | ----- | --- |\n"
        "| PatchPilot  | n/a | n/a | n/a | n/a | n/a |\n"
        "| EPSS        | n/a | n/a | n/a | n/a | n/a |\n",
        encoding="utf-8",
    )

    original = Path.cwd()
    try:
        os.chdir(tmp_path)
        run_id = train_lgbm(config_path)
        assert run_id.startswith("run-")
        assert (tmp_path / ".mlruns" / "latest.json").exists()

        write_report(
            report_path=report_path,
            silver_path=tmp_path / "data" / "silver" / "cve_master.parquet",
            mlruns_dir=tmp_path / ".mlruns",
            readme_path=readme_path,
            config_path=config_path,
        )
        body = report_path.read_text(encoding="utf-8")
        assert "**Status:** ok" in body or "metrics computed" in body
        assert_benchmark_gate(report_path=report_path, config_path=config_path)

        from patchpilot.serve import api as api_mod

        api_mod.STATE.load(
            mlruns_dir=tmp_path / ".mlruns",
            silver_path=tmp_path / "data" / "silver" / "cve_master.parquet",
            bronze_nvd_dir=tmp_path / "data" / "bronze" / "nvd",
        )
        client = TestClient(api_mod.app)
        assert client.get("/healthz").status_code == 200
        score = client.post("/score", json={"cve_ids": ["CVE-2023-0001"]})
        assert score.status_code == 200
        rank = client.post(
            "/rank",
            json={
                "sbom": {
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
            },
        )
        assert rank.status_code == 200
        assert rank.json()["items"]
    finally:
        os.chdir(original)
