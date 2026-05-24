---
name: PatchPilot Roadmap
overview: A production roadmap for PatchPilot based on the current implementation, with the immediate focus on benchmark credibility before product/UI expansion.
todos:
  - id: leakage-audit
    content: Audit and fix point-in-time feature construction and benchmark leakage risks.
    status: completed
  - id: fixture-ci
    content: Add deterministic fixture-based ingest/train/eval/API tests for PR CI.
    status: pending
  - id: benchmark-contract
    content: Revise benchmark protocol, README/report behavior, and CI gate semantics.
    status: completed
  - id: api-sbom-tests
    content: Add FastAPI integration tests and clarify or implement SBOM CPE/version matching.
    status: pending
isProject: false
---

# PatchPilot Engineering Roadmap

## Current Finding
PatchPilot has a real scaffold: public vulnerability ingestion, silver CVE dataset, LightGBM training, EPSS comparison, FastAPI scoring, SBOM ranking, tests, Docker, and CI. The main blocker is not missing polish; it is trust. The current benchmark cannot be treated as credible until point-in-time data handling, evaluation fixtures, and integration tests are tightened.

Key evidence:
- [README.md](README.md) claims numeric benchmark results, while [docs/benchmarks/REPORT.md](docs/benchmarks/REPORT.md) currently says metrics could not be computed.
- [src/patchpilot/train/train.py](src/patchpilot/train/train.py) assembles features in memory and always joins graph features.
- [src/patchpilot/features/tabular.py](src/patchpilot/features/tabular.py) uses latest EPSS and current KEV membership as features.
- [src/patchpilot/features/temporal.py](src/patchpilot/features/temporal.py) computes temporal features from a global latest publication date.
- [src/patchpilot/serve/sbom.py](src/patchpilot/serve/sbom.py) documents version-aware matching, but actually resolves mostly by product name.

## Recommended Immediate Phase
Prioritize a data quality and evaluation integrity phase. This should make the project capable of making honest claims before adding model complexity, dashboards, deployment, or scanner integrations.

## Roadmap
- Phase 1: Benchmark Truth and Data Leakage Control
  - Make EPSS, KEV-derived features, temporal features, and graph/popularity features explicitly point-in-time or remove them from benchmarked training.
  - Add regression tests that fail if future data leaks into training/evaluation rows.
  - Acceptance: `make test` includes fixture-based leakage tests and benchmark docs no longer overstate results.

- Phase 2: Deterministic E2E Fixture Pipeline
  - Add small frozen fixtures for NVD, KEV, EPSS, silver, train, eval, and API smoke paths.
  - Add CI jobs that verify ingest-to-report behavior without relying on live public APIs.
  - Acceptance: PR CI proves the pipeline works on fixed data; weekly live benchmark remains separate.

- Phase 3: Honest Model Benchmarking
  - Decide whether PatchPilot is a standalone EPSS challenger or a residual/reranking model over EPSS.
  - Use stable holdout windows, meaningful gates, and clearly documented positive-rate/row-count thresholds.
  - Acceptance: benchmark report is reproducible, non-empty, and explains when EPSS wins.

- Phase 4: API and SBOM Correctness
  - Add FastAPI TestClient coverage, deterministic degraded-mode behavior, and a real CPE/version matching design.
  - Acceptance: `/score` and `/rank` behavior is tested, documented, and does not silently imply version precision it lacks.

- Phase 5: Productizable Operations
  - Add path/env config, Docker compose cleanup, minimal deployment docs, logging, payload limits, and artifact versioning.
  - Acceptance: fresh clone, Docker, API, demo, and benchmark workflows are reliable and documented.

- Phase 6: Advanced Extensions
  - Only after the above: SHAP, conformal intervals, ExploitDB/GHSA enrichment, scanner/GitHub Action integrations, UI/dashboard, cloud deployment, and LLM features.

## What Not To Build Yet
Do not build dashboards, LLM explanations, startup features, scanner integrations, or cloud deployment until the benchmark and SBOM mapping are honest. Those would make the project look larger but not more trustworthy.