# Runbook

## First run (local)

1. Install Python 3.11 and [uv](https://docs.astral.sh/uv/).
2. Clone the repo and sync dependencies:

   ```bash
   uv sync
   uv python install 3.11
   ```

3. Run the fixture pipeline (no live NVD key required):

   ```bash
   make test-e2e
   ```

   This builds silver/gold fixtures, trains a model into `.mlruns/`, and exercises the API.

4. Start the API and rank a sample SBOM:

   ```bash
   make serve
   # in another shell:
   curl -s http://localhost:8000/healthz
   curl -s http://localhost:8000/readyz
   uv run patchpilot rank --sbom sample_sbom.json --local
   ```

5. Optional Docker path:

   ```bash
   make up
   curl -s http://localhost:8000/healthz
   make down
   ```

## Local quickstart

```
uv sync
make test          # unit + integration tests
make test-e2e      # fixture train/eval/API (no live NVD)
make ingest        # live NVD/EPSS/KEV → bronze + silver
make train         # LightGBM → .mlruns/<run_id>/
make eval          # docs/benchmarks/REPORT.md (+ README sync)
make ablate        # docs/benchmarks/ABLATIONS.md
make serve         # API :8000
make demo          # Streamlit :8501
```

Docker:

```
make up            # api :8000 + demo :8501
docker compose run --rm trainer   # one-shot train against bind-mounted data
make down
```

## Environment overrides

| Variable | Default | Purpose |
|----------|---------|---------|
| `NVD_API_KEY` | unset | Faster NVD paging (~0.6s vs ~6.5s) |
| `PATCHPILOT_MLRUNS_DIR` | `.mlruns` | Model registry directory |
| `PATCHPILOT_SILVER_PATH` | `data/silver/cve_master.parquet` | Silver parquet path |
| `PATCHPILOT_BRONZE_NVD_DIR` | `data/bronze/nvd` | NVD bronze for SBOM matching |
| `PATCHPILOT_API` | `http://localhost:8000` | Streamlit demo API base URL |

## Artifact layout / rollback

```
.mlruns/<run_id>/model.pkl
.mlruns/<run_id>/metadata.json
.mlruns/latest.json
```

To roll back a bad train:

1. Inspect `.mlruns/*/metadata.json` for a previous good `run_id`.
2. Point `latest.json` at that run's `model.pkl` and version.
3. Restart the API process (`make serve` or recreate the `api` container).

Bad or missing artifacts must not crash the process: `/healthz` reports `ok` or
`degraded`, and `/score` falls back to EPSS when silver exists. `/readyz` returns
200 only when the score path can return non-vacuous results (silver present).

## Use in your CI

PatchPilot ships a composite GitHub Action that ranks a CycloneDX SBOM against a
running API. The job fails if `/readyz` is not HTTP 200.

### Prerequisites

- A reachable PatchPilot API (`docker compose up`, a hosted instance, or a CI job
  that starts the API before ranking).
- A CycloneDX JSON SBOM file in the repository or generated earlier in the workflow.

### Minimal workflow

```yaml
jobs:
  rank-sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Rank vulnerabilities
        uses: ihassanrayan-max/patchpilot/.github/actions/rank-sbom@v0.1.0
        with:
          sbom-path: path/to/sbom.json
          api-url: https://patchpilot.example.com
          output-path: ranked.json

      - name: Upload ranked report
        uses: actions/upload-artifact@v4
        with:
          name: ranked-sbom
          path: ranked.json
```

### Inputs and outputs

| Input | Required | Description |
|-------|----------|-------------|
| `sbom-path` | yes | CycloneDX JSON file on the runner |
| `api-url` | yes | API base URL (no trailing slash) |
| `output-path` | no | Output file (default `ranked-sbom.json`) |

| Output | Description |
|--------|-------------|
| `ranked-json-path` | Path to the ranked JSON written by the action |

See [`.github/workflows/example-rank-sbom.yml`](../.github/workflows/example-rank-sbom.yml)
for a `workflow_dispatch` sample in this repository.

### Release artifacts

Tagged releases (`v*`) publish sdist and wheel assets via
[`.github/workflows/release.yml`](../.github/workflows/release.yml). Install from
a wheel in CI with:

```bash
uv pip install patchpilot-0.1.0-py3-none-any.whl
patchpilot rank --sbom sbom.json --api https://your-api.example.com
```

## Common issues

- **`uv sync` fails on Windows**: run `uv python install 3.11` first.
- **`docker compose build` slow**: first build resolves deps; later builds cache.
- **Model missing in API**: confirm `.mlruns/` is bind-mounted and `latest.json` exists.
- **Action fails on `/readyz`**: ensure silver data is mounted and the API finished startup.
- **Benchmark unavailable**: REPORT explains why (sparse holdout, missing silver/model).
  README table becomes `n/a` — do not invent numbers.
- **SBOM false positives**: `/rank` includes `match_method` / `match_confidence` /
  `match_reason`. Prefer `inline_vex` or `product_version_exact` over `product_name`.
- **Live ingest rate limits**: set `NVD_API_KEY`; use `--cache-dir data/cache`.

## Degraded / no-model mode

```
# Temporarily hide the registry
mv .mlruns .mlruns.bak
make serve
curl localhost:8000/healthz    # model_version null
curl -X POST localhost:8000/score -H 'content-type: application/json' \
  -d '{"cve_ids":["CVE-2023-0001"]}'
mv .mlruns.bak .mlruns
```

## Deployment notes (Phase 7)

Do not deploy publicly until [`PATCHPILOT_MASTER_ROADMAP.md`](../PATCHPILOT_MASTER_ROADMAP.md)
credibility checklist is green. When ready:

1. Build API image from `infra/docker/Dockerfile.api`.
2. Mount or bake silver + `.mlruns` artifacts.
3. Set env path overrides and `NVD_API_KEY` only on the trainer job.
4. Smoke: `/healthz`, `/readyz`, `/model/info`, `/score`, `/rank`.
5. Keep weekly live eval separate from the web process.

## Phase exit criteria

See [`PLAN.md`](../PLAN.md) and the Status Ledger in
[`PATCHPILOT_MASTER_ROADMAP.md`](../PATCHPILOT_MASTER_ROADMAP.md).
