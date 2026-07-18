# Runbook

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

Bad or missing artifacts must not crash the process: `/healthz` stays `ok`
with `model_version=null`, and `/score` falls back to EPSS when silver exists.

## Common issues

- **`uv sync` fails on Windows**: run `uv python install 3.11` first.
- **`docker compose build` slow**: first build resolves deps; later builds cache.
- **Model missing in API**: confirm `.mlruns/` is bind-mounted and `latest.json` exists.
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
4. Smoke: `/healthz`, `/model/info`, `/score`, `/rank`.
5. Keep weekly live eval separate from the web process.

## Phase exit criteria

See [`PLAN.md`](../PLAN.md) and the Status Ledger in
[`PATCHPILOT_MASTER_ROADMAP.md`](../PATCHPILOT_MASTER_ROADMAP.md).
