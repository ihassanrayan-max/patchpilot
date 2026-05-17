# PatchPilot — Build Plan

This document is the contract that downstream phase agents follow verbatim.
Every later phase must respect the schema, API, and CLI contracts below.

---

## 1. Phases

Each phase has exactly one acceptance command (the Makefile target). A phase
is "green" only when that command succeeds in a fresh clone.

### Phase 1 — Ingestion + silver lake + label

**Acceptance:** `make ingest` produces a silver Parquet at
`data/silver/cve_master.parquet` matching the schema contract below, and
the label test passes:

```
make ingest
uv run pytest -q tests/test_label_construction.py
```

Scope:
- `patchpilot.ingest.{nvd,epss,kev}` — download to `data/bronze/**`.
- `patchpilot.validate.{schemas,expectations}` — schema + GE suite.
- Silver join lands the contract below.
- Label `exploited_30d` built from KEV.
- `flows.daily_ingest.daily_ingest_flow` is runnable.

### Phase 2 — Features + train + MLflow

**Acceptance:** `make train` logs an MLflow run under `.mlruns/`, and a
deterministic re-run produces an identical (params, metrics) tuple:

```
make train
uv run pytest -q tests/test_temporal_cv.py
```

Scope:
- `patchpilot.features.{tabular,temporal,graph}` materializes gold Parquet.
- `patchpilot.train.temporal_cv` enforces embargo ≥ 30 days.
- `patchpilot.models.lgbm.LgbmModel` trained + calibrated (isotonic).
- Run is logged to MLflow with config, metrics, model artifact.

### Phase 3 — Evaluation report (PatchPilot vs EPSS)

**Acceptance:** `make eval` writes `docs/benchmarks/REPORT.md` with **real
numeric** AUC-PR, AUC-ROC, P@K, Brier, and ECE for both PatchPilot and EPSS:

```
make eval
test -s docs/benchmarks/REPORT.md
```

Scope:
- `patchpilot.eval.metrics` returns real numbers (no NaN).
- `patchpilot.eval.compare_epss.write_report` populates the table in
  `docs/benchmarks/REPORT.md` between the markers; no placeholder dashes.

### Phase 4 — Serving + demo

**Acceptance:**

```
make serve &
curl -X POST http://localhost:8000/score \
     -H 'content-type: application/json' \
     -d '{"cve_ids":["CVE-2024-1234"]}'        # 200 with real JSON
curl -X POST http://localhost:8000/rank \
     -H 'content-type: application/json' \
     -d @sample_sbom.json                       # 200 with real JSON
make demo                                       # Streamlit on :8501 loads
```

Scope:
- `patchpilot.serve.api` loads the latest MLflow model.
- `patchpilot.serve.sbom.parse_cyclonedx` + `cves_for_components`.
- Streamlit demo uploads SBOM and renders ranked list.
- `tests/test_sbom_parser.py` passes.

### Phase 5 — End-to-end + CI

**Acceptance, on a fresh clone:**

```
make up && make ingest && make train && make eval
```

succeeds, and `.github/workflows/ci.yml` is green on `main`.

---

## 2. Stretch list (Phase 6) — only after 1–5 green

- Conformal prediction intervals on probabilities.
- SHAP explanations served alongside `/score` responses.
- Evidently drift dashboards over silver/gold parquet.
- ExploitDB ingestion as a second positive-label signal.
- GHSA ingestion as a feature input.
- DistilBERT embeddings on CVE descriptions.
- Daily retrain flow via Prefect.

---

## 3. Do-Not-Build list (out of scope for this project)

- Next.js or any non-Streamlit frontend.
- Grafana dashboards.
- Prometheus exporters.
- OpenTelemetry instrumentation.
- Postgres MLflow backend (we use the local file backend at `.mlruns`).
- Mocked or fabricated CSVs committed to the repo.

---

## 4. Schema contract — `data/silver/cve_master.parquet`

This is the only authoritative schema. Every later phase consumes it.

| # | column | dtype | nullable | constraint |
|---|--------|-------|----------|------------|
| 1 | `cve_id`               | `string`               | no  | primary key, regex `^CVE-\d{4}-\d{4,}$` |
| 2 | `published_date`       | `date32`               | no  | UTC date |
| 3 | `last_modified_date`   | `date32`               | no  | `>= published_date` |
| 4 | `cvss_v3_base_score`   | `float32`              | yes | in [0.0, 10.0] |
| 5 | `cvss_v3_severity`     | `string`               | yes | in {LOW, MEDIUM, HIGH, CRITICAL} |
| 6 | `cvss_v3_vector`       | `string`               | yes | CVSS v3.x vector string |
| 7 | `cwe_ids`              | `list<string>`         | yes | each item matches `^CWE-\d+$` |
| 8 | `vendor_count`         | `int32`                | no  | >= 0 |
| 9 | `product_count`        | `int32`                | no  | >= 0 |
| 10 | `description_len`     | `int32`                | no  | >= 0 |
| 11 | `ref_has_exploit`     | `bool`                 | no  | any reference tagged `Exploit` |
| 12 | `ref_has_patch`       | `bool`                 | no  | any reference tagged `Patch` |
| 13 | `epss_score`          | `float32`              | yes | in [0.0, 1.0] (EPSS snapshot used) |
| 14 | `epss_percentile`     | `float32`              | yes | in [0.0, 1.0] |
| 15 | `epss_snapshot_date`  | `date32`               | yes | snapshot used for `epss_score` |
| 16 | `in_kev`              | `bool`                 | no  | from CISA KEV catalog |
| 17 | `kev_date_added`      | `date32`               | yes | non-null iff `in_kev` |
| 18 | `exploited_30d`       | `bool`                 | no  | **LABEL** |

### Exact label definition

```
exploited_30d(cve) := (cve.cve_id ∈ CISA_KEV)
                     ∧ (KEV.date_added <= cve.published_date + 30 days)
```

### Right-censoring rule (train/eval only)

Rows with `published_date > today_utc - 30 days` are **excluded** from
training and evaluation, because their 30-day exploitation window has not
yet closed. They are still included in scoring/serving inputs.

---

## 5. API contract — FastAPI service

Pydantic v2 models live in `src/patchpilot/serve/schemas.py`. The
contract below is binding.

### `POST /score`

Request:

```json
{ "cve_ids": ["CVE-2024-1234", "CVE-2023-9999"] }
```

Constraints: `1 <= len(cve_ids) <= 1000`. Extra fields rejected.

Response (200):

```json
{
  "model_version": "lgbm@v0.1.0",
  "scored_at": "2026-05-16T00:00:00Z",
  "results": [
    {
      "cve_id": "CVE-2024-1234",
      "probability": 0.87,
      "percentile": 0.991,
      "in_kev": false
    }
  ]
}
```

`probability ∈ [0,1]`, `percentile ∈ [0,1]`. Unknown CVE ids → return
`probability=0.0, percentile=0.0, in_kev=false`.

### `POST /rank`

Request: CycloneDX 1.5 JSON SBOM under key `sbom`.

```json
{ "sbom": { "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [...] } }
```

Response (200):

```json
{
  "model_version": "lgbm@v0.1.0",
  "ranked_at": "2026-05-16T00:00:00Z",
  "items": [
    {
      "rank": 1,
      "cve_id": "CVE-2024-1234",
      "purl": "pkg:pypi/foo@1.2.3",
      "probability": 0.87,
      "percentile": 0.991,
      "cvss_v3_base_score": 9.8,
      "in_kev": true
    }
  ]
}
```

Items are sorted by `probability` descending; ties broken by
`cvss_v3_base_score` descending, then `cve_id` ascending. `rank` is dense
1-based. Non-CycloneDX inputs → HTTP 422.

### `GET /healthz`

```json
{ "status": "ok", "model_version": "lgbm@v0.1.0" }
```

`model_version` is `null` until Phase 4 loads a real model.

---

## 6. CLI contract — `patchpilot` typer app

```
patchpilot ingest [--source nvd|epss|kev|all] [--since YYYY-MM-DD]
                  [--out-dir data/bronze]                                 # Phase 1
patchpilot train  [--config config/settings.toml]                        # Phase 2
patchpilot eval   [--model-uri runs:/<id>/model]
                  [--report docs/benchmarks/REPORT.md]                   # Phase 3
patchpilot serve  [--host 0.0.0.0] [--port 8000]                         # Phase 4 (Phase 0 wires uvicorn)
```

All commands exit with code 2 and a "`Phase N not yet implemented`" stderr
message until their implementing phase lands. The exception is `serve`,
which starts uvicorn immediately so the API container is exercisable in
Phase 0.

---

## 7. Phase 0 acceptance (already verified in this run)

```
pip install uv && uv python install 3.11
uv sync
uv run ruff check .
uv run mypy src/patchpilot
uv run pytest -q
docker compose build
```

All six must pass before any Phase 1 work begins.
