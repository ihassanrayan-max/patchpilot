# PatchPilot — Build Plan (Contract)

This document is the **schema / API / CLI contract**.
For the living execution roadmap, status ledger, and agent handoff rules, see
[`PATCHPILOT_MASTER_ROADMAP.md`](PATCHPILOT_MASTER_ROADMAP.md).

Every later phase must respect the contracts below.

---

## 1. Phases

Each phase has an acceptance command. A phase is "green" only when that
command succeeds (fixture path preferred for CI).

### Phase 1 — Ingestion + silver lake + label

**Acceptance:**

```
make ingest
uv run pytest -q tests/test_label_construction.py
```

Scope:
- `patchpilot.ingest.{nvd,epss,kev}` — download to `data/bronze/**`.
- `patchpilot.validate.{schemas,expectations}` — schema + value checks.
- Silver join lands the contract below.
- Label `exploited_30d` built from KEV.
- `patchpilot.flows.daily_ingest.daily_ingest_flow` is runnable.

### Phase 2 — Features + train + local registry

**Acceptance:**

```
make train
uv run pytest -q tests/test_temporal_cv.py tests/test_feature_leakage.py
```

Scope:
- `patchpilot.features.{tabular,temporal,graph,point_in_time}` assemble features.
- Training/eval use **point-in-time** EPSS and per-row temporal/graph anchors.
- Current KEV membership is **not** a model feature.
- `patchpilot.train.temporal_cv` enforces embargo ≥ 30 days.
- `patchpilot.models.lgbm.LgbmModel` trained + calibrated (isotonic).
- Artifacts persist under `.mlruns/<run_id>/` with `latest.json` pointer
  (local file registry; full MLflow tracking server is optional, not required).

### Phase 3 — Evaluation report (PatchPilot vs EPSS)

**Acceptance:**

```
make eval
uv run pytest -q tests/test_eval_holdout.py tests/test_eval_metrics.py
```

Scope:
- Rolling closed-window holdout via `select_eval_holdout`
  (config: `[eval].holdout_days`, `min_holdout_rows`, `min_holdout_positives`).
- `patchpilot.eval.compare_epss.write_report` writes
  `docs/benchmarks/REPORT.md` and syncs the README table
  (or writes `n/a` when metrics are unavailable — never fabricate).

### Phase 4 — Serving + demo

**Acceptance:**

```
uv run pytest -q tests/test_api.py tests/test_sbom_parser.py
make serve &
curl -X POST http://localhost:8000/score \
     -H 'content-type: application/json' \
     -d '{"cve_ids":["CVE-2024-1234"]}'
curl -X POST http://localhost:8000/rank \
     -H 'content-type: application/json' \
     -d @sample_sbom.json
```

Scope:
- `patchpilot.serve.api` loads the latest local registry model.
- `/rank` includes match metadata (`match_method`, `match_confidence`, `match_reason`).
- Streamlit demo uploads SBOM and renders ranked list.

### Phase 5 — End-to-end + CI

**Acceptance:**

```
make test-e2e
```

and `.github/workflows/ci.yml` is green on `main` (fixture path; no live NVD required).

Weekly live ingest/eval remains in `.github/workflows/eval-vs-epss.yml`.

---

## 2. Stretch list — only after Phase 5 green

- Conformal prediction intervals on probabilities.
- SHAP explanations served alongside `/score` responses.
- Evidently drift dashboards over silver/gold parquet.
- ExploitDB ingestion as a second positive-label signal.
- GHSA ingestion as a feature input.
- DistilBERT embeddings on CVE descriptions.
- Daily retrain flow via Prefect (optional; plain CLI already works).
- GitHub Action / scanner integrations (see master roadmap Phase 8).

---

## 3. Do-Not-Build list (until master roadmap allows)

- Next.js or any non-Streamlit frontend.
- Grafana dashboards / Prometheus / OpenTelemetry as vanity ops.
- Postgres MLflow backend (local `.mlruns` file registry is supported).
- Fabricated benchmark numbers committed as “real” results.
- Claiming PatchPilot beats EPSS without REPORT.md evidence.

---

## 4. Schema contract — `data/silver/cve_master.parquet`

This is the only authoritative silver schema. Every later phase consumes it.

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

### Rolling holdout (eval)

After right-censoring, evaluation uses the most recent closed window that
meets `[eval].min_holdout_rows` and `[eval].min_holdout_positives`
(default window length `[eval].holdout_days`). Training excludes that window
when enough pre-holdout rows exist.

### Point-in-time feature rules

- Training/eval EPSS features use the latest EPSS snapshot on or before
  each CVE's `published_date`.
- Temporal and graph popularity features use `as_of = published_date` per row.
- `in_kev` may appear in API responses for display; it is **not** a training feature.
- Live scoring may use current EPSS via `assemble_scoring_frame`.

---

## 5. API contract — FastAPI service

Pydantic v2 models live in `src/patchpilot/serve/schemas.py`.

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

Unknown CVE ids → `probability=0.0, percentile=0.0, in_kev=false`.
If no model is loaded, `/score` falls back to EPSS-only probabilities when silver data exists.

### `POST /rank`

Request: CycloneDX JSON SBOM under key `sbom`.

Response items include ranking fields plus match metadata:

```json
{
  "rank": 1,
  "cve_id": "CVE-2024-1234",
  "purl": "pkg:pypi/foo@1.2.3",
  "probability": 0.87,
  "percentile": 0.991,
  "cvss_v3_base_score": 9.8,
  "in_kev": true,
  "match_method": "inline_vex",
  "match_confidence": "high",
  "match_reason": "CycloneDX vulnerabilities[].id attached via affects.ref"
}
```

`match_method` is one of: `inline_vex`, `product_version_exact`, `product_name`, `unknown`.
Non-CycloneDX inputs → HTTP 422.

### `GET /healthz`

```json
{ "status": "ok", "model_version": "lgbm@v0.1.0" }
```

`model_version` is `null` when no model is loaded (degraded mode).

---

## 6. CLI contract — `patchpilot` typer app

```
patchpilot ingest [--source nvd|epss|kev|all] [--since YYYY-MM-DD]
                  [--out-dir data/bronze] [--cache-dir DIR]
patchpilot train  [--config config/settings.toml]
patchpilot eval   [--report docs/benchmarks/REPORT.md] [--ablate]
patchpilot serve  [--host 0.0.0.0] [--port 8000]
```

---

## 7. Local registry contract

Supported artifact layout:

```
.mlruns/<run_id>/model.pkl
.mlruns/<run_id>/metadata.json
.mlruns/latest.json
```

`latest.json` contains `{run_id, artifact, model_version}`.
Serving and eval load through this pointer. A hosted MLflow server is not required.

---

## 8. Phase 0 acceptance

```
pip install uv && uv python install 3.11
uv sync
uv run ruff check .
uv run mypy src/patchpilot
uv run pytest -q
docker compose build
```
