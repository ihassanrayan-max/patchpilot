# PatchPilot vs EPSS - Benchmark Report

_Generated: 2026-05-24T00:24:44.622966+00:00_

**Status:** ok - metrics computed.

Model artifact: `.mlruns\run-2d5766d9f9-20260524T002442\model.pkl`  
Model version: `lgbm@v0.1.0`  
Trained at: `2026-05-24T00:24:42.022113+00:00`  
Features: 18

## Dataset windows

| Field | Value |
| ----- | ----- |
| closed rows (after censoring) | 8000 |
| closed publication range | 2023-01-01 .. 2023-04-04 |
| train publication range | 2023-01-01 .. 2023-01-04 |
| eval publication range | 2023-01-05 .. 2023-04-04 |
| eval window length | 90 days |
| eval rows | 7692 |
| eval positives | 19 |
| eval positive rate | 0.0025 |

## Right-censoring rule

Rows with `published_date > today_utc - 30 days` are excluded because their 30-day exploitation label window has not closed.

## Headline metrics

| Model | AUC-PR | AUC-ROC | P@100 | Brier | ECE |
| ----- | ------ | ------- | ----- | ----- | --- |
| PatchPilot | 0.0118 | 0.6367 | 0.0500 | 0.0024 | 0.0007 |
| EPSS | 0.3174 | 0.9014 | 0.1000 | 0.0130 | 0.0232 |

## Notes

PatchPilot scores come from the latest LightGBM run; EPSS scores come from the EPSS column of `cve_master.parquet`. Both models are scored on the same rolling closed-window holdout selected by `select_eval_holdout` (most recent right-censored slice meeting configured minimums). The label is `exploited_30d` per `PLAN.md`. Training excludes this slice; see `heldout_content_sha256` in `.mlruns/<run_id>/metadata.json`.
