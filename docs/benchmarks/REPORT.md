# PatchPilot vs EPSS - Benchmark Report

_Generated: 2026-06-01T13:34:18.725888+00:00_

**Status:** ok - metrics computed.

Model artifact: `.mlruns/run-0abab5c1af-20260601T133414/model.pkl`  
Model version: `lgbm@v0.1.0`  
Trained at: `2026-06-01T13:34:14.569112+00:00`  
Features: 18

## Dataset windows

| Field | Value |
| ----- | ----- |
| closed rows (after censoring) | 50000 |
| closed publication range | 2024-01-01 .. 2025-03-10 |
| train publication range | 2024-01-01 .. 2024-12-10 |
| eval publication range | 2024-12-11 .. 2025-03-10 |
| eval window length | 90 days |
| eval rows | 11447 |
| eval positives | 29 |
| eval positive rate | 0.0025 |

## Right-censoring rule

Rows with `published_date > today_utc - 30 days` are excluded because their 30-day exploitation label window has not closed.

## Headline metrics

| Model | AUC-PR | AUC-ROC | P@100 | Brier | ECE |
| ----- | ------ | ------- | ----- | ----- | --- |
| PatchPilot | 0.0146 | 0.8610 | 0.0300 | 0.0025 | 0.0018 |
| EPSS | 0.3484 | 0.9893 | 0.1400 | 0.0059 | 0.0112 |

## Notes

PatchPilot scores come from the latest LightGBM run; EPSS scores come from the EPSS column of `cve_master.parquet`. Both models are scored on the same rolling closed-window holdout selected by `select_eval_holdout` (most recent right-censored slice meeting configured minimums). The label is `exploited_30d` per `PLAN.md`. Training excludes this slice; see `heldout_content_sha256` in `.mlruns/<run_id>/metadata.json`.
