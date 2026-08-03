# PatchPilot vs EPSS - Benchmark Report

_Generated: 2026-08-03T11:38:05.293293+00:00_

**Status:** ok - metrics computed.

Model artifact: `/home/runner/work/patchpilot/patchpilot/.mlruns/run-eb8a238829-20260803T113801/model.pkl`  
Model version: `lgbm@v0.1.0`  
Trained at: `2026-08-03T11:38:01.910191+00:00`  
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
| PatchPilot | 0.0161 | 0.7970 | 0.0100 | 0.0025 | 0.0002 |
| EPSS | 0.0025 | 0.5000 | 0.0000 | 0.0025 | 0.0025 |

## Notes

PatchPilot scores come from the latest trained artifact (EPSS-complement: `clamp01(epss + residual)` when the strategy is active); EPSS scores come from the same point-in-time `f_epss_score` feature used at training time (not a live/current lookup), so the comparison is a fair head-to-head. Both models are scored on the same rolling closed-window holdout selected by `select_eval_holdout` (most recent right-censored slice meeting configured minimums). The label is `exploited_30d` per `PLAN.md`. Training excludes this slice; see `heldout_content_sha256` in `.mlruns/<run_id>/metadata.json`.

**Evaluation integrity:** EPSS-complement strategy active: PatchPilot = clamp01(EPSS + residual). Lift over EPSS on this holdout is delta-AUC-PR = +0.0135 (above the EPSS-only baseline).
