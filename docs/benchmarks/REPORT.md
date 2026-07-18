# PatchPilot vs EPSS - Benchmark Report

_Generated: 2026-07-18T03:08:21.041872+00:00_

**Status:** ok - metrics computed.

Model artifact: `C:\Users\hassan\AppData\Local\Temp\patchpilot-ablate-30tbpkj9\.mlruns\run-877468c130-20260718T030819\model.pkl`  
Model version: `lgbm@v0.1.0`  
Trained at: `2026-07-18T03:08:19.851856+00:00`  
Features: 18

## Dataset windows

| Field | Value |
| ----- | ----- |
| closed rows (after censoring) | 220 |
| closed publication range | 2023-06-01 .. 2024-01-06 |
| train publication range | 2023-06-01 .. 2023-11-07 |
| eval publication range | 2023-11-08 .. 2024-01-06 |
| eval window length | 60 days |
| eval rows | 60 |
| eval positives | 4 |
| eval positive rate | 0.0667 |

## Right-censoring rule

Rows with `published_date > today_utc - 30 days` are excluded because their 30-day exploitation label window has not closed.

## Headline metrics

| Model | AUC-PR | AUC-ROC | P@10 | Brier | ECE |
| ----- | ------ | ------- | ----- | ----- | --- |
| PatchPilot | 1.0000 | 1.0000 | 0.4000 | 0.0044 | 0.0341 |
| EPSS | 1.0000 | 1.0000 | 0.4000 | 0.0107 | 0.0990 |

## Notes

PatchPilot scores come from the latest trained artifact (EPSS-complement: `clamp01(epss + residual)` when the strategy is active); EPSS scores come from the same point-in-time `f_epss_score` feature used at training time (not a live/current lookup), so the comparison is a fair head-to-head. Both models are scored on the same rolling closed-window holdout selected by `select_eval_holdout` (most recent right-censored slice meeting configured minimums). The label is `exploited_30d` per `PLAN.md`. Training excludes this slice; see `heldout_content_sha256` in `.mlruns/<run_id>/metadata.json`.

**Evaluation integrity:** EPSS-complement strategy active: PatchPilot = clamp01(EPSS + residual). Lift over EPSS on this holdout is delta-AUC-PR = +0.0000 (at or below the EPSS-only baseline).
