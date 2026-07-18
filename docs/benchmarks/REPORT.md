# PatchPilot vs EPSS - Benchmark Report

_Generated: 2026-07-18T03:17:38.784502+00:00_

**Status:** ok - metrics computed.

Model artifact: `C:\Users\hassan\Downloads\PatchPilot\.mlruns\run-825fb9cf6e-20260718T031726\model.pkl`  
Model version: `lgbm@v0.1.0`  
Trained at: `2026-07-18T03:17:26.834613+00:00`  
Features: 18

## Dataset windows

| Field | Value |
| ----- | ----- |
| closed rows (after censoring) | 220 |
| closed publication range | 2023-06-01 .. 2024-01-06 |
| train publication range | 2023-06-01 .. 2023-10-08 |
| eval publication range | 2023-10-09 .. 2024-01-06 |
| eval window length | 90 days |
| eval rows | 90 |
| eval positives | 5 |
| eval positive rate | 0.0556 |

## Right-censoring rule

Rows with `published_date > today_utc - 30 days` are excluded because their 30-day exploitation label window has not closed.

## Headline metrics

| Model | AUC-PR | AUC-ROC | P@100 | Brier | ECE |
| ----- | ------ | ------- | ----- | ----- | --- |
| PatchPilot | 1.0000 | 1.0000 | 0.0556 | 0.0038 | 0.0322 |
| EPSS | 1.0000 | 1.0000 | 0.0556 | 0.0106 | 0.0983 |

## Notes

PatchPilot scores come from the latest trained artifact (EPSS-complement: `clamp01(epss + residual)` when the strategy is active); EPSS scores come from the same point-in-time `f_epss_score` feature used at training time (not a live/current lookup), so the comparison is a fair head-to-head. Both models are scored on the same rolling closed-window holdout selected by `select_eval_holdout` (most recent right-censored slice meeting configured minimums). The label is `exploited_30d` per `PLAN.md`. Training excludes this slice; see `heldout_content_sha256` in `.mlruns/<run_id>/metadata.json`.

**Evaluation integrity:** EPSS-complement strategy active: PatchPilot = clamp01(EPSS + residual). Lift over EPSS on this holdout is delta-AUC-PR = +0.0000 (at or below the EPSS-only baseline).
