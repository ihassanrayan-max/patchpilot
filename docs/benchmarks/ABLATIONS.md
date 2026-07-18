# PatchPilot Ablations

_Generated: 2026-07-18T02:46:16.158307+00:00_

**Status:** ok

## Holdout window

- start: 2023-11-08
- end: 2024-01-06
- n rows: 60
- n positives: 4

## Variants

| Variant | AUC-PR | AUC-ROC | P@10 | Brier |
| ------- | ------ | ------- | ----- | ----- |
| EPSS-only baseline | 1.0000 | 1.0000 | 0.4000 | 0.0107 |
| Full LightGBM | 1.0000 | 1.0000 | 0.4000 | 0.0000 |
| LightGBM no-EPSS features | 0.0868 | 0.5000 | 0.1000 | 0.0624 |

## Interpretation guide

- If **EPSS-only** dominates AUC-PR, PatchPilot is not yet a standalone challenger.
- If **no-EPSS** is near chance but **full** approaches EPSS, the model is largely an EPSS residual/reranker — say so honestly.
- If **no-EPSS** beats EPSS, non-EPSS signals are carrying value.

## Notes

- none
