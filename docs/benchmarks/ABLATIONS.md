# PatchPilot Ablations

_Generated: 2026-07-18T03:08:20.474694+00:00_

**Status:** ok

## Holdout window

- start: 2023-11-08
- end: 2024-01-06
- n rows: 60
- n positives: 4

## Variants

| Variant | AUC-PR | AUC-ROC | P@10 | Brier |
| ------- | ------ | ------- | ----- | ----- |
| EPSS-only baseline (PIT) | 1.0000 | 1.0000 | 0.4000 | 0.0107 |
| Full LightGBM (label target) | 0.1927 | 0.8326 | 0.1000 | 0.0574 |
| LightGBM no-EPSS features | 0.0868 | 0.5000 | 0.1000 | 0.0624 |
| EPSS-complement (residual blend) | 1.0000 | 1.0000 | 0.4000 | 0.0044 |

## Interpretation guide

- If **EPSS-only** dominates AUC-PR, PatchPilot is not yet a standalone challenger.
- If **no-EPSS** is near chance but **full** approaches EPSS, the model is largely an EPSS residual/reranker — say so honestly.
- If **no-EPSS** beats EPSS, non-EPSS signals are carrying value.
- **EPSS-complement** is the strategy actually shipped in `serve/scoring.py`: `clamp01(epss + residual)`. A positive lift means the residual model adds signal on top of EPSS instead of just reproducing it.
- **EPSS-complement lift**: delta-AUC-PR (complement - EPSS-only) = +0.0000.

## Notes

- none
