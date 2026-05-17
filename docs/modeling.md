# Modeling

## Task

Binary classification: predict `exploited_30d` (see `PLAN.md` for label).

## Baseline

EPSS daily score, exposed as a `predict_proba` adapter so it shares the
evaluation harness with the challenger.

## Challenger

LightGBM binary classifier (`patchpilot.models.lgbm.LgbmModel`), fit with
time-respecting cross-validation (`patchpilot.train.temporal_cv`) and
calibrated with isotonic regression on the held-out validation fold
(`patchpilot.train.calibration`).

## Anti-leakage rules

- Features computed strictly at `as_of` — no information after the
  validation-fold start date may enter training features.
- Embargo between train end and validation start ≥ `horizon_days` (30).
- Right-censored window: CVEs published in the last 30 days are excluded
  from both train and eval (their 30-day window is not complete).
