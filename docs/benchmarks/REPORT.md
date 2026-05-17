# PatchPilot vs EPSS - Benchmark Report

_Generated: 2026-05-17T04:10:40.182703+00:00_

Model artifact: `.mlruns\run-0a70f7cc82-20260517T041017\model.pkl`  
Model version: `lgbm@v0.1.0`  
Trained at: `2026-05-17T04:10:17.691808+00:00`  
Features: 22

## Held-out window

| Field | Value |
| ----- | ----- |
| start | 2023-03-20 |
| end   | 2023-04-04 |
| n CVEs | 1600 |
| positive rate | 0.0025 |

## Headline metrics

| Model       | AUC-PR | AUC-ROC | P@100 | Brier | ECE |
| ----------- | ------ | ------- | ----- | ----- | --- |
| PatchPilot  | 0.1465 | 0.7526 | 0.0300 | 0.0021 | 0.0011 |
| EPSS        | 0.4370 | 0.9651 | 0.0300 | 0.0136 | 0.0242 |

## Notes

PatchPilot scores come from the latest LightGBM run; EPSS scores come from the EPSS column of the silver `cve_master.parquet`. Both models are scored on the same right-censored tail window. The label is `exploited_30d` per the contract in `PLAN.md`.

If `n CVEs` above is in the low thousands and the positive rate is below 1%, the metrics here will be noisy and the LightGBM challenger usually underperforms EPSS because EPSS already encodes much of the signal PatchPilot has to re-learn from a sparse positive set. Re-run `patchpilot ingest --source nvd --since <earlier-date> --nvd-max-records 20000` to widen the training/eval window before drawing conclusions.
