# Evaluation

## Metrics (both models reported)

- **AUC-PR** — primary ranking metric under heavy class imbalance.
- **AUC-ROC** — secondary ranking metric.
- **P@K** — precision among the top-K (`config.eval.top_k`, default 100).
- **Brier score** — calibration + sharpness.
- **ECE** — expected calibration error (10 equal-width bins).

## Comparison protocol

1. Apply the 30-day right-censoring rule so labels are observable.
2. Select the most recent rolling closed-window holdout that meets
   `[eval].min_holdout_rows` and `[eval].min_holdout_positives`
   (default: last 90 days, at least 50 rows and 1 positive).
3. Train on all older right-censored rows; score both PatchPilot and EPSS on
   the same holdout slice.
4. `patchpilot.eval.compare_epss.write_report` writes
   `docs/benchmarks/REPORT.md` and syncs the README benchmark table.

## CI gate

`.github/workflows/eval-vs-epss.yml` runs the report and fails if PatchPilot
underperforms EPSS on AUC-PR by more than the configured margin (Phase 3
sets this margin).
