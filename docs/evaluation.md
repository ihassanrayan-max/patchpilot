# Evaluation

## Metrics (both models reported)

- **AUC-PR** — primary ranking metric under heavy class imbalance.
- **AUC-ROC** — secondary ranking metric.
- **P@K** — precision among the top-K (`config.eval.top_k`, default 100).
- **Brier score** — calibration + sharpness.
- **ECE** — expected calibration error (10 equal-width bins).

## Comparison protocol

1. Pick a held-out time window strictly after the last training fold.
2. Score both PatchPilot and EPSS on the same CVE set.
3. `patchpilot.eval.compare_epss.write_report` writes
   `docs/benchmarks/REPORT.md` with the table headers defined in
   `docs/benchmarks/REPORT.md` filled in with real numbers.

## CI gate

`.github/workflows/eval-vs-epss.yml` runs the report and fails if PatchPilot
underperforms EPSS on AUC-PR by more than the configured margin (Phase 3
sets this margin).
