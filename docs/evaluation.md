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
3. Train on older right-censored rows (when enough history exists);
   score both PatchPilot and EPSS on the same holdout slice.
4. `patchpilot.eval.compare_epss.write_report` writes
   `docs/benchmarks/REPORT.md` and syncs the README benchmark table.
   When metrics cannot be computed, both files show `n/a` with a reason —
   never fabricated numbers.

## Point-in-time scoring for the challenger

PatchPilot holdout scores use the same point-in-time feature assembly as
training (`assemble_training_frame`). The EPSS baseline uses the EPSS
columns on silver (`EpssBaseline.from_silver`) for the comparison protocol.

## CI gates

- **PR CI** (`.github/workflows/ci.yml`): unit tests + fixture e2e
  (`make test-e2e`). No live NVD required.
- **Weekly live eval** (`.github/workflows/eval-vs-epss.yml`): ingest /
  train / eval on live feeds; fails if the report is unavailable or if
  EPSS AUC-PR exceeds PatchPilot by more than `[eval].auc_pr_margin`.

## Ablations

`make ablate` writes `docs/benchmarks/ABLATIONS.md` comparing full /
no-EPSS / EPSS-only variants on the same holdout.
