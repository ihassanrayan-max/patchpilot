# Architecture

```mermaid
flowchart LR
    NVD[NVD JSON feeds] --> Ingest
    EPSS[FIRST EPSS daily CSV] --> Ingest
    KEV[CISA KEV catalog] --> Ingest
    Ingest[ingest/*] --> Bronze[(data/bronze/*.parquet)]
    Bronze --> Validate[validate/*]
    Validate --> Silver[(data/silver/cve_master.parquet)]
    Silver --> Features[features/*]
    Features --> Gold[(data/gold/*.parquet)]
    Gold --> Train[train.train_lgbm]
    Train --> MLflow[(.mlruns/)]
    MLflow --> Eval[eval.compare_epss]
    MLflow --> Serve[serve.api FastAPI]
    Serve --> Demo[apps/demo Streamlit]
    Eval --> Report[docs/benchmarks/REPORT.md]
```

## Layers

- **Bronze** — raw, append-only Parquet from NVD/EPSS/KEV.
- **Silver** — `data/silver/cve_master.parquet` (the schema contract; see `PLAN.md`).
- **Gold** — feature matrices for training/eval.
- **Registry** — MLflow file backend at `.mlruns`.
- **Serve** — FastAPI app exposing `/score`, `/rank`, `/healthz`.
- **Demo** — Streamlit app that uploads an SBOM and calls `/rank`.

Details for each phase land in `PLAN.md`.
