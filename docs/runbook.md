# Runbook

## Local quickstart

```
make up        # docker compose up -d  (api on :8000, demo on :8501)
make ingest    # Phase 1
make train     # Phase 2
make eval      # Phase 3, writes docs/benchmarks/REPORT.md
```

## Common issues

- **`uv sync` fails on Windows**: ensure `uv python install 3.11` has been
  run and `python -m uv` resolves to a 0.5+ binary.
- **`docker compose build` slow**: first build downloads the base image and
  resolves the dep graph; subsequent builds are cached.
- **MLflow runs missing**: confirm `.mlruns/` is bind-mounted into the
  `trainer` and `api` services and is writable.

## Phase-by-phase exit criteria

See `PLAN.md`. Each phase has a single command in the Makefile that, when
green, marks the phase complete.
