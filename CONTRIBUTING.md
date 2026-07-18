# Contributing

Thanks for helping improve PatchPilot.

## Development setup

```bash
uv sync
make test
make test-e2e
```

See [`docs/runbook.md`](docs/runbook.md) for first-run, rollback, and CI integration.

## Pull requests

1. Branch from `main`.
2. Keep changes focused; avoid unrelated refactors.
3. Run `uv run pytest -q`, `make lint`, and `make typecheck` before opening a PR.
4. Update docs when behavior or operator workflows change.

## Scope notes

- Do not commit secrets (`.env`, API keys, private data).
- Benchmark claims must stay honest — see [`docs/benchmarks/REPORT.md`](docs/benchmarks/REPORT.md).
- File ownership during v0.1 parallel work is documented in the repo plan; avoid cross-lane edits to ML/serve scoring unless coordinating a merge wave.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
