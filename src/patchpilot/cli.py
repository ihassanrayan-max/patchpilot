"""Typer-based ``patchpilot`` command-line entry point.

Phase 0 wires sub-commands ``ingest``, ``train``, ``eval``, and ``serve`` that
exit with a clear ``Phase N`` message until their implementing phase lands.
The Makefile invokes these commands; Dockerfiles use them as ``CMD``.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated

import typer

app: typer.Typer = typer.Typer(
    name="patchpilot",
    help="PatchPilot CLI: ingest, train, eval, serve.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command("ingest")
def ingest_cmd(
    source: Annotated[
        str,
        typer.Option(help="One of: nvd, epss, kev, all."),
    ] = "all",
    since: Annotated[
        str | None,
        typer.Option(help="Earliest publishedDate (YYYY-MM-DD) for NVD ingestion."),
    ] = None,
    config: Annotated[
        Path,
        typer.Option(help="Path to settings TOML (default NVD since from [ingest].)."),
    ] = Path("config/settings.toml"),
    out_dir: Annotated[
        Path,
        typer.Option(help="Bronze output directory."),
    ] = Path("data/bronze"),
    nvd_max_records: Annotated[
        int,
        typer.Option(help="Maximum NVD records to pull."),
    ] = 50000,
    cache_dir: Annotated[
        Path | None,
        typer.Option(help="Optional cache dir for raw API payloads (reproducible)."),
    ] = None,
    skip_silver: Annotated[
        bool,
        typer.Option(help="Only refresh bronze; skip the silver join."),
    ] = False,
) -> None:
    """Run bronze ingestion from NVD / EPSS / KEV and rebuild the silver join."""
    import tomllib
    from datetime import datetime as _dt

    from patchpilot.flows.daily_ingest import cli_entry

    source = source.lower()
    if source == "all":
        sources: tuple[str, ...] = ("nvd", "epss", "kev")
    elif source in {"nvd", "epss", "kev"}:
        sources = (source,)
    else:
        typer.echo(f"unknown source '{source}', expected one of nvd|epss|kev|all", err=True)
        raise typer.Exit(code=2)

    parsed_since: date | None = None
    if since is not None:
        try:
            parsed_since = _dt.strptime(since, "%Y-%m-%d").date()
        except ValueError as exc:
            typer.echo(f"--since must be YYYY-MM-DD ({exc})", err=True)
            raise typer.Exit(code=2) from exc
    elif "nvd" in sources:
        cfg_path = Path(config)
        if not cfg_path.is_file():
            typer.echo(f"config file missing at {cfg_path}; pass --since or fix path", err=True)
            raise typer.Exit(code=2)
        with cfg_path.open("rb") as fh:
            cfg = tomllib.load(fh)
        raw_since = (cfg.get("ingest") or {}).get("nvd_since")
        if not isinstance(raw_since, str):
            typer.echo("[ingest].nvd_since missing from settings TOML", err=True)
            raise typer.Exit(code=2)
        try:
            parsed_since = _dt.strptime(raw_since, "%Y-%m-%d").date()
        except ValueError as exc:
            typer.echo(f"[ingest].nvd_since must be YYYY-MM-DD ({exc})", err=True)
            raise typer.Exit(code=2) from exc

    data_dir = out_dir.parent if out_dir.name == "bronze" else Path("data")
    results = cli_entry(
        data_dir=data_dir,
        sources=sources,
        nvd_since=parsed_since,
        nvd_max_records=nvd_max_records,
        cache_dir=cache_dir,
        skip_silver=skip_silver,
    )
    for name, value in results.items():
        typer.echo(f"{name}: {value}")


@app.command("train")
def train_cmd(
    config: Annotated[
        Path,
        typer.Option(help="Path to settings TOML."),
    ] = Path("config/settings.toml"),
) -> None:
    """Train the LightGBM challenger; persist artifact + metadata under .mlruns/."""
    from patchpilot.train.train import train_lgbm

    run_id = train_lgbm(config)
    typer.echo(f"trained run_id={run_id}")


@app.command("eval")
def eval_cmd(
    model_uri: Annotated[
        str,
        typer.Option(help="Model URI to evaluate. Defaults to latest local artifact."),
    ] = "latest",
    report: Annotated[
        Path,
        typer.Option(help="Markdown report output path."),
    ] = Path("docs/benchmarks/REPORT.md"),
) -> None:
    """Evaluate PatchPilot vs EPSS and write the benchmark report."""
    from patchpilot.eval.compare_epss import write_report

    out = write_report(model_uri=model_uri, report_path=report)
    typer.echo(f"wrote report to {out}")


@app.command("serve")
def serve_cmd(
    host: Annotated[str, typer.Option(help="Bind host.")] = "0.0.0.0",  # noqa: S104
    port: Annotated[int, typer.Option(help="Bind port.")] = 8000,
) -> None:
    """Start the FastAPI service via uvicorn. Phase 4 wires a real model."""
    import uvicorn

    uvicorn.run("patchpilot.serve.api:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
