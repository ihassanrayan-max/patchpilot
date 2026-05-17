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
    out_dir: Annotated[
        Path,
        typer.Option(help="Bronze output directory."),
    ] = Path("data/bronze"),
) -> None:
    """Run bronze ingestion from NVD / EPSS / KEV. Phase 1 implementation."""
    _ = source, since, out_dir, date
    typer.echo("patchpilot ingest: Phase 1 not yet implemented", err=True)
    raise typer.Exit(code=2)


@app.command("train")
def train_cmd(
    config: Annotated[
        Path,
        typer.Option(help="Path to settings TOML."),
    ] = Path("config/settings.toml"),
) -> None:
    """Train the LightGBM challenger and log to MLflow. Phase 2 implementation."""
    _ = config
    typer.echo("patchpilot train: Phase 2 not yet implemented", err=True)
    raise typer.Exit(code=2)


@app.command("eval")
def eval_cmd(
    model_uri: Annotated[
        str,
        typer.Option(help="MLflow model URI to evaluate, e.g. runs:/<id>/model."),
    ] = "runs:/latest/model",
    report: Annotated[
        Path,
        typer.Option(help="Markdown report output path."),
    ] = Path("docs/benchmarks/REPORT.md"),
) -> None:
    """Evaluate PatchPilot vs EPSS and write the benchmark report. Phase 3."""
    _ = model_uri, report
    typer.echo("patchpilot eval: Phase 3 not yet implemented", err=True)
    raise typer.Exit(code=2)


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
