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
    ablate: Annotated[
        bool,
        typer.Option("--ablate", help="Also write docs/benchmarks/ABLATIONS.md."),
    ] = False,
    ablations_report: Annotated[
        Path,
        typer.Option(help="Ablations Markdown output path."),
    ] = Path("docs/benchmarks/ABLATIONS.md"),
) -> None:
    """Evaluate PatchPilot vs EPSS and write the benchmark report."""
    from patchpilot.eval.compare_epss import write_report

    out = write_report(model_uri=model_uri, report_path=report)
    typer.echo(f"wrote report to {out}")
    if ablate:
        from patchpilot.eval.ablations import run_ablations

        abl = run_ablations(report_path=ablations_report)
        typer.echo(f"wrote ablations to {abl}")


@app.command("rank")
def rank_cmd(
    sbom: Annotated[
        Path,
        typer.Option("--sbom", help="Path to a CycloneDX 1.4/1.5 JSON SBOM."),
    ],
    api: Annotated[
        str | None,
        typer.Option(
            "--api",
            help="Base URL of a running PatchPilot API (POST /rank). Mutually exclusive with --local.",
        ),
    ] = None,
    local: Annotated[
        bool,
        typer.Option(
            "--local",
            help="Score in-process without a running API server (loads model/silver directly).",
        ),
    ] = False,
    mlruns_dir: Annotated[
        Path | None,
        typer.Option(help="Model artifacts dir for --local (default .mlruns or $PATCHPILOT_MLRUNS_DIR)."),
    ] = None,
    silver_path: Annotated[
        Path | None,
        typer.Option(
            help="Silver parquet for --local (default data/silver/cve_master.parquet "
            "or $PATCHPILOT_SILVER_PATH)."
        ),
    ] = None,
    bronze_nvd_dir: Annotated[
        Path | None,
        typer.Option(help="Bronze NVD dir for --local (default data/bronze/nvd or $PATCHPILOT_BRONZE_NVD_DIR)."),
    ] = None,
) -> None:
    """Rank CVEs found in a CycloneDX SBOM; write ranked JSON to stdout.

    Exactly one of ``--api`` or ``--local`` selects the scoring backend.
    When neither is given, defaults to ``--local`` so the command works
    offline right after ``uv sync`` (EPSS-only fallback if no model/silver
    are present yet).
    """
    import json as _json

    if api and local:
        typer.echo("pass only one of --api or --local, not both", err=True)
        raise typer.Exit(code=2)

    sbom_path = Path(sbom)
    if not sbom_path.is_file():
        typer.echo(f"SBOM not found at {sbom_path}", err=True)
        raise typer.Exit(code=2)
    try:
        sbom_doc = _json.loads(sbom_path.read_text(encoding="utf-8"))
    except _json.JSONDecodeError as exc:
        typer.echo(f"SBOM is not valid JSON: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if api:
        import httpx

        try:
            with httpx.Client(base_url=api, timeout=30.0) as client:
                resp = client.post("/rank", json={"sbom": sbom_doc})
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            typer.echo(f"rank request to {api} failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        typer.echo(_json.dumps(resp.json(), indent=2))
        return

    from patchpilot.serve.api import STATE, rank_sbom

    STATE.load(mlruns_dir=mlruns_dir, silver_path=silver_path, bronze_nvd_dir=bronze_nvd_dir)
    try:
        response = rank_sbom(STATE, sbom_doc)
    except ValueError as exc:
        typer.echo(f"invalid SBOM: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(_json.dumps(response.model_dump(mode="json"), indent=2))


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
