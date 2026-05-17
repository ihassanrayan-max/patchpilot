"""Daily ingestion orchestrator.

We do not depend on a Prefect runtime: it is heavy, slow to import, and the
job we run is a deterministic, idempotent sequence of three downloads
followed by a silver join. A plain function gives us the same correctness
with zero extra cold-start cost. The signature still matches the Phase 1
contract so a Prefect ``@flow`` decorator can be re-added later without
changing call sites.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from loguru import logger

from patchpilot.ingest.epss import ingest_epss
from patchpilot.ingest.kev import ingest_kev
from patchpilot.ingest.nvd import ingest_nvd
from patchpilot.ingest.silver import build_silver
from patchpilot.validate.expectations import validate_cve_master


def daily_ingest_flow(
    target_date: date,
    data_dir: Path,
    *,
    nvd_since: date | None = None,
    nvd_max_records: int = 2000,
    cache_dir: Path | None = None,
    sources: tuple[str, ...] = ("nvd", "epss", "kev"),
    skip_silver: bool = False,
) -> dict[str, Path | bool | None]:
    """Run the daily ingestion flow for ``target_date``.

    Returns a dict of artifact paths and the validation status. Idempotent
    on ``(target_date, data_dir, nvd_since)``.
    """
    data_dir = Path(data_dir)
    bronze = data_dir / "bronze"
    silver_path = data_dir / "silver" / "cve_master.parquet"
    cache_dir = Path(cache_dir) if cache_dir is not None else None

    results: dict[str, Path | bool | None] = {
        "nvd": None,
        "kev": None,
        "epss": None,
        "silver": None,
        "validated": None,
    }

    if "nvd" in sources:
        since = nvd_since or (target_date - timedelta(days=365))
        logger.info("ingesting NVD since {}", since)
        results["nvd"] = ingest_nvd(
            since,
            bronze / "nvd",
            max_records=nvd_max_records,
            cache_dir=cache_dir / "nvd" if cache_dir else None,
        )

    if "kev" in sources:
        logger.info("ingesting CISA KEV catalog")
        results["kev"] = ingest_kev(
            bronze / "kev",
            cache_dir=cache_dir / "kev" if cache_dir else None,
        )

    if "epss" in sources:
        snap = target_date - timedelta(days=1)
        logger.info("ingesting EPSS snapshot {}", snap)
        try:
            results["epss"] = ingest_epss(
                snap,
                bronze / "epss",
                cache_dir=cache_dir / "epss" if cache_dir else None,
            )
        except Exception as exc:
            logger.warning("EPSS snapshot {} failed ({}); trying previous day", snap, exc)
            results["epss"] = ingest_epss(
                snap - timedelta(days=1),
                bronze / "epss",
                cache_dir=cache_dir / "epss" if cache_dir else None,
            )

    if not skip_silver and (bronze / "nvd").exists() and (bronze / "kev").exists():
        logger.info("building silver cve_master at {}", silver_path)
        results["silver"] = build_silver(bronze, silver_path)
        results["validated"] = validate_cve_master(silver_path)
        logger.info("silver validation passed={}", results["validated"])

    return results


def cli_entry(
    data_dir: Path,
    *,
    sources: tuple[str, ...] = ("nvd", "epss", "kev"),
    nvd_since: date | None = None,
    nvd_max_records: int = 2000,
    cache_dir: Path | None = None,
    skip_silver: bool = False,
) -> dict[str, Path | bool | None]:
    """Convenience wrapper used by ``patchpilot ingest``."""
    return daily_ingest_flow(
        target_date=datetime.now(UTC).date(),
        data_dir=data_dir,
        nvd_since=nvd_since,
        nvd_max_records=nvd_max_records,
        cache_dir=cache_dir,
        sources=sources,
        skip_silver=skip_silver,
    )
