"""Build a tiny offline PatchPilot dataset for fixture e2e tests.

Creates bronze NVD/KEV/EPSS parquet files and a silver ``cve_master.parquet``
under a caller-provided root. No network I/O.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import polars as pl
import pyarrow.parquet as pq

from patchpilot.ingest.silver import build_cve_master, write_cve_master
from patchpilot.validate.schemas import epss_schema, kev_schema, nvd_bronze_schema


def build_fixture_tree(
    root: Path,
    *,
    n_days: int = 220,
    start: date = date(2023, 6, 1),
    positive_every: int = 18,
) -> dict[str, Path]:
    """Materialise bronze + silver under ``root/data`` and return key paths."""
    root = Path(root)
    data_dir = root / "data"
    bronze = data_dir / "bronze"
    silver_dir = data_dir / "silver"
    nvd_dir = bronze / "nvd"
    kev_dir = bronze / "kev"
    epss_dir = bronze / "epss"
    for path in (nvd_dir, kev_dir, epss_dir, silver_dir):
        path.mkdir(parents=True, exist_ok=True)

    nvd_rows: list[dict[str, object]] = []
    kev_rows: list[dict[str, object]] = []
    epss_rows: list[dict[str, object]] = []

    for offset in range(n_days):
        pub = start + timedelta(days=offset)
        cve_id = f"CVE-2023-{offset + 1:04d}"
        positive = offset % positive_every == 0
        product = "openssl" if offset % 3 == 0 else "libxml2"
        version = "3.0.0" if product == "openssl" else "2.9.10"
        nvd_rows.append(
            {
                "cve_id": cve_id,
                "published_date": pub,
                "last_modified_date": pub + timedelta(days=1),
                "cvss_v3_base_score": 7.5 if not positive else 9.8,
                "cvss_v3_severity": "HIGH" if not positive else "CRITICAL",
                "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe_ids": ["CWE-79"] if offset % 2 == 0 else ["CWE-22"],
                "vendor_count": 1,
                "product_count": 1,
                "description": f"Fixture vulnerability for {product}",
                "description_len": 40,
                "ref_has_exploit": positive,
                "ref_has_patch": True,
                "vendors": ["fixture"],
                "products": [product],
                "versions": [version],
            }
        )
        if positive:
            kev_rows.append(
                {
                    "cve_id": cve_id,
                    "vendor_project": "fixture",
                    "product": product,
                    "vulnerability_name": f"Fixture {cve_id}",
                    "date_added": pub + timedelta(days=5),
                    "short_description": "fixture",
                    "required_action": "patch",
                    "due_date": pub + timedelta(days=30),
                    "known_ransomware_campaign_use": "Unknown",
                    "notes": None,
                }
            )
        epss_rows.append(
            {
                "cve_id": cve_id,
                "epss_score": 0.85 if positive else 0.05 + (offset % 10) * 0.01,
                "epss_percentile": 0.95 if positive else 0.20 + (offset % 10) * 0.02,
                "snapshot_date": pub,
            }
        )

    nvd = pl.DataFrame(nvd_rows)
    kev = pl.DataFrame(kev_rows) if kev_rows else pl.DataFrame(
        schema={
            "cve_id": pl.Utf8,
            "vendor_project": pl.Utf8,
            "product": pl.Utf8,
            "vulnerability_name": pl.Utf8,
            "date_added": pl.Date,
            "short_description": pl.Utf8,
            "required_action": pl.Utf8,
            "due_date": pl.Date,
            "known_ransomware_campaign_use": pl.Utf8,
            "notes": pl.Utf8,
        }
    )
    epss = pl.DataFrame(epss_rows)

    nvd_path = nvd_dir / f"{start.isoformat()}.parquet"
    kev_path = kev_dir / "kev.parquet"
    epss_path = epss_dir / f"{start.isoformat()}.parquet"
    pq.write_table(nvd.to_arrow().cast(nvd_bronze_schema()), nvd_path, compression="zstd")
    pq.write_table(kev.to_arrow().cast(kev_schema()), kev_path, compression="zstd")
    pq.write_table(epss.to_arrow().cast(epss_schema()), epss_path, compression="zstd")

    master = build_cve_master(nvd, kev, epss)
    silver_path = silver_dir / "cve_master.parquet"
    write_cve_master(master, silver_path)

    return {
        "data_dir": data_dir,
        "bronze_dir": bronze,
        "nvd": nvd_path,
        "kev": kev_path,
        "epss": epss_path,
        "silver": silver_path,
    }


def write_fixture_settings(root: Path, *, holdout_days: int = 60) -> Path:
    """Write a settings.toml rooted at ``root`` for offline train/eval."""
    root = Path(root)
    config_path = root / "settings.toml"
    config_path.write_text(
        f"""
[paths]
data_dir = "data"
bronze_dir = "data/bronze"
silver_dir = "data/silver"
gold_dir = "data/gold"
mlruns_dir = ".mlruns"
reports_dir = "docs/benchmarks"

[features]
include_tabular = true
include_temporal = true
include_graph = false

[train]
n_splits = 2
embargo_days = 30
seed = 42

[train.lgbm]
objective = "binary"
learning_rate = 0.1
num_leaves = 15
min_data_in_leaf = 20
n_estimators = 50

[eval]
top_k = 10
holdout_days = {holdout_days}
min_holdout_rows = 40
min_holdout_positives = 1
min_holdout_days = 14
auc_pr_margin = 1.0
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config_path
