# Data Sources

| Source | URL / contract | Cadence | Used for |
| ------ | -------------- | ------- | -------- |
| NVD CVE JSON 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` (and `https://nvd.nist.gov/feeds/json/cve/2.0/`) | Daily modified feed | CVE metadata, CVSS, CWE, CPEs, references |
| FIRST EPSS daily CSV | `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz` | Daily | Baseline benchmark; feature input |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Continuous | Label: `exploited_30d`; KEV feature |

## Phase 1 schema produced per source

- `data/bronze/nvd/<YYYY-MM>.parquet` — one row per CVE per modified-feed pull
- `data/bronze/epss/<YYYY-MM-DD>.parquet` — one row per (cve_id, snapshot_date)
- `data/bronze/kev/kev.parquet` — snapshot of the full catalog

The silver join into `data/silver/cve_master.parquet` is defined in `PLAN.md`.
