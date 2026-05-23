"""Backward-compatible re-export for external / Prefect call sites.

The implementation lives in ``patchpilot.flows.daily_ingest`` so the CLI and
installed package do not depend on a top-level ``flows`` module on ``PYTHONPATH``.
"""

from __future__ import annotations

from patchpilot.flows.daily_ingest import cli_entry, daily_ingest_flow

__all__ = ["cli_entry", "daily_ingest_flow"]
