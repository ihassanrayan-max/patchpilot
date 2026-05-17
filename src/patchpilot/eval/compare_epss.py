"""Side-by-side PatchPilot vs EPSS evaluation report writer.

Implemented in: Phase 3.
"""

from __future__ import annotations

from pathlib import Path


def write_report(model_uri: str, report_path: Path) -> Path:
    """Score PatchPilot and EPSS on the held-out window and write a Markdown report.

    Inputs:  ``model_uri`` — MLflow model URI (e.g. ``runs:/<id>/model``).
             ``report_path`` — output Markdown file, conventionally
                                ``docs/benchmarks/REPORT.md``.
    Outputs: absolute path to the written report.
    Invariants: the report contains real numeric AUC-PR, AUC-ROC, P@K, Brier,
                and ECE for both PatchPilot and EPSS; no placeholders.
    Implemented in: Phase 3.
    """
    raise NotImplementedError("Phase 3")
