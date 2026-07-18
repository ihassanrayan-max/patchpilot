"""Thin helpers around the local file model registry under ``.mlruns/``.

PatchPilot's supported registry is the JSON/file layout written by
``patchpilot.train.train`` (``model.pkl``, ``metadata.json``, ``latest.json``).
These helpers do **not** require a hosted MLflow tracking server. They exist
so call sites can share load/URI logic without implying fake MLflow maturity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from patchpilot.models.lgbm import LgbmModel


def get_tracking_uri(mlruns_dir: Path) -> str:
    """Return a ``file://`` URI for the local registry directory.

    Pure helper; no I/O. Useful if a future phase wraps the same directory
    with the MLflow client.
    """
    path = Path(mlruns_dir).resolve()
    return path.as_uri()


def load_latest_pointer(mlruns_dir: Path) -> dict[str, Any] | None:
    """Read ``.mlruns/latest.json`` or return ``None`` if missing/invalid."""
    pointer = Path(mlruns_dir) / "latest.json"
    if not pointer.exists():
        return None
    try:
        return cast(dict[str, Any], json.loads(pointer.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None


def load_latest_model(mlruns_dir: Path | str = ".mlruns") -> LgbmModel:
    """Load the latest finished local registry model.

    Raises ``FileNotFoundError`` when the pointer or artifact is missing.
    """
    mlruns_dir = Path(mlruns_dir)
    info = load_latest_pointer(mlruns_dir)
    if info is None:
        raise FileNotFoundError(f"no latest.json under {mlruns_dir}")
    artifact = Path(str(info.get("artifact") or ""))
    if not artifact.exists():
        run_id = info.get("run_id")
        if isinstance(run_id, str):
            artifact = mlruns_dir / run_id / "model.pkl"
    if not artifact.exists():
        raise FileNotFoundError(f"model artifact missing under {mlruns_dir}")
    return LgbmModel.load(artifact)
