"""Shared pytest fixtures and import-path setup for the test suite."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT: Path = Path(__file__).resolve().parent.parent
_SRC: Path = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
