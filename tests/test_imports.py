"""Phase 0 wiring test: every module under ``patchpilot`` and ``flows`` must import.

This is the only test that must pass green in Phase 0. It guarantees the
scaffold is internally consistent: no missing imports, no typos in
``__init__.py`` files, no broken cross-module references.
"""

from __future__ import annotations

import importlib
import pkgutil

import flows
import patchpilot


def _iter_module_names(package: object) -> list[str]:
    """Walk a package and return every importable submodule name."""
    paths = getattr(package, "__path__", None)
    if paths is None:
        return [package.__name__]  # type: ignore[attr-defined]
    return [
        info.name
        for info in pkgutil.walk_packages(path=paths, prefix=f"{package.__name__}.")
    ]


def test_patchpilot_modules_import() -> None:
    """Every module under ``src/patchpilot`` imports cleanly."""
    modules = _iter_module_names(patchpilot)
    assert modules, "patchpilot package exposed no modules"
    for name in modules:
        importlib.import_module(name)


def test_flows_modules_import() -> None:
    """Every module under ``flows/`` imports cleanly."""
    modules = _iter_module_names(flows)
    assert modules, "flows package exposed no modules"
    for name in modules:
        importlib.import_module(name)


def test_cli_app_constructed() -> None:
    """The typer app is importable and has the four expected commands."""
    from patchpilot.cli import app

    names = {cmd.name or cmd.callback.__name__ for cmd in app.registered_commands}
    assert {"ingest", "train", "eval", "serve"} <= names
