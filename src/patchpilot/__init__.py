"""PatchPilot: predict 30-day CVE exploitation and rank SBOM vulnerabilities.

This package is the foundation laid in Phase 0. Every submodule exposes typed
stubs that raise ``NotImplementedError("Phase N")`` where N is the phase that
will implement the function. See ``PLAN.md`` for the full phase contract.
"""

from __future__ import annotations

__version__: str = "0.1.0"
__all__: list[str] = ["__version__"]
