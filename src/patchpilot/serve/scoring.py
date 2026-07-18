"""EPSS-complement scoring: the single source of truth for blend math.

Locked shared interface (see the multi-agent execution plan):

    def score_cve_ids(state, cve_ids: list[str]) -> list[ScoreItem]

Strategy (only supported v0.1 strategy, ``[train].strategy = "epss_complement"``
in ``config/settings.toml``): the trained model predicts a *residual* on top
of point-in-time EPSS rather than an absolute probability of exploitation.
At serving time::

    probability = clamp01(epss + residual)   # when per-CVE features exist
    probability = epss                       # known EPSS, no features/model
    probability = 0.0                        # neither is known

This guarantees PatchPilot never silently zeroes out a CVE that EPSS already
flags as risky, even when the challenger model has nothing to say about it
(unseen CVE, cold-start, degraded deployment with no trained artifact, etc).

Callers (``patchpilot.serve.api`` routes, ``patchpilot rank`` CLI) must
import and call :func:`score_cve_ids` rather than reimplementing this blend;
Agent B's routes/CLI only wire requests to it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import numpy as np

from patchpilot.models.baseline_epss import EpssBaseline
from patchpilot.serve.schemas import ScoreItem

if TYPE_CHECKING:
    from patchpilot.models.lgbm import LgbmModel


@runtime_checkable
class AppState(Protocol):
    """Structural contract this module needs from the serving app state.

    Deliberately a ``Protocol`` (duck typing) rather than a concrete class:
    ``patchpilot.serve.api._ModelState`` already satisfies this shape, and
    scoring.py must not import ``api.py`` (that would create a circular
    import and couple the ML lane to route wiring, which the plan's file
    ownership split explicitly forbids).
    """

    model: LgbmModel | None
    feature_names: list[str]
    feature_lookup: dict[str, np.ndarray]
    baseline: EpssBaseline
    in_kev_lookup: dict[str, bool]
    metadata: dict[str, Any]


def _clamp01(x: float) -> float:
    """Clamp ``x`` to ``[0, 1]``."""
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _is_residual_model(state: AppState) -> bool:
    """Whether the loaded model predicts an EPSS residual (vs an absolute probability).

    Defaults to residual/complement semantics (the only supported v0.1
    strategy) unless metadata explicitly says otherwise, or the model
    object itself declares a non-regression ``task`` (e.g. an ablation
    classifier accidentally left as ``latest.json``).
    """
    metadata = getattr(state, "metadata", None) or {}
    strategy = str(metadata.get("strategy", "epss_complement"))
    model = getattr(state, "model", None)
    model_task = getattr(model, "task", "regression")
    return strategy == "epss_complement" and model_task == "regression"


def score_cve_ids(state: AppState, cve_ids: list[str]) -> list[ScoreItem]:
    """Score ``cve_ids`` with the EPSS-complement blend.

    For each CVE:

    * If a model is loaded and the CVE has known point-in-time features,
      blend ``clamp01(epss + residual)`` where ``residual`` is the model's
      raw (uncalibrated, unclipped) prediction.
    * Else if EPSS is known for the CVE, fall back to the EPSS score alone.
    * Else return ``0.0`` (fully unknown CVE).
    """
    model = getattr(state, "model", None)
    feature_names: list[str] = getattr(state, "feature_names", None) or []
    feature_lookup: dict[str, np.ndarray] = getattr(state, "feature_lookup", None) or {}
    baseline: EpssBaseline = getattr(state, "baseline", None) or EpssBaseline.from_mapping({})
    in_kev_lookup: dict[str, bool] = getattr(state, "in_kev_lookup", None) or {}

    epss_scores = baseline.predict_proba(cve_ids)
    percentiles = baseline.predict_percentile(cve_ids)

    can_blend = model is not None and bool(feature_names) and bool(feature_lookup)
    residuals: np.ndarray | None = None
    if can_blend and model is not None:
        zero_row = np.zeros(len(feature_names), dtype=np.float32)
        rows = np.stack([feature_lookup.get(cve, zero_row) for cve in cve_ids])
        if hasattr(model, "predict_raw") and _is_residual_model(state):
            residuals = np.asarray(model.predict_raw(rows), dtype=np.float64)
        else:
            # Non-complement (e.g. plain classification) artifact: treat its
            # absolute probability as already-blended so behaviour degrades
            # gracefully instead of double-adding EPSS.
            residuals = np.asarray(model.predict_proba(rows), dtype=np.float64) - np.asarray(
                epss_scores, dtype=np.float64
            )

    results: list[ScoreItem] = []
    for i, cve in enumerate(cve_ids):
        epss = float(epss_scores[i])
        known_epss = baseline.known(cve)
        if can_blend and cve in feature_lookup and residuals is not None:
            probability = _clamp01(epss + float(residuals[i]))
        elif known_epss:
            probability = _clamp01(epss)
        else:
            probability = 0.0
        results.append(
            ScoreItem(
                cve_id=cve,
                probability=probability,
                percentile=_clamp01(float(percentiles[i])),
                in_kev=bool(in_kev_lookup.get(cve, False)),
            )
        )
    return results
