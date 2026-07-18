"""Unit tests for the EPSS-complement blend in ``patchpilot.serve.scoring``.

Uses a lightweight stand-in state object (structurally compatible with the
``AppState`` protocol) rather than the real FastAPI ``_ModelState`` /
LightGBM artifact, so these tests are fast and independent of
``serve/api.py`` (owned by Agent B) and of any trained model file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pytest

from patchpilot.models.baseline_epss import EpssBaseline
from patchpilot.serve.scoring import score_cve_ids


class _StubResidualModel:
    """Fake ``task="regression"`` model returning a fixed residual per row."""

    task = "regression"

    def __init__(self, residual_by_row: dict[tuple[float, ...], float]) -> None:
        self._residual_by_row = residual_by_row

    def predict_raw(self, rows: np.ndarray) -> np.ndarray:
        return np.asarray(
            [self._residual_by_row.get(tuple(row.tolist()), 0.0) for row in rows],
            dtype=np.float32,
        )


class _StubClassifierModel:
    """Fake ``task="classification"`` model returning a fixed absolute probability."""

    task = "classification"

    def __init__(self, proba_by_row: dict[tuple[float, ...], float]) -> None:
        self._proba_by_row = proba_by_row

    def predict_proba(self, rows: np.ndarray) -> np.ndarray:
        return np.asarray(
            [self._proba_by_row.get(tuple(row.tolist()), 0.0) for row in rows],
            dtype=np.float32,
        )


@dataclass
class _FakeState:
    """Minimal stand-in satisfying the ``scoring.AppState`` protocol."""

    model: Any = None
    feature_names: list[str] = field(default_factory=list)
    feature_lookup: dict[str, np.ndarray] = field(default_factory=dict)
    baseline: EpssBaseline = field(default_factory=lambda: EpssBaseline.from_mapping({}))
    in_kev_lookup: dict[str, bool] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


def test_unknown_cve_with_no_epss_and_no_model_scores_zero() -> None:
    """Fully unknown CVE (no EPSS, no features, no model) -> 0.0, not an error."""
    state = _FakeState()
    results = score_cve_ids(state, ["CVE-2099-00001"])
    assert len(results) == 1
    assert results[0].probability == 0.0
    assert results[0].percentile == 0.0
    assert results[0].in_kev is False


def test_known_epss_but_no_features_falls_back_to_epss() -> None:
    """Missing per-CVE features (no model, or model doesn't know this CVE) -> EPSS."""
    state = _FakeState(
        baseline=EpssBaseline.from_mapping({"CVE-2024-0001": 0.42}, {"CVE-2024-0001": 0.9}),
    )
    results = score_cve_ids(state, ["CVE-2024-0001"])
    assert results[0].probability == pytest.approx(0.42)
    assert results[0].percentile == pytest.approx(0.9)


def test_known_epss_with_model_loaded_but_cve_missing_from_feature_lookup_falls_back_to_epss() -> (
    None
):
    """A model is loaded, but this specific CVE has no row in ``feature_lookup`` -> EPSS."""
    model = _StubResidualModel({})
    state = _FakeState(
        model=model,
        feature_names=["f_epss_score", "f_cvss"],
        feature_lookup={"CVE-2024-9999": np.array([0.1, 5.0], dtype=np.float32)},
        baseline=EpssBaseline.from_mapping({"CVE-2024-0002": 0.15}),
        metadata={"strategy": "epss_complement"},
    )
    results = score_cve_ids(state, ["CVE-2024-0002"])
    assert results[0].probability == pytest.approx(0.15)


def test_blend_adds_residual_to_epss_when_features_known() -> None:
    """probability = clamp01(epss + residual) for a known CVE with a loaded residual model."""
    row = np.array([0.3, 7.0], dtype=np.float32)
    model = _StubResidualModel({tuple(row.tolist()): 0.2})
    state = _FakeState(
        model=model,
        feature_names=["f_epss_score", "f_cvss"],
        feature_lookup={"CVE-2024-0003": row},
        baseline=EpssBaseline.from_mapping({"CVE-2024-0003": 0.3}),
        metadata={"strategy": "epss_complement"},
    )
    results = score_cve_ids(state, ["CVE-2024-0003"])
    assert results[0].probability == pytest.approx(0.5, abs=1e-6)


def test_blend_clamps_above_one() -> None:
    """A large positive residual must not push probability above 1.0."""
    row = np.array([0.9, 9.0], dtype=np.float32)
    model = _StubResidualModel({tuple(row.tolist()): 0.5})
    state = _FakeState(
        model=model,
        feature_names=["f_epss_score", "f_cvss"],
        feature_lookup={"CVE-2024-0004": row},
        baseline=EpssBaseline.from_mapping({"CVE-2024-0004": 0.9}),
        metadata={"strategy": "epss_complement"},
    )
    results = score_cve_ids(state, ["CVE-2024-0004"])
    assert results[0].probability == pytest.approx(1.0)


def test_blend_clamps_below_zero() -> None:
    """A large negative residual must not push probability below 0.0."""
    row = np.array([0.05, 2.0], dtype=np.float32)
    model = _StubResidualModel({tuple(row.tolist()): -0.5})
    state = _FakeState(
        model=model,
        feature_names=["f_epss_score", "f_cvss"],
        feature_lookup={"CVE-2024-0005": row},
        baseline=EpssBaseline.from_mapping({"CVE-2024-0005": 0.05}),
        metadata={"strategy": "epss_complement"},
    )
    results = score_cve_ids(state, ["CVE-2024-0005"])
    assert results[0].probability == pytest.approx(0.0)


def test_never_zeroes_out_a_cve_epss_flags_as_risky_even_without_a_model() -> None:
    """Core product guarantee: no model loaded still returns EPSS, never a silent 0."""
    state = _FakeState(
        model=None,
        baseline=EpssBaseline.from_mapping({"CVE-2024-0006": 0.77}),
    )
    results = score_cve_ids(state, ["CVE-2024-0006"])
    assert results[0].probability == pytest.approx(0.77)


def test_in_kev_and_batch_ordering_preserved() -> None:
    """Batch scoring preserves input order and per-CVE ``in_kev`` metadata."""
    row = np.array([0.6, 8.0], dtype=np.float32)
    model = _StubResidualModel({tuple(row.tolist()): 0.1})
    state = _FakeState(
        model=model,
        feature_names=["f_epss_score", "f_cvss"],
        feature_lookup={"CVE-2024-0007": row},
        baseline=EpssBaseline.from_mapping(
            {"CVE-2024-0007": 0.6, "CVE-2024-0008": 0.05}
        ),
        in_kev_lookup={"CVE-2024-0007": True},
        metadata={"strategy": "epss_complement"},
    )
    results = score_cve_ids(state, ["CVE-2024-0008", "CVE-2024-0007", "CVE-2099-99999"])
    assert [r.cve_id for r in results] == ["CVE-2024-0008", "CVE-2024-0007", "CVE-2099-99999"]
    assert results[0].probability == pytest.approx(0.05)
    assert results[1].probability == pytest.approx(0.7, abs=1e-6)
    assert results[1].in_kev is True
    assert results[2].probability == 0.0
    assert results[2].in_kev is False


def test_non_complement_classifier_artifact_degrades_gracefully() -> None:
    """A plain classification-task model (no complement metadata) still returns a probability.

    This is a defensive fallback for a mis-set ``latest.json`` pointing at a
    non-complement (e.g. ablation) artifact: scoring must not crash, and
    should not double-count EPSS on top of an already-absolute probability.
    """
    row = np.array([0.4, 6.0], dtype=np.float32)
    model = _StubClassifierModel({tuple(row.tolist()): 0.65})
    state = _FakeState(
        model=model,
        feature_names=["f_epss_score", "f_cvss"],
        feature_lookup={"CVE-2024-0009": row},
        baseline=EpssBaseline.from_mapping({"CVE-2024-0009": 0.4}),
        metadata={"strategy": "full"},
    )
    results = score_cve_ids(state, ["CVE-2024-0009"])
    assert results[0].probability == pytest.approx(0.65, abs=1e-6)
