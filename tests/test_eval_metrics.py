"""Regression tests for ranking/calibration helpers vs sklearn / references."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

from patchpilot.eval.metrics import (
    auc_roc,
    aucpr,
    brier_score,
    expected_calibration_error,
    precision_at_k,
)


def _reference_precision_at_k(y_true: np.ndarray, y_score: np.ndarray, k: int) -> float:
    yt = np.asarray(y_true, dtype=np.float64).ravel()
    ys = np.asarray(y_score, dtype=np.float64).ravel()
    kk = min(k, len(ys))
    top_idx = np.argsort(-ys)[:kk]
    return float(yt[top_idx].sum()) / float(kk)


def _reference_ece(y_true: np.ndarray, y_score: np.ndarray, n_bins: int = 10) -> float:
    yt = np.asarray(y_true, dtype=np.float64).ravel()
    ys = np.clip(np.asarray(y_score, dtype=np.float64).ravel(), 0.0, 1.0)
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(yt)
    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        mask = (ys >= lo) & (ys <= hi if i == n_bins - 1 else ys < hi)
        if not mask.any():
            continue
        bin_conf = ys[mask].mean()
        bin_acc = yt[mask].mean()
        ece += abs(bin_conf - bin_acc) * (mask.sum() / n)
    return float(ece)


def test_metrics_agree_with_sklearn_and_references_on_synthetic_frame() -> None:
    rng = np.random.default_rng(42)
    y_true = rng.integers(0, 2, size=1000, dtype=np.int8)
    while np.unique(y_true).size < 2:
        y_true = rng.integers(0, 2, size=1000, dtype=np.int8)
    y_score = rng.uniform(0.0, 1.0, size=1000).astype(np.float64)

    np.testing.assert_allclose(
        aucpr(y_true, y_score),
        average_precision_score(y_true, y_score),
        rtol=1e-12,
        atol=1e-12,
    )
    np.testing.assert_allclose(
        auc_roc(y_true, y_score),
        roc_auc_score(y_true, y_score),
        rtol=1e-12,
        atol=1e-12,
    )
    clipped = np.clip(y_score, 0.0, 1.0)
    np.testing.assert_allclose(
        brier_score(y_true, y_score),
        brier_score_loss(y_true, clipped),
        rtol=1e-12,
        atol=1e-12,
    )

    for k in (1, 10, 100, 500):
        np.testing.assert_allclose(
            precision_at_k(y_true, y_score, k=k),
            _reference_precision_at_k(y_true, y_score, k=k),
            rtol=1e-12,
            atol=1e-12,
        )

    np.testing.assert_allclose(
        expected_calibration_error(y_true, y_score, n_bins=10),
        _reference_ece(y_true, y_score, n_bins=10),
        rtol=1e-12,
        atol=1e-12,
    )


def test_assert_benchmark_gate_rejects_empty_report(tmp_path: Path) -> None:
    from patchpilot.eval.compare_epss import assert_benchmark_gate

    report = tmp_path / "REPORT.md"
    report.write_text(
        "# PatchPilot vs EPSS - Benchmark Report\n\n**Status:** could not compute metrics.\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as exc:
        assert_benchmark_gate(report_path=report, config_path=tmp_path / "missing.toml")
    assert exc.value.code == 1


def test_assert_benchmark_gate_accepts_report_within_margin(tmp_path: Path) -> None:
    from patchpilot.eval.compare_epss import assert_benchmark_gate

    report = tmp_path / "REPORT.md"
    report.write_text(
        "# PatchPilot vs EPSS - Benchmark Report\n\n"
        "| Model       | AUC-PR | AUC-ROC | P@100 | Brier | ECE |\n"
        "| ----------- | ------ | ------- | ----- | ----- | --- |\n"
        "| PatchPilot  | 0.2000 | 0.7000 | 0.0300 | 0.0020 | 0.0010 |\n"
        "| EPSS        | 0.4370 | 0.9650 | 0.0300 | 0.0140 | 0.0240 |\n",
        encoding="utf-8",
    )
    config = tmp_path / "settings.toml"
    config.write_text("[eval]\nauc_pr_margin = 1.0\n", encoding="utf-8")
    assert_benchmark_gate(report_path=report, config_path=config)
