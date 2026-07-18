"""FastAPI application exposing ``/healthz``, ``/model/info``, ``/score``, ``/rank``.

Loading strategy:
* Paths come from constructor args, else env overrides, else defaults.
* If a trained model artifact exists under ``.mlruns/latest.json`` we load
  it eagerly at process start.
* If a silver parquet exists we load its EPSS columns into the
  ``EpssBaseline`` so unknown-CVE / no-model paths still return EPSS.
* If neither exists we still start up cleanly. ``/healthz`` reports the
  degraded state and ``/score`` falls back to EPSS-only scoring.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import numpy as np
import polars as pl
from fastapi import FastAPI, HTTPException

from patchpilot.models.baseline_epss import EpssBaseline
from patchpilot.models.lgbm import LgbmModel
from patchpilot.serve import scoring
from patchpilot.serve.sbom import ComponentCveMatch, cves_for_components, parse_cyclonedx
from patchpilot.serve.schemas import (
    HealthResponse,
    ModelInfoResponse,
    RankItem,
    RankRequest,
    RankResponse,
    ReadyResponse,
    ScoreItem,
    ScoreRequest,
    ScoreResponse,
)

DEFAULT_MLRUNS = Path(os.environ.get("PATCHPILOT_MLRUNS_DIR", ".mlruns"))
DEFAULT_SILVER = Path(
    os.environ.get("PATCHPILOT_SILVER_PATH", "data/silver/cve_master.parquet")
)
DEFAULT_BRONZE_NVD = Path(os.environ.get("PATCHPILOT_BRONZE_NVD_DIR", "data/bronze/nvd"))


class _ModelState:
    """Thread-safe container for the loaded model + lookup tables."""

    def __init__(self) -> None:
        """Initialise empty state; populate via :meth:`load`."""
        self._lock = threading.Lock()
        self.model: LgbmModel | None = None
        self.metadata: dict[str, Any] = {}
        self.feature_names: list[str] = []
        self.silver: pl.DataFrame | None = None
        self.baseline: EpssBaseline = EpssBaseline.from_mapping({})
        self.feature_lookup: dict[str, np.ndarray] = {}
        self.in_kev_lookup: dict[str, bool] = {}
        self.cvss_lookup: dict[str, float | None] = {}
        self.silver_path: Path = DEFAULT_SILVER
        self.mlruns_dir: Path = DEFAULT_MLRUNS
        self.bronze_nvd_dir: Path = DEFAULT_BRONZE_NVD

    def load(
        self,
        *,
        mlruns_dir: Path | None = None,
        silver_path: Path | None = None,
        bronze_nvd_dir: Path | None = None,
    ) -> None:
        """Idempotent model + silver-cache load with optional path overrides."""
        with self._lock:
            self.mlruns_dir = Path(mlruns_dir) if mlruns_dir is not None else DEFAULT_MLRUNS
            self.silver_path = Path(silver_path) if silver_path is not None else DEFAULT_SILVER
            self.bronze_nvd_dir = (
                Path(bronze_nvd_dir) if bronze_nvd_dir is not None else DEFAULT_BRONZE_NVD
            )
            self._load_silver(self.silver_path)
            self._load_model(self.mlruns_dir)

    def _load_silver(self, silver_path: Path) -> None:
        """Populate the per-CVE lookups used by ``/score`` and ``/rank``."""
        if not silver_path.exists():
            self.silver = None
            self.baseline = EpssBaseline.from_mapping({})
            self.feature_lookup = {}
            self.in_kev_lookup = {}
            self.cvss_lookup = {}
            return
        df = pl.read_parquet(silver_path)
        self.silver = df
        scores = dict(
            zip(
                df.get_column("cve_id").to_list(),
                [float(x) if x is not None else 0.0 for x in df.get_column("epss_score").to_list()],
                strict=True,
            )
        )
        pct = dict(
            zip(
                df.get_column("cve_id").to_list(),
                [
                    float(x) if x is not None else 0.0
                    for x in df.get_column("epss_percentile").to_list()
                ],
                strict=True,
            )
        )
        self.baseline = EpssBaseline.from_mapping(scores, pct)
        self.in_kev_lookup = dict(
            zip(
                df.get_column("cve_id").to_list(),
                [bool(x) for x in df.get_column("in_kev").to_list()],
                strict=True,
            )
        )
        self.cvss_lookup = dict(
            zip(
                df.get_column("cve_id").to_list(),
                [None if x is None else float(x) for x in df.get_column("cvss_v3_base_score").to_list()],
                strict=True,
            )
        )

    def _load_model(self, mlruns_dir: Path) -> None:
        """Locate and load the latest model artifact + metadata."""
        pointer = mlruns_dir / "latest.json"
        if not pointer.exists():
            self.model = None
            self.metadata = {}
            self.feature_names = []
            self.feature_lookup = {}
            return
        info = cast(dict[str, Any], json.loads(pointer.read_text()))
        artifact = _resolve_artifact_path(mlruns_dir, info)
        if artifact is None:
            self.model = None
            self.metadata = {}
            self.feature_names = []
            self.feature_lookup = {}
            return
        self.model = LgbmModel.load(artifact)
        meta_path = artifact.parent / "metadata.json"
        if meta_path.exists():
            self.metadata = cast(dict[str, Any], json.loads(meta_path.read_text()))
        else:
            self.metadata = {}
        self.feature_names = self.metadata.get("feature_names") or []
        self._build_feature_lookup()

    def _build_feature_lookup(self) -> None:
        """Materialise a per-cve feature row dict for fast scoring."""
        if self.silver is None or self.model is None or not self.feature_names:
            self.feature_lookup = {}
            return
        from patchpilot.train.train import assemble_scoring_frame

        try:
            bronze_dir = self.bronze_nvd_dir.parent if self.bronze_nvd_dir.name == "nvd" else None
            frame = assemble_scoring_frame(
                self.silver_path,
                bronze_dir=bronze_dir,
            )
        except Exception:  # noqa: BLE001
            self.feature_lookup = {}
            return
        missing = [c for c in self.feature_names if c not in frame.columns]
        if missing:
            self.feature_lookup = {}
            return
        cve_ids = frame.get_column("cve_id").to_list()
        matrix = frame.select(self.feature_names).to_numpy().astype(np.float32)
        self.feature_lookup = {str(cve): matrix[i] for i, cve in enumerate(cve_ids)}

    @property
    def model_version(self) -> str | None:
        """Return the loaded model version or ``None`` if no model is loaded."""
        return cast(str | None, self.metadata.get("model_version")) if self.model is not None else None

    @property
    def silver_present(self) -> bool:
        """Whether a silver dataset was successfully loaded."""
        return self.silver is not None

    @property
    def is_healthy(self) -> bool:
        """Full readiness: model loaded *and* silver present (used by ``/healthz``)."""
        return self.model is not None and self.silver_present

    @property
    def is_ready(self) -> bool:
        """Minimal readiness for non-vacuous scoring: silver present (model optional; EPSS fallback)."""
        return self.silver_present


def _resolve_artifact_path(mlruns_dir: Path, info: dict[str, Any]) -> Path | None:
    """Resolve a model artifact path from ``latest.json`` contents.

    Training may persist a cwd-relative ``artifact`` string. Prefer that path
    when it exists; otherwise fall back to ``mlruns_dir/<run_id>/model.pkl``.
    """
    raw = info.get("artifact")
    if isinstance(raw, str) and raw:
        candidate = Path(raw)
        if candidate.exists():
            return candidate
        nested = mlruns_dir / candidate.name
        if nested.exists():
            return nested
    run_id = info.get("run_id")
    if isinstance(run_id, str) and run_id:
        fallback = mlruns_dir / run_id / "model.pkl"
        if fallback.exists():
            return fallback
    return None


STATE: _ModelState = _ModelState()
STATE.load()

app: FastAPI = FastAPI(
    title="PatchPilot",
    version="0.1.0",
    description="Predict 30-day CVE exploitation and rank SBOM vulnerabilities.",
)


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    """Liveness probe with real readiness: ``ok`` only when a model is loaded
    *and* a silver dataset is present; ``degraded`` otherwise (the service is
    still up and ``/score``/``/rank`` still work via EPSS fallback, but
    results may be less complete).
    """
    status = "ok" if STATE.is_healthy else "degraded"
    return HealthResponse(status=status, model_version=STATE.model_version)


@app.get("/readyz", response_model=ReadyResponse, responses={503: {"model": ReadyResponse}})
def readyz() -> ReadyResponse:
    """Readiness probe: 200 only when scoring can return non-vacuous results.

    Silver must be present (source of EPSS scores). The model is optional —
    when absent, ``/score``/``/rank`` fall back to EPSS-only probabilities.
    """
    body = ReadyResponse(
        status="ready" if STATE.is_ready else "not_ready",
        model_loaded=STATE.model is not None,
        silver_present=STATE.silver_present,
        detail=(
            "silver present; model optional (EPSS fallback active)"
            if STATE.is_ready
            else "not ready: silver dataset missing, cannot serve non-vacuous scores"
        ),
    )
    if not STATE.is_ready:
        raise HTTPException(status_code=503, detail=body.model_dump())
    return body


@app.get("/model/info", response_model=ModelInfoResponse)
def model_info() -> ModelInfoResponse:
    """Return metadata about the currently loaded model artifact."""
    meta = STATE.metadata or {}
    return ModelInfoResponse(
        model_version=STATE.model_version,
        run_id=meta.get("run_id"),
        trained_at=meta.get("trained_at"),
        n_features=meta.get("n_features"),
        n_rows=meta.get("n_rows"),
        n_pos=meta.get("n_pos"),
        feature_names=meta.get("feature_names"),
        avg_metrics=meta.get("avg_metrics"),
        final_valid_metrics=meta.get("final_valid_metrics"),
        silver_path=str(STATE.silver_path) if STATE.silver_path else None,
        artifact=meta.get("artifact"),
    )


@app.post("/score", response_model=ScoreResponse)
def score(request: ScoreRequest) -> ScoreResponse:
    """Score a batch of CVE ids."""
    cve_ids = list(request.cve_ids)
    items = scoring.score_cve_ids(STATE, cve_ids)
    return ScoreResponse(
        model_version=STATE.model_version or "unavailable",
        scored_at=datetime.now(UTC),
        results=items,
    )


def rank_sbom(state: _ModelState, sbom: dict[str, Any]) -> RankResponse:
    """Parse ``sbom``, resolve CVE candidates, score via :mod:`patchpilot.serve.scoring`,
    and return a sorted :class:`RankResponse`.

    Shared by the ``/rank`` route and the ``patchpilot rank`` CLI so both
    surfaces stay in lockstep and neither reimplements the blend/sort logic.
    Raises ``ValueError`` on a non-CycloneDX SBOM (callers translate to the
    transport-appropriate error).
    """
    components = parse_cyclonedx(sbom)

    pairs = cves_for_components(components, nvd_bronze_dir=state.bronze_nvd_dir)
    if not pairs:
        return RankResponse(
            model_version=state.model_version or "unavailable",
            ranked_at=datetime.now(UTC),
            items=[],
        )

    unique_cves = list({m.cve_id for m in pairs})
    scored = {item.cve_id: item for item in scoring.score_cve_ids(state, unique_cves)}

    rows: list[tuple[float, float, str, str, ScoreItem, ComponentCveMatch]] = []
    for match in pairs:
        item = scored.get(match.cve_id)
        if item is None:
            continue
        cvss = state.cvss_lookup.get(match.cve_id)
        rows.append(
            (
                item.probability,
                cvss if cvss is not None else 0.0,
                match.cve_id,
                match.purl,
                item,
                match,
            )
        )

    rows.sort(key=lambda r: (-r[0], -r[1], r[2]))

    items: list[RankItem] = []
    for idx, (_proba, _cvss, cve, purl, item, match) in enumerate(rows, start=1):
        items.append(
            RankItem(
                rank=idx,
                cve_id=cve,
                purl=purl,
                probability=item.probability,
                percentile=item.percentile,
                cvss_v3_base_score=state.cvss_lookup.get(cve),
                in_kev=item.in_kev,
                match_method=match.match_method,
                match_confidence=match.match_confidence,
                match_reason=match.match_reason,
            )
        )

    return RankResponse(
        model_version=state.model_version or "unavailable",
        ranked_at=datetime.now(UTC),
        items=items,
    )


@app.post("/rank", response_model=RankResponse)
def rank(request: RankRequest) -> RankResponse:
    """Rank vulnerabilities discovered in a CycloneDX SBOM."""
    try:
        return rank_sbom(STATE, request.sbom)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
