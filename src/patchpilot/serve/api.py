"""FastAPI application exposing ``/score``, ``/rank``, and ``/healthz``.

Phase 0 wires routes that raise HTTP 501 so the surface area is real and the
service starts cleanly. Phase 4 plugs the trained model in.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from patchpilot.serve.schemas import (
    HealthResponse,
    RankRequest,
    RankResponse,
    ScoreRequest,
    ScoreResponse,
)

app: FastAPI = FastAPI(
    title="PatchPilot",
    version="0.1.0",
    description="Predict 30-day CVE exploitation and rank SBOM vulnerabilities.",
)


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    """Liveness probe. Returns ``status='ok'`` once Phase 4 wires a model."""
    return HealthResponse(status="ok", model_version=None)


@app.post("/score", response_model=ScoreResponse)
def score(request: ScoreRequest) -> ScoreResponse:
    """Score a batch of CVE ids. Phase 4 implementation."""
    _ = request
    raise HTTPException(status_code=501, detail="Phase 4")


@app.post("/rank", response_model=RankResponse)
def rank(request: RankRequest) -> RankResponse:
    """Rank vulnerabilities in a CycloneDX SBOM. Phase 4 implementation."""
    _ = request
    raise HTTPException(status_code=501, detail="Phase 4")
