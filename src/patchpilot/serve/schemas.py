"""Pydantic v2 request/response models for the FastAPI service.

These classes are the public API contract documented in ``PLAN.md`` and are
wired into the FastAPI routes in ``patchpilot.serve.api``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScoreRequest(BaseModel):
    """POST /score request body."""

    model_config = ConfigDict(extra="forbid")

    cve_ids: list[str] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="List of CVE identifiers to score, e.g. ['CVE-2024-1234'].",
    )


class ScoreItem(BaseModel):
    """One scored CVE in a /score response."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    probability: float = Field(..., ge=0.0, le=1.0)
    percentile: float = Field(..., ge=0.0, le=1.0)
    in_kev: bool


class ScoreResponse(BaseModel):
    """POST /score response body."""

    model_config = ConfigDict(extra="forbid")

    model_version: str
    scored_at: datetime
    results: list[ScoreItem]


class RankRequest(BaseModel):
    """POST /rank request body: a CycloneDX 1.5 JSON SBOM."""

    model_config = ConfigDict(extra="forbid")

    sbom: dict[str, Any] = Field(
        ...,
        description="CycloneDX 1.5 JSON document (bomFormat='CycloneDX').",
    )


class RankItem(BaseModel):
    """One ranked CVE+component pair in a /rank response."""

    model_config = ConfigDict(extra="forbid")

    rank: int = Field(..., ge=1)
    cve_id: str
    purl: str
    probability: float = Field(..., ge=0.0, le=1.0)
    percentile: float = Field(..., ge=0.0, le=1.0)
    cvss_v3_base_score: float | None = Field(default=None, ge=0.0, le=10.0)
    in_kev: bool
    match_method: str = Field(
        default="unknown",
        description="How the CVE was associated: inline_vex|product_version_exact|product_name|unknown",
    )
    match_confidence: str = Field(
        default="low",
        description="high|medium|low — confidence of the component→CVE association",
    )
    match_reason: str = Field(
        default="",
        description="Human-readable explanation of the match",
    )


class RankResponse(BaseModel):
    """POST /rank response body."""

    model_config = ConfigDict(extra="forbid")

    model_version: str
    ranked_at: datetime
    items: list[RankItem]


class HealthResponse(BaseModel):
    """GET /healthz response body."""

    model_config = ConfigDict(extra="forbid")

    status: str
    model_version: str | None = None


class ReadyResponse(BaseModel):
    """GET /readyz response body (200 only when scoring can return non-vacuous results)."""

    model_config = ConfigDict(extra="forbid")

    status: str
    model_loaded: bool
    silver_present: bool
    detail: str


class ModelInfoResponse(BaseModel):
    """GET /model/info response body."""

    model_config = ConfigDict(extra="forbid")

    model_version: str | None = None
    run_id: str | None = None
    trained_at: str | None = None
    n_features: int | None = None
    n_rows: int | None = None
    n_pos: int | None = None
    feature_names: list[str] | None = None
    avg_metrics: dict[str, float] | None = None
    final_valid_metrics: dict[str, float] | None = None
    silver_path: str | None = None
    artifact: str | None = None
