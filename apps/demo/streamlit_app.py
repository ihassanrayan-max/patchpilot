"""Streamlit demo: score CVE ids and rank an SBOM via the PatchPilot API.

The page is intentionally small. It talks to the FastAPI service over
HTTP at ``PATCHPILOT_API`` (default ``http://localhost:8000``) so the
demo container and the API container can stay decoupled.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import streamlit as st

API_URL = os.environ.get("PATCHPILOT_API", "http://localhost:8000")
DEFAULT_CVES = "CVE-2022-42475\nCVE-2023-21674\nCVE-2024-12345"

_INLINE_FALLBACK_SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "openssl",
                "version": "3.0.0",
                "purl": "pkg:generic/openssl@3.0.0",
            }
        ],
        "vulnerabilities": [
            {"id": "CVE-2022-42475", "affects": [{"ref": "pkg:generic/openssl@3.0.0"}]}
        ],
    },
    indent=2,
)


def _load_default_sbom() -> str:
    """Best-effort load of the repo's root ``sample_sbom.json``.

    Tries an explicit ``PATCHPILOT_SAMPLE_SBOM`` override, the current
    working directory, and the path relative to this file (``apps/demo`` ->
    repo root) so the demo works both from a local checkout and a container
    build. Falls back to a small inline SBOM if none are found.
    """
    candidates = []
    env_override = os.environ.get("PATCHPILOT_SAMPLE_SBOM")
    if env_override:
        candidates.append(Path(env_override))
    candidates.append(Path("sample_sbom.json"))
    candidates.append(Path(__file__).resolve().parents[2] / "sample_sbom.json")
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8")
        except OSError:
            continue
    return _INLINE_FALLBACK_SBOM


DEFAULT_SBOM = _load_default_sbom()


def _client() -> httpx.Client:
    """Return a short-timeout httpx client targeting the configured API."""
    return httpx.Client(base_url=API_URL, timeout=15.0)


def _model_info_panel() -> None:
    """Render the loaded model metadata as a side-pane."""
    st.sidebar.header("Model")
    st.sidebar.write(f"API: `{API_URL}`")
    try:
        with _client() as client:
            r = client.get("/healthz")
            st.sidebar.write(f"healthz: `{r.json()}`")
            info = client.get("/model/info").json()
    except httpx.HTTPError as exc:
        st.sidebar.error(f"could not reach API: {exc}")
        return
    st.sidebar.write(f"model_version: `{info.get('model_version')}`")
    st.sidebar.write(f"run_id: `{info.get('run_id')}`")
    st.sidebar.write(f"n_features: {info.get('n_features')}")
    st.sidebar.write(f"n_rows: {info.get('n_rows')}")
    st.sidebar.write(f"n_pos: {info.get('n_pos')}")
    fm = info.get("final_valid_metrics") or {}
    if fm:
        st.sidebar.json(fm)


def _score_panel() -> None:
    """Render the CVE-score input/output panel."""
    st.subheader("Score CVE ids")
    raw = st.text_area(
        "One CVE id per line.",
        value=DEFAULT_CVES,
        height=120,
    )
    if st.button("Score"):
        cve_ids = [line.strip() for line in raw.splitlines() if line.strip()]
        if not cve_ids:
            st.warning("Enter at least one CVE id.")
            return
        try:
            with _client() as client:
                r = client.post("/score", json={"cve_ids": cve_ids})
                r.raise_for_status()
        except httpx.HTTPError as exc:
            st.error(f"score request failed: {exc}")
            return
        payload: dict[str, Any] = r.json()
        st.write(f"`scored_at` {payload.get('scored_at')}")
        st.dataframe(payload["results"])


def _rank_panel() -> None:
    """Render the SBOM rank input/output panel."""
    st.subheader("Rank an SBOM")
    sbom_text = st.text_area(
        "Paste a CycloneDX 1.4/1.5 SBOM JSON.",
        value=DEFAULT_SBOM,
        height=240,
    )
    upload = st.file_uploader("...or upload a CycloneDX SBOM JSON file.", type=["json"])
    if upload is not None:
        sbom_text = upload.read().decode("utf-8")
    if st.button("Rank"):
        try:
            sbom = json.loads(sbom_text)
        except json.JSONDecodeError as exc:
            st.error(f"SBOM is not valid JSON: {exc}")
            return
        try:
            with _client() as client:
                r = client.post("/rank", json={"sbom": sbom})
                r.raise_for_status()
        except httpx.HTTPError as exc:
            st.error(f"rank request failed: {exc}")
            return
        payload = r.json()
        st.write(f"`ranked_at` {payload.get('ranked_at')}  -  {len(payload['items'])} pairs")
        st.dataframe(payload["items"])


def main() -> None:
    """Render the Streamlit demo."""
    st.set_page_config(page_title="PatchPilot Demo", layout="wide")
    st.title("PatchPilot")
    st.caption(
        "Predict 30-day CVE exploitation and rank SBOM vulnerabilities. "
        "Backed by the PatchPilot FastAPI service."
    )
    _model_info_panel()
    _score_panel()
    st.divider()
    _rank_panel()


if __name__ == "__main__":
    main()
