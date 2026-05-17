"""Streamlit demo: upload an SBOM, get a ranked vulnerability list.

Phase 0 ships a placeholder page so the demo container builds and starts.
Phase 4 wires the SBOM uploader and ``/rank`` round-trip.
"""

from __future__ import annotations


def main() -> None:
    """Render the Streamlit demo. Phase 0: placeholder page only."""
    import streamlit as st

    st.set_page_config(page_title="PatchPilot Demo", layout="wide")
    st.title("PatchPilot")
    st.caption("Predict 30-day CVE exploitation and rank SBOM vulnerabilities.")
    st.info(
        "Phase 0 scaffold. SBOM upload and ranked vulnerability view land in Phase 4. "
        "See PLAN.md for the full roadmap."
    )


if __name__ == "__main__":
    main()
