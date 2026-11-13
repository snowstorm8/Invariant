"""Hypothesis strategies for operation parameters."""

from __future__ import annotations

from hypothesis import strategies as st

from invariant.core.scenario import Role

roles: st.SearchStrategy[Role] = st.sampled_from(list(Role))

# Small alphabet keeps examples readable and rules out accidental collisions
# with the engine's ``<<INV:n>>`` markers.
contents: st.SearchStrategy[str] = st.text(alphabet="abcxyz 019", max_size=8)
