"""Release flags.

Meridian ships several code paths behind flags while they roll out. ``MERIDIAN_FLAGS`` selects
which ones are on for this process: ``all`` (the default, the build as currently deployed to
staging), ``none`` (every path on its stable implementation) or a comma separated list.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

ALL_FLAGS: frozenset[str] = frozenset(
    {
        "edge-cache-v2",
        "recent-viewers",
        "coediting-lease",
        "owner-follows-editor",
        "read-replica",
        "collab-sessions",
        "history-rotation",
        "friendly-refusals",
        "merge-revisions",
        "draft-autosave",
        "lean-error-pages",
        "bulk-render",
        "undo-toast",
    }
)


def flags_from_env(env: Mapping[str, str] | None = None) -> frozenset[str]:
    raw = (os.environ if env is None else env).get("MERIDIAN_FLAGS", "all").strip().lower()
    if raw in ("", "all"):
        return ALL_FLAGS
    if raw == "none":
        return frozenset()
    chosen = frozenset(part.strip() for part in raw.split(",") if part.strip())
    unknown = chosen - ALL_FLAGS
    if unknown:
        raise ValueError(f"unknown flags: {sorted(unknown)}")
    return chosen
