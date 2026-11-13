"""Parsing and comparison of organisation state snapshots.

A snapshot is what a legitimate listing of one organisation returns, reduced to
the fields the expected-state model predicts: document id -> (content, version).
Both functions are pure; taking the listing is the engine's job.
"""

from __future__ import annotations

from typing import Any

from invariant.adapters.base import Observation

#: External document id -> (content, version).
Snapshot = dict[str, tuple[str, int]]


def parse_snapshot(probe: Observation) -> Snapshot | None:
    """The snapshot carried by a listing observation.

    None means the probe is unusable (no response, non-200, malformed); it never
    means "empty". An empty listing is ``{}``.
    """
    if probe.status != 200:
        return None
    body: Any = probe.json_body()
    if not isinstance(body, list):
        return None
    snapshot: Snapshot = {}
    for item in body:
        if not isinstance(item, dict):
            return None
        doc_id, content, version = item.get("id"), item.get("content"), item.get("version")
        if not (
            isinstance(doc_id, str) and isinstance(content, str) and isinstance(version, int)
        ):
            return None
        snapshot[doc_id] = (content, version)
    return snapshot


def diff_snapshots(expected: Snapshot, observed: Snapshot) -> list[str]:
    """Human-readable differences, in a deterministic order.

    Missing documents first, then unexpected ones, then changed ones; each group
    sorted by document id. An empty list means the snapshots are equal.
    """
    diffs: list[str] = []
    for doc_id in sorted(expected.keys() - observed.keys()):
        diffs.append(f"{doc_id} expected but missing")
    for doc_id in sorted(observed.keys() - expected.keys()):
        diffs.append(f"{doc_id} present but not expected")
    for doc_id in sorted(expected.keys() & observed.keys()):
        if expected[doc_id] != observed[doc_id]:
            diffs.append(
                f"{doc_id} expected (content={expected[doc_id][0]!r}, "
                f"version={expected[doc_id][1]}) observed (content="
                f"{observed[doc_id][0]!r}, version={observed[doc_id][1]})"
            )
    return diffs
