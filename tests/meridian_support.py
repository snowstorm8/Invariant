"""Helpers for tests of the Meridian Docs example (the enterprise demo application)."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi.testclient import TestClient
from meridian.app import create_app

from invariant.adapters.http import HttpAdapter
from invariant.integrations.builtin_rules import builtin_source, library_source
from invariant.integrations.document_saas import DOCUMENT_SAAS
from invariant.rules.engine import RuleSet

MERIDIAN = Path(__file__).resolve().parent.parent / "examples" / "meridian_docs"

#: The release flag behind each hidden defect, and the default rule that catches it.
DEFECTS: dict[str, str] = {
    "edge-cache-v2": "AC-1",
    "recent-viewers": "AC-2",
    "coediting-lease": "AC-3",
    "owner-follows-editor": "AC-4",
    "read-replica": "AC-7",
    "collab-sessions": "DX-1",
    "history-rotation": "IR-1",
    "friendly-refusals": "DX-3",
    "merge-revisions": "IR-3",
    "draft-autosave": "IR-2",
    "lean-error-pages": "TH-1",
    "bulk-render": "TH-6",
    "undo-toast": "TH-8",
}


class MeridianAdapter(HttpAdapter):
    """In-process Meridian build with exactly these flags on (one app per adapter)."""

    def __init__(self, flags: frozenset[str]) -> None:
        client = TestClient(create_app(flags), raise_server_exceptions=False)
        client.__enter__()
        super().__init__(client)
        self._test_client = client

    def close(self) -> None:
        self._test_client.__exit__(None, None, None)


def shipped_rules() -> RuleSet:
    """Every default rule (core + web library), as the console runs them."""
    return RuleSet.from_text(builtin_source() + "\n" + library_source(), DOCUMENT_SAAS.schema)


def copy_project(tmp_path: Path, *, flags: str) -> Path:
    """A copy of the example whose manifest pins ``MERIDIAN_FLAGS`` (``none`` = the fixed build)."""
    target = tmp_path / "meridian"
    shutil.copytree(MERIDIAN, target, ignore=shutil.ignore_patterns("__pycache__"))
    manifest = target / "invariant.toml"
    manifest.write_text(
        manifest.read_text().replace(
            'start_timeout = 20', f'start_timeout = 20\nenv = {{ MERIDIAN_FLAGS = "{flags}" }}'
        )
    )
    return target
