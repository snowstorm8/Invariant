"""Adapter factories wiring the demo app into Invariant (in-process, via TestClient)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from invariant.adapters.http import HttpAdapter

from .app.main import create_app

#: The controlled defect used for the milestone.
DEFAULT_DEFECT = "stale-cache-read"


class InProcessAdapter(HttpAdapter):
    """HttpAdapter over an in-process ASGI app; one app (hence one state) per adapter."""

    def __init__(self, defects: frozenset[str]) -> None:
        # raise_server_exceptions=False: a crashing handler must surface as a 500
        # observation (INCONCLUSIVE), not as an exception in the test process.
        client = TestClient(create_app(defects), raise_server_exceptions=False)
        # Entering the context keeps one event-loop portal alive across requests;
        # without it every request spawns a thread, which is ~10x slower.
        client.__enter__()
        super().__init__(client)
        self._test_client = client

    def close(self) -> None:
        self._test_client.__exit__(None, None, None)


def adapter_for(defects: frozenset[str]) -> HttpAdapter:
    return InProcessAdapter(defects)


def vulnerable_adapter() -> HttpAdapter:
    return adapter_for(frozenset({DEFAULT_DEFECT}))


def fixed_adapter() -> HttpAdapter:
    return adapter_for(frozenset())
