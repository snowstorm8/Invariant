"""Adapter factories wiring the demo app into Invariant (in-process, via TestClient)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from invariant.adapters.http import HttpAdapter
from invariant.console.target import ConsoleTarget, TargetOption

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


#: The seeded defects, described for people (the console and the web bridge).
DEFECTS = {
    "stale-cache-read": {
        "title": "Stale cache read",
        "description": "GET /documents/{id} serves recently updated documents from a cache keyed by id only, skipping the tenant check.",
        "property": "TI-1",
    },
    "update-missing-tenant-check": {
        "title": "Update missing tenant check",
        "description": "PUT /documents/{id} checks the caller's role but not that the document belongs to the caller's organization.",
        "property": "TI-2",
    },
    "viewer-can-update": {
        "title": "Viewer can update",
        "description": "PUT /documents/{id} does not enforce the role check, so read-only viewers can modify documents.",
        "property": "AZ-1",
    },
    "missing-security-headers": {
        "title": "Missing security headers",
        "description": "Responses omit nosniff, no-store, frame and referrer policy and announce the server version.",
        "property": "TH-1",
    },
    "verbose-errors": {
        "title": "Verbose errors",
        "description": "A request for another organization's document gets a 403 naming the owner instead of a plain 404.",
        "property": "DX-3",
    },
}


def console_target() -> ConsoleTarget:
    """The demo app as the console presents it: one switch per seeded defect."""
    return ConsoleTarget(
        name="vulnerable_saas",
        description="Local, deliberately vulnerable multi-tenant document service.",
        adapter_for=adapter_for,
        options=tuple(TargetOption(id=k, **v) for k, v in DEFECTS.items()),
    )
