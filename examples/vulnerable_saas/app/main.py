"""Application factory for the demo SaaS."""

from __future__ import annotations

from fastapi import FastAPI

from .models import KNOWN_DEFECTS, AppState
from .routes import resources, users


def create_app(defects: frozenset[str] = frozenset()) -> FastAPI:
    """Build an isolated app instance. ``defects`` is a subset of KNOWN_DEFECTS."""
    unknown = defects - KNOWN_DEFECTS
    if unknown:
        raise ValueError(f"unknown defects: {sorted(unknown)}")
    app = FastAPI(title="vulnerable-saas (intentionally insecure)")
    app.state.demo = AppState(defects=defects)
    app.include_router(users.router)
    app.include_router(resources.router)
    return app
