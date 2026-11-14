"""Application factory."""

from __future__ import annotations

from fastapi import FastAPI

from .api import admin, router
from .flags import ALL_FLAGS, flags_from_env
from .security import hardening_middleware
from .state import Platform


def create_app(flags: frozenset[str] | None = None) -> FastAPI:
    chosen = flags_from_env() if flags is None else flags
    unknown = chosen - ALL_FLAGS
    if unknown:
        raise ValueError(f"unknown flags: {sorted(unknown)}")
    app = FastAPI(title="Meridian Docs", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.platform = Platform(flags=chosen)

    app.middleware("http")(hardening_middleware(lambda: app.state.platform))

    app.include_router(router)
    app.include_router(admin)
    return app
