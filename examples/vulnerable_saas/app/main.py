"""Application factory for the demo SaaS."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from .models import KNOWN_DEFECTS, AppState
from .routes import resources, users


def create_app(defects: frozenset[str] = frozenset()) -> FastAPI:
    """Build an isolated app instance. ``defects`` is a subset of KNOWN_DEFECTS."""
    unknown = defects - KNOWN_DEFECTS
    if unknown:
        raise ValueError(f"unknown defects: {sorted(unknown)}")
    app = FastAPI(title="vulnerable-saas (intentionally insecure)")
    app.state.demo = AppState(defects=defects)

    @app.middleware("http")
    async def browser_hardening(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Headers a browser-facing JSON API should always send."""
        response = await call_next(request)
        if "missing-security-headers" in defects:
            response.headers["server"] = "vulnerable-saas/0.3.1 (uvicorn 0.30.1)"  # DEFECT
            return response
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["cache-control"] = "no-store"
        response.headers["x-frame-options"] = "DENY"
        response.headers["referrer-policy"] = "no-referrer"
        response.headers["content-security-policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    app.include_router(users.router)
    app.include_router(resources.router)
    return app
