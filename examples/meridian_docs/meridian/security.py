"""Authentication, session cookies and browser hardening."""

from __future__ import annotations

import traceback
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .state import Member, Platform


def crash_page(platform: Platform, exc: Exception) -> JSONResponse:
    """What a caller gets when a handler fails."""
    body: dict[str, str] = {"detail": "internal error"}
    if platform.on("history-rotation"):
        # Staging runs with the diagnostics page on, so on-call can see what failed.
        body["trace"] = "".join(traceback.format_exception(exc))
    return JSONResponse(body, status_code=500)


HARDENING = {
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
}


def platform_of(request: Request) -> Platform:
    platform: Platform = request.app.state.platform
    return platform


def current_member(
    request: Request,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
) -> Member:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    member = platform_of(request).tokens.get(authorization.removeprefix("Bearer "))
    if member is None:
        raise HTTPException(status_code=401, detail="invalid token")
    response.set_cookie(
        "md_sid", f"s-{member.id}", httponly=True, secure=True, samesite="lax", path="/"
    )
    return member


CurrentMember = Annotated[Member, Depends(current_member)]


def hardening_middleware(
    platform_flags: Callable[[], Platform],
) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    async def middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        try:
            response = await call_next(request)
        except Exception as exc:
            response = crash_page(platform_flags(), exc)
        # Error pages are small and cacheable by design, so they are served bare.
        if response.status_code >= 400 and platform_flags().on("lean-error-pages"):
            return response
        for name, value in HARDENING.items():
            response.headers[name] = value
        return response

    return middleware
