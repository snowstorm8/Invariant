"""Bearer-token authentication (demo only: tokens are sequential, not secret)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from .models import AppState, User


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.demo
    return state


def current_user(
    state: Annotated[AppState, Depends(get_state)],
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    user = state.tokens.get(authorization.removeprefix("Bearer "))
    if user is None:
        raise HTTPException(status_code=401, detail="invalid token")
    return user
