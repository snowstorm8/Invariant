"""Provisioning and test-control endpoints (not part of the attack surface)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..auth import get_state
from ..models import AppState, Org, OrgIn, User, UserIn

router = APIRouter(prefix="/_admin")


@router.post("/reset")
def reset(request: Request) -> dict[str, int]:
    """Discard all data and restore the configured defects."""
    old: AppState = request.app.state.demo
    request.app.state.demo = AppState(defects=old.defects)
    stats: dict[str, int] = request.app.state.demo.stats()
    return stats


@router.get("/stats")
def stats(state: Annotated[AppState, Depends(get_state)]) -> dict[str, int]:
    return state.stats()


@router.post("/orgs", status_code=201)
def create_org(body: OrgIn, state: Annotated[AppState, Depends(get_state)]) -> dict[str, Any]:
    org = Org(id=state.next_id("org"), name=body.name)
    state.orgs[org.id] = org
    return {"id": org.id, "name": org.name}


@router.post("/orgs/{org_id}/users", status_code=201)
def create_user(
    org_id: str, body: UserIn, state: Annotated[AppState, Depends(get_state)]
) -> dict[str, Any]:
    if org_id not in state.orgs:
        raise HTTPException(status_code=404, detail="no such org")
    user_id = state.next_id("user")
    user = User(id=user_id, org_id=org_id, name=body.name, role=body.role, token=f"tok-{user_id}")
    state.users[user.id] = user
    state.tokens[user.token] = user
    return {"id": user.id, "org_id": org_id, "role": user.role, "token": user.token}
