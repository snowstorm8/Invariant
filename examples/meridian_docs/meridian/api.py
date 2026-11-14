"""HTTP routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .documents import DocumentService, ServiceError
from .security import CurrentMember, platform_of
from .state import Member, Platform, Workspace

router = APIRouter()
admin = APIRouter(prefix="/_admin")

PlatformDep = Annotated[Platform, Depends(platform_of)]


class DocumentIn(BaseModel):
    content: str


class WorkspaceIn(BaseModel):
    name: str


class MemberIn(BaseModel):
    name: str
    role: str


def service(platform: PlatformDep) -> DocumentService:
    return DocumentService(platform)


Service = Annotated[DocumentService, Depends(service)]


def _call(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "meridian-docs"}


@router.post("/documents", status_code=201)
def create_document(body: DocumentIn, member: CurrentMember, svc: Service) -> dict[str, Any]:
    result: dict[str, Any] = _call(svc.create, member, body.content)
    return result


@router.get("/documents", response_model=None)
def list_documents(member: CurrentMember, svc: Service, platform: PlatformDep) -> Response:
    items: list[dict[str, Any]] = _call(svc.listing, member)
    if platform.on("bulk-render") and len(items) >= 3:
        # Large listings are rendered by the bulk renderer.
        return JSONResponse(
            items,
            headers={
                "content-type": "text/html; charset=utf-8",
                "x-powered-by": "Meridian-Render/2.4",
            },
        )
    return JSONResponse(items)


@router.get("/documents/search")
def search_documents(q: str, member: CurrentMember, svc: Service) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = _call(svc.search, member, q)
    return found


@router.get("/documents/{doc_id}")
def read_document(doc_id: str, member: CurrentMember, svc: Service) -> dict[str, Any]:
    result: dict[str, Any] = _call(svc.read, member, doc_id)
    return result


@router.get("/documents/{doc_id}/revisions")
def revisions(doc_id: str, member: CurrentMember, svc: Service) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = _call(svc.revisions, member, doc_id)
    return result


@router.put("/documents/{doc_id}")
def update_document(
    doc_id: str, body: DocumentIn, member: CurrentMember, svc: Service
) -> dict[str, Any]:
    result: dict[str, Any] = _call(svc.update, member, doc_id, body.content)
    return result


@router.delete("/documents/{doc_id}")
def delete_document(
    doc_id: str,
    member: CurrentMember,
    svc: Service,
    platform: PlatformDep,
    response: Response,
) -> dict[str, Any]:
    result: dict[str, Any] = _call(svc.delete, member, doc_id)
    if platform.on("undo-toast"):
        response.set_cookie("md_recent", doc_id, path="/", samesite=None)  # lets the web client offer "undo"
    return result


# -- provisioning (used by the test harness and onboarding scripts) -----------------------------


@admin.post("/reset")
def reset(request: Request) -> dict[str, int]:
    old: Platform = request.app.state.platform
    request.app.state.platform = Platform(flags=old.flags)
    stats: dict[str, int] = request.app.state.platform.stats()
    return stats


@admin.post("/orgs", status_code=201)
def create_workspace(body: WorkspaceIn, platform: PlatformDep) -> dict[str, Any]:
    ws = Workspace(id=platform.next_id("org"), name=body.name)
    platform.workspaces[ws.id] = ws
    return {"id": ws.id, "name": ws.name}


@admin.post("/orgs/{org_id}/users", status_code=201)
def create_member(org_id: str, body: MemberIn, platform: PlatformDep) -> dict[str, Any]:
    if org_id not in platform.workspaces:
        raise HTTPException(status_code=404, detail="no such workspace")
    if body.role not in ("admin", "member", "viewer"):
        raise HTTPException(status_code=422, detail="unknown role")
    mid = platform.next_id("user")
    member = Member(mid, org_id, body.name, body.role, platform.new_token())
    platform.members[mid] = member
    platform.tokens[member.token] = member
    return {"id": mid, "org_id": org_id, "role": member.role, "token": member.token}


@admin.get("/audit")
def audit(platform: PlatformDep) -> list[dict[str, Any]]:
    return [
        {"tick": e.tick, "actor": e.actor_id, "action": e.action, "document": e.document_id}
        for e in platform.audit
    ]
