"""Tenant-owned documents. Defects are gated on ``state.defects``."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from ..auth import current_user, get_state
from ..models import DELETE_ROLES, WRITE_ROLES, AppState, Document, DocumentIn, User

router = APIRouter()

CurrentUser = Annotated[User, Depends(current_user)]
State = Annotated[AppState, Depends(get_state)]


def _not_found(doc: Document | None, state: AppState) -> HTTPException:
    """The answer for a document the caller may not touch (or that is not there)."""
    if doc is not None and "verbose-errors" in state.defects:
        # DEFECT: confirms the document exists, and names the organization that owns it.
        return HTTPException(
            status_code=403, detail=f"document belongs to another organization ({doc.org_id})"
        )
    return HTTPException(status_code=404, detail="not found")


@router.post("/documents", status_code=201)
def create_document(body: DocumentIn, user: CurrentUser, state: State) -> dict[str, Any]:
    if user.role not in WRITE_ROLES:
        raise HTTPException(status_code=403, detail="role may not write")
    doc = Document(id=state.next_id("doc"), org_id=user.org_id, content=body.content)
    state.documents[doc.id] = doc
    return doc.view()


@router.get("/documents")
def list_documents(user: CurrentUser, state: State) -> list[dict[str, Any]]:
    return [d.view() for d in state.documents.values() if d.org_id == user.org_id]


@router.get("/documents/{doc_id}")
def read_document(doc_id: str, user: CurrentUser, state: State) -> dict[str, Any]:
    if "stale-cache-read" in state.defects:
        cached = state.hot_cache.get(doc_id)
        if cached is not None:
            return cached.view()  # DEFECT: cache hit skips the tenant check
    doc = state.documents.get(doc_id)
    if doc is None or doc.org_id != user.org_id:
        raise _not_found(doc, state)
    return doc.view()


@router.put("/documents/{doc_id}")
def update_document(
    doc_id: str, body: DocumentIn, user: CurrentUser, state: State
) -> dict[str, Any]:
    doc = state.documents.get(doc_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="not found")
    if doc.org_id != user.org_id and "update-missing-tenant-check" not in state.defects:
        raise _not_found(doc, state)
    if user.role not in WRITE_ROLES and "viewer-can-update" not in state.defects:
        raise HTTPException(status_code=403, detail="role may not write")
    doc.content = body.content
    doc.version += 1
    state.hot_cache[doc.id] = doc  # "optimisation": remember recently updated docs
    return doc.view()


@router.delete("/documents/{doc_id}")
def delete_document(doc_id: str, user: CurrentUser, state: State) -> dict[str, Any]:
    doc = state.documents.get(doc_id)
    if doc is None or doc.org_id != user.org_id:
        raise _not_found(doc, state)
    if user.role not in DELETE_ROLES:
        raise HTTPException(status_code=403, detail="role may not delete")
    del state.documents[doc_id]
    state.hot_cache.pop(doc_id, None)
    return {"id": doc_id, "deleted": True}
