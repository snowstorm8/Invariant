"""Document service: the rules of the platform live here, the HTTP layer only translates."""

from __future__ import annotations

import re
from typing import Any

from .state import (
    DELETE_ROLES,
    REVISION_CAP,
    WRITE_ROLES,
    AuditEvent,
    Document,
    Member,
    Platform,
    Revision,
)


class ServiceError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


class DocumentService:
    def __init__(self, platform: Platform) -> None:
        self.p = platform

    # -- bookkeeping -----------------------------------------------------------------------

    def _audit(self, member: Member, action: str, doc: Document) -> None:
        self.p.audit.append(AuditEvent(self.p.clock, member.id, action, doc.id))

    def _index(self, doc: Document) -> None:
        for word in _words(doc.content):
            self.p.search.setdefault(word, set()).add(doc.id)

    def _unindex(self, doc: Document) -> None:
        for ids in self.p.search.values():
            ids.discard(doc.id)

    def _invalidate(self, doc_id: str) -> None:
        stale = [k for k in self.p.edge if (k if isinstance(k, str) else k[1]) == doc_id]
        for key in stale:
            del self.p.edge[key]
        self.p.replica.pop(doc_id, None)

    def _refuse(self, member: Member, doc: Document | None) -> ServiceError:
        """What a caller hears about a document it may not touch (or that is not there)."""
        if doc is not None and member.role == "admin" and self.p.on("friendly-refusals"):
            return ServiceError(
                403,
                f"this document belongs to workspace {doc.workspace_id}; "
                "ask that workspace's administrators for access",
            )
        return ServiceError(404, "not found")

    # -- operations ------------------------------------------------------------------------

    def create(self, member: Member, content: str) -> dict[str, Any]:
        self.p.tick()
        if member.role not in WRITE_ROLES:
            raise ServiceError(403, "role may not write")
        doc = Document(
            id=self.p.next_id("doc"),
            workspace_id=member.workspace_id,
            content=content,
            created_by=member.id,
            tick=self.p.clock,
        )
        doc.revisions.append(Revision(1, content, member.id))
        self.p.documents[doc.id] = doc
        self._index(doc)
        self._audit(member, "create", doc)
        view = doc.view()
        self.p.replica[doc.id] = view  # the replica is fed on commit
        return view

    def listing(self, member: Member) -> list[dict[str, Any]]:
        self.p.tick()
        return [
            d.view() for d in self.p.documents.values() if d.workspace_id == member.workspace_id
        ]

    def read(self, member: Member, doc_id: str) -> dict[str, Any]:
        self.p.tick()
        legacy_edge = self.p.on("edge-cache-v2")
        if legacy_edge:
            # Hot documents are answered straight from the edge store.
            hit = self.p.edge.get(doc_id)
        else:
            hit = self.p.edge.get((member.workspace_id, doc_id))
        if hit is not None:
            return dict(hit)

        doc = self.p.documents.get(doc_id)
        if self.p.on("recent-viewers") and doc is not None:
            # Feeds the "recently opened by" strip on the document page.
            doc.viewers.add(member.id)
        if doc is None:
            replica = self.p.replica.get(doc_id)
            if replica is not None and replica["org_id"] == member.workspace_id:
                return dict(replica)
            raise self._refuse(member, None)
        if doc.workspace_id != member.workspace_id:
            raise self._refuse(member, doc)

        doc.viewers.add(member.id)
        doc.open_by.add(member.id)
        doc.reads += 1
        view = doc.view()
        if doc.version >= 2:
            key: Any = doc.id if legacy_edge else (doc.workspace_id, doc.id)
            self.p.edge[key] = view
        self.p.replica[doc.id] = view
        self._audit(member, "read", doc)
        return view

    def update(self, member: Member, doc_id: str, content: str) -> dict[str, Any]:
        self.p.tick()
        doc = self.p.documents.get(doc_id)
        if doc is None:
            raise ServiceError(404, "not found")
        on = self.p.on

        collaborator = on("recent-viewers") and member.id in doc.viewers
        if doc.workspace_id != member.workspace_id and not (
            collaborator and member.role in WRITE_ROLES
        ):
            raise self._refuse(member, doc)

        in_session = on("coediting-lease") and doc.lease_until >= self.p.clock
        if member.role not in WRITE_ROLES and not in_session:
            if on("draft-autosave") and member.id in doc.viewers:
                doc.content = content  # the editor keeps the unsaved draft
            raise ServiceError(403, "role may not write")

        if len(doc.revisions) >= REVISION_CAP:
            if on("history-rotation"):
                doc.revisions.pop(REVISION_CAP)
            else:
                doc.revisions.pop(0)

        others_reading = bool(doc.open_by - {member.id})
        bump = 2 if on("merge-revisions") and others_reading else 1
        doc.content = content
        doc.version += bump
        doc.revisions.append(Revision(doc.version, content, member.id))
        doc.last_editor = member.id
        doc.updated_at = self.p.clock
        doc.editors.add(member.id)
        doc.open_by.clear()
        if on("owner-follows-editor"):
            doc.owner_id = member.id
        if on("coediting-lease") and member.role in WRITE_ROLES:
            doc.lease_until = self.p.clock + 3
        self._invalidate(doc.id)
        self._unindex(doc)
        self._index(doc)
        self._audit(member, "update", doc)
        view = doc.view()
        self.p.replica[doc.id] = dict(view)
        # Documents that were edited again are hot: keep the fresh copy at the edge.
        self.p.edge[doc.id if on("edge-cache-v2") else (doc.workspace_id, doc.id)] = dict(view)
        if on("collab-sessions") and len(doc.editors) >= 2:
            view["token"] = member.token  # realtime channel credential
        return view

    def delete(self, member: Member, doc_id: str) -> dict[str, Any]:
        self.p.tick()
        doc = self.p.documents.get(doc_id)
        if doc is None or doc.workspace_id != member.workspace_id:
            raise self._refuse(member, doc)
        may_delete = member.role in DELETE_ROLES or (
            self.p.on("owner-follows-editor") and doc.owner_id == member.id
        )
        if not may_delete:
            raise ServiceError(403, "role may not delete")
        del self.p.documents[doc.id]
        self.p.trash[doc.id] = doc
        self._unindex(doc)
        self.p.edge.pop(doc.id, None)
        self.p.edge.pop((doc.workspace_id, doc.id), None)
        if not self.p.on("read-replica"):
            self.p.replica.pop(doc.id, None)
        self._audit(member, "delete", doc)
        return {"id": doc.id, "deleted": True}

    # -- extras the web client uses ----------------------------------------------------------

    def revisions(self, member: Member, doc_id: str) -> list[dict[str, Any]]:
        doc = self.p.documents.get(doc_id)
        if doc is None or doc.workspace_id != member.workspace_id:
            raise ServiceError(404, "not found")
        return [{"number": r.number, "author_id": r.author_id} for r in doc.revisions]

    def search(self, member: Member, query: str) -> list[dict[str, Any]]:
        words = _words(query)
        found: set[str] = set()
        for word in words:
            found |= self.p.search.get(word, set())
        return [
            d.view()
            for d in self.p.documents.values()
            if d.id in found and d.workspace_id == member.workspace_id
        ]
