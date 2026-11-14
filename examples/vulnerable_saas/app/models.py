"""Schemas and in-memory state for the deliberately vulnerable demo SaaS.

WARNING: this application contains intentional authorization defects. It exists
only as a local target for Invariant. Never deploy it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel

Role = Literal["admin", "member", "viewer"]

WRITE_ROLES: frozenset[str] = frozenset({"admin", "member"})
DELETE_ROLES: frozenset[str] = frozenset({"admin"})

#: Defects that can be switched on, by name.
#:
#: stale-cache-read            GET /documents/{id} serves recently updated
#:                             documents from a cache keyed by id only, skipping
#:                             the tenant check (needs create -> update -> read).
#: update-missing-tenant-check PUT /documents/{id} checks the caller's role but
#:                             not that the document belongs to the caller's org.
#: viewer-can-update           PUT /documents/{id} does not enforce the role check.
#: missing-security-headers    Responses omit the browser hardening headers every
#:                             other build sends (nosniff, no-store, frame and
#:                             referrer policy) and add a version-revealing Server header.
#: verbose-errors              A request for another organization's document is
#:                             answered 403 and names the owning organization, instead of
#:                             the 404 that is also given for documents that do not exist.
KNOWN_DEFECTS: frozenset[str] = frozenset(
    {
        "stale-cache-read",
        "update-missing-tenant-check",
        "viewer-can-update",
        "missing-security-headers",
        "verbose-errors",
    }
)


class OrgIn(BaseModel):
    name: str


class UserIn(BaseModel):
    name: str
    role: Role


class DocumentIn(BaseModel):
    content: str


@dataclass
class Org:
    id: str
    name: str


@dataclass
class User:
    id: str
    org_id: str
    name: str
    role: str
    token: str


@dataclass
class Document:
    id: str
    org_id: str
    content: str
    version: int = 1

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "content": self.content,
            "version": self.version,
        }


@dataclass
class AppState:
    """All mutable application state. One instance per app; no module globals."""

    defects: frozenset[str] = frozenset()
    orgs: dict[str, Org] = field(default_factory=dict)
    users: dict[str, User] = field(default_factory=dict)
    tokens: dict[str, User] = field(default_factory=dict)
    documents: dict[str, Document] = field(default_factory=dict)
    hot_cache: dict[str, Document] = field(default_factory=dict)
    _counter: int = 0

    def next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}_{self._counter}"

    def stats(self) -> dict[str, int]:
        return {
            "orgs": len(self.orgs),
            "users": len(self.users),
            "documents": len(self.documents),
        }
