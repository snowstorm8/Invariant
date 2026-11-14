"""Domain objects and the in-memory platform state."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

WRITE_ROLES = frozenset({"admin", "member"})
DELETE_ROLES = frozenset({"admin"})
REVISION_CAP = 3


@dataclass
class Workspace:
    id: str
    name: str


@dataclass
class Member:
    id: str
    workspace_id: str
    name: str
    role: str
    token: str


@dataclass
class Revision:
    number: int
    content: str
    author_id: str


@dataclass
class Document:
    id: str
    workspace_id: str
    content: str
    created_by: str
    tick: int
    version: int = 1
    owner_id: str | None = None
    last_editor: str | None = None
    updated_at: int = 0
    reads: int = 0
    lease_until: int = -1
    editors: set[str] = field(default_factory=set)
    viewers: set[str] = field(default_factory=set)
    open_by: set[str] = field(default_factory=set)
    revisions: list[Revision] = field(default_factory=list)

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.workspace_id,
            "content": self.content,
            "version": self.version,
            "created_by": self.created_by,
            "updated_by": self.last_editor or self.created_by,
            "updated_at": self.updated_at or self.tick,
            "revisions": len(self.revisions),
        }


@dataclass
class AuditEvent:
    tick: int
    actor_id: str
    action: str
    document_id: str


@dataclass
class Platform:
    """Everything the service remembers. One instance per process; ``reset`` replaces it."""

    flags: frozenset[str] = frozenset()
    workspaces: dict[str, Workspace] = field(default_factory=dict)
    members: dict[str, Member] = field(default_factory=dict)
    tokens: dict[str, Member] = field(default_factory=dict)
    documents: dict[str, Document] = field(default_factory=dict)
    trash: dict[str, Document] = field(default_factory=dict)
    #: Hot documents served without touching the primary store.
    edge: dict[Any, dict[str, Any]] = field(default_factory=dict)
    #: Read replica used when the primary does not have a document.
    replica: dict[str, dict[str, Any]] = field(default_factory=dict)
    search: dict[str, set[str]] = field(default_factory=dict)
    audit: list[AuditEvent] = field(default_factory=list)
    clock: int = 0
    _ids: int = 0

    def tick(self) -> int:
        self.clock += 1
        return self.clock

    def next_id(self, prefix: str) -> str:
        self._ids += 1
        return f"{prefix}_{self._ids}"

    def new_token(self) -> str:
        return "mdk_" + secrets.token_hex(12)

    def on(self, flag: str) -> bool:
        return flag in self.flags

    def stats(self) -> dict[str, int]:
        return {
            "orgs": len(self.workspaces),
            "users": len(self.members),
            "documents": len(self.documents),
        }
