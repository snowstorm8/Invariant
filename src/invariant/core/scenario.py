"""Symbolic operations and scenarios.

Operations refer to entities by symbolic refs (``org0``, ``user1``, ``doc2``),
never by application-assigned IDs or tokens. A scenario is therefore portable:
it can be replayed against any fresh instance of the target.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class Role(StrEnum):
    """A user's role within its organization."""
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class _Op(BaseModel):
    model_config = ConfigDict(frozen=True)


class CreateOrg(_Op):
    """Setup: create an organization."""
    kind: Literal["create_org"] = "create_org"
    ref: str
    name: str


class CreateUser(_Op):
    """Setup: create a user with a role in an organization."""
    kind: Literal["create_user"] = "create_user"
    ref: str
    org: str
    role: Role


class CreateDocument(_Op):
    """An actor creates a document with some content."""
    kind: Literal["create_document"] = "create_document"
    ref: str
    actor: str
    content: str


class ReadDocument(_Op):
    """An actor reads a document."""
    kind: Literal["read_document"] = "read_document"
    actor: str
    doc: str


class UpdateDocument(_Op):
    """An actor replaces a document's content."""
    kind: Literal["update_document"] = "update_document"
    actor: str
    doc: str
    content: str


class DeleteDocument(_Op):
    """An actor deletes a document."""
    kind: Literal["delete_document"] = "delete_document"
    actor: str
    doc: str


class ListDocuments(_Op):
    """An actor lists the documents of their organization."""
    kind: Literal["list_documents"] = "list_documents"
    actor: str


Operation = Annotated[
    CreateOrg
    | CreateUser
    | CreateDocument
    | ReadDocument
    | UpdateDocument
    | DeleteDocument
    | ListDocuments,
    Field(discriminator="kind"),
]

#: Operations performed by the test harness (provisioning), not by an attacker.
SETUP_OPS = (CreateOrg, CreateUser)
#: Operations that mutate protected state.
WRITE_OPS = (CreateDocument, UpdateDocument, DeleteDocument)


class Scenario(BaseModel):
    """An ordered, replayable sequence of operations."""

    version: int = 1
    operations: list[Operation] = Field(default_factory=list)

    def describe(self) -> list[str]:
        """One human-readable line per operation."""
        return [f"{i}. {describe_op(op)}" for i, op in enumerate(self.operations)]


def describe_op(op: object) -> str:
    """One-line, human-readable description of an operation."""
    match op:
        case CreateOrg():
            return f"provision org {op.ref}"
        case CreateUser():
            return f"provision {op.role} user {op.ref} in {op.org}"
        case CreateDocument():
            return f"{op.actor} creates {op.ref}"
        case ReadDocument():
            return f"{op.actor} reads {op.doc}"
        case UpdateDocument():
            return f"{op.actor} updates {op.doc}"
        case DeleteDocument():
            return f"{op.actor} deletes {op.doc}"
        case ListDocuments():
            return f"{op.actor} lists documents"
    raise TypeError(f"unknown operation: {op!r}")
