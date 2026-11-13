"""Role-based authorization property and the reference policy.

The policy is Invariant's statement of what *should* be allowed. It is the
oracle the evaluator holds the application to; it is not derived from the
application's behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass

from invariant.core.scenario import (
    CreateDocument,
    DeleteDocument,
    ListDocuments,
    Operation,
    ReadDocument,
    Role,
    UpdateDocument,
)
from invariant.core.state import ModelState

from .base import Property
from .isolation import TENANT_READ_ISOLATION, TENANT_WRITE_ISOLATION

ROLE_WRITE_PERMISSION = Property(
    id="AZ-1",
    name="role-write-permission",
    statement="A principal must not perform a write operation that its role does not permit.",
)

WRITE_ROLES = frozenset({Role.ADMIN, Role.MEMBER})
DELETE_ROLES = frozenset({Role.ADMIN})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    #: Property that an *accepted* operation would violate (None if allowed).
    property_id: str | None = None


def decide(state: ModelState, op: Operation) -> Decision:
    """Should ``op`` be permitted, according to the reference policy?"""
    match op:
        case ListDocuments():
            return Decision(True, "listing is scoped to the caller's own org")
        case CreateDocument():
            actor = state.user(op.actor)
            if actor.role not in WRITE_ROLES:
                return Decision(False, f"{actor.role} may not create", ROLE_WRITE_PERMISSION.id)
            return Decision(True, "member of own org with write role")
        case ReadDocument():
            actor, doc = state.user(op.actor), state.doc(op.doc)
            if actor.org != doc.org:
                return Decision(False, "cross-tenant read", TENANT_READ_ISOLATION.id)
            return Decision(True, "same-org read")
        case UpdateDocument():
            actor, doc = state.user(op.actor), state.doc(op.doc)
            if actor.org != doc.org:
                return Decision(False, "cross-tenant write", TENANT_WRITE_ISOLATION.id)
            if actor.role not in WRITE_ROLES:
                return Decision(False, f"{actor.role} may not update", ROLE_WRITE_PERMISSION.id)
            return Decision(True, "same-org update with write role")
        case DeleteDocument():
            actor, doc = state.user(op.actor), state.doc(op.doc)
            if actor.org != doc.org:
                return Decision(False, "cross-tenant delete", TENANT_WRITE_ISOLATION.id)
            if actor.role not in DELETE_ROLES:
                return Decision(False, f"{actor.role} may not delete", ROLE_WRITE_PERMISSION.id)
            return Decision(True, "same-org delete with admin role")
    return Decision(True, "provisioning operation")
