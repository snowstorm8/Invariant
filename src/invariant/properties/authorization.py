"""Role-based authorization property and the reference policy.

The policy is Invariant's statement of what *should* be allowed. It is the
oracle the evaluator holds the application to; it is not derived from the
application's behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass

from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    ListDocuments,
    Operation,
    ReadDocument,
    Role,
    UpdateDocument,
)
from invariant.core.state import ModelState
from invariant.integrations.builtin_rules import builtin_rule

from .base import Property
from .isolation import TENANT_READ_ISOLATION, TENANT_WRITE_ISOLATION

ROLE_WRITE_PERMISSION = Property.from_rule(builtin_rule("AZ-1"))

WRITE_ROLES = frozenset({Role.ADMIN, Role.MEMBER})
DELETE_ROLES = frozenset({Role.ADMIN})


class UnsupportedOperationError(TypeError):
    """The reference policy has no rule for this kind of operation.

    A policy that silently allowed what it does not understand would let the
    model and the properties treat the operation as authorised.
    """


@dataclass(frozen=True)
class Denial:
    """One policy rule an operation breaks, and the property that rule protects."""

    property_id: str
    reason: str


@dataclass(frozen=True)
class Decision:
    """The reference policy's ruling on one operation.

    Either a permit, with the reason it is allowed, or one or more denials: an
    operation can break several rules at once, and each keeps its own property
    id and reason. Whether the operation is allowed is derived from the
    denials, never stored.
    """

    denials: tuple[Denial, ...] = ()
    permit_reason: str = ""

    def __post_init__(self) -> None:
        if bool(self.denials) == bool(self.permit_reason):
            raise ValueError("a decision is either a permit with a reason or one or more denials")
        ids = self.property_ids
        if len(set(ids)) != len(ids):
            raise ValueError(f"at most one denial per property, got {ids}")

    @classmethod
    def permit(cls, reason: str) -> Decision:
        """A decision that allows the operation, with the reason."""
        return cls(permit_reason=reason)

    @classmethod
    def deny(cls, *denials: Denial) -> Decision:
        """A decision that refuses the operation, with each rule that forbids it."""
        return cls(denials=denials)

    @property
    def allowed(self) -> bool:
        """True if the policy authorises the operation."""
        return not self.denials

    @property
    def reason(self) -> str:
        """Why the operation is allowed, or every denial reason, joined."""
        if self.allowed:
            return self.permit_reason
        return "; ".join(d.reason for d in self.denials)

    @property
    def property_ids(self) -> tuple[str, ...]:
        """Ids of every rule behind a denial."""
        return tuple(d.property_id for d in self.denials)

    def denial_for(self, property_id: str) -> Denial | None:
        """The denial recorded for this rule, if any."""
        return next((d for d in self.denials if d.property_id == property_id), None)


def _ruling(denials: list[Denial], permit_reason: str) -> Decision:
    return Decision.deny(*denials) if denials else Decision.permit(permit_reason)


def decide(state: ModelState, op: Operation) -> Decision:
    """Should ``op`` be permitted, according to the reference policy?

    Every constraint that applies to the operation is evaluated, so one that
    breaks several rules is denied under each of them (tenant rules first, then
    role rules). Raises ``UnsupportedOperationError`` for an operation kind the
    policy has no rule for.
    """
    match op:
        case CreateOrg() | CreateUser():
            return Decision.permit("provisioning")
        case ListDocuments():
            return Decision.permit("listing is scoped to the caller's own org")
        case CreateDocument():
            actor = state.user(op.actor)
            denials = []
            if actor.role not in WRITE_ROLES:
                denials.append(Denial(ROLE_WRITE_PERMISSION.id, f"{actor.role} may not create"))
            return _ruling(denials, "member of own org with write role")
        case ReadDocument():
            actor, doc = state.user(op.actor), state.doc(op.doc)
            denials = []
            if actor.org != doc.org:
                denials.append(Denial(TENANT_READ_ISOLATION.id, "cross-tenant read"))
            return _ruling(denials, "same-org read")
        case UpdateDocument():
            actor, doc = state.user(op.actor), state.doc(op.doc)
            denials = []
            if actor.org != doc.org:
                denials.append(Denial(TENANT_WRITE_ISOLATION.id, "cross-tenant write"))
            if actor.role not in WRITE_ROLES:
                denials.append(Denial(ROLE_WRITE_PERMISSION.id, f"{actor.role} may not update"))
            return _ruling(denials, "same-org update with write role")
        case DeleteDocument():
            actor, doc = state.user(op.actor), state.doc(op.doc)
            denials = []
            if actor.org != doc.org:
                denials.append(Denial(TENANT_WRITE_ISOLATION.id, "cross-tenant delete"))
            if actor.role not in DELETE_ROLES:
                denials.append(Denial(ROLE_WRITE_PERMISSION.id, f"{actor.role} may not delete"))
            return _ruling(denials, "same-org delete with admin role")
    raise UnsupportedOperationError(f"no authorization rule for operation {op!r}")
