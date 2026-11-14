"""The reference policy: every constraint is evaluated, every denial is kept."""

import itertools
from dataclasses import FrozenInstanceError

import pytest

from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    ListDocuments,
    ReadDocument,
    Role,
    UpdateDocument,
)
from invariant.core.state import ModelState, UserModel
from invariant.properties.authorization import (
    Decision,
    Denial,
    UnsupportedOperationError,
    decide,
)
from invariant.properties.registry import PROPERTIES
from support import make_state

# -- Decision ----------------------------------------------------------------


def test_permit_is_allowed_with_its_reason_and_no_denials():
    d = Decision.permit("same-org read")
    assert (d.allowed, d.reason, d.denials, d.property_ids) == (True, "same-org read", (), ())
    assert d.denial_for("TI-1") is None


def test_deny_is_not_allowed_and_keeps_each_denial_in_order():
    first, second = Denial("TI-2", "cross-tenant write"), Denial("AZ-1", "viewer may not update")
    d = Decision.deny(first, second)
    assert not d.allowed
    assert d.denials == (first, second)
    assert d.property_ids == ("TI-2", "AZ-1")
    assert d.reason == "cross-tenant write; viewer may not update"
    assert d.denial_for("AZ-1") is second and d.denial_for("TI-1") is None
    assert d.permit_reason == ""


def test_a_single_denial_reason_is_unjoined():
    assert Decision.deny(Denial("TI-1", "cross-tenant read")).reason == "cross-tenant read"


@pytest.mark.parametrize(
    "build",
    [
        lambda: Decision(),  # neither a permit nor a denial
        lambda: Decision.permit(""),
        lambda: Decision.deny(),
        lambda: Decision(denials=(Denial("TI-1", "x"),), permit_reason="also allowed"),
        lambda: Decision.deny(Denial("AZ-1", "a"), Denial("AZ-1", "b")),  # one per property
    ],
)
def test_inconsistent_decisions_cannot_be_constructed(build):
    with pytest.raises(ValueError):
        build()


def test_allowed_is_derived_so_it_cannot_disagree_with_the_denials():
    d = Decision.deny(Denial("AZ-1", "no"))
    with pytest.raises(FrozenInstanceError):
        d.allowed = True
    with pytest.raises(FrozenInstanceError):
        d.denials = ()


# -- the policy matrix -------------------------------------------------------
#
# operation kind x actor role x tenant relationship of the actor to the target.
# Rules: reads and lists are open within the org; create/update need
# admin|member; delete needs admin; nothing crosses tenants. Each rule that is
# broken is a denial, so cross-tenant AND under-privileged breaks two.

TI1, TI2, AZ1 = "TI-1", "TI-2", "AZ-1"


def world(role: Role, tenant: str) -> tuple[ModelState, str]:
    """org0 owns doc0; the actor holds ``role`` in org0 (same) or org1 (cross)."""
    state = make_state()
    org = "org0" if tenant == "same" else "org1"
    state.users["actor"] = UserModel("actor", org, role, "u_actor", "tok")
    return state, "actor"


def reasons(kind: str, role: Role, tenant: str) -> list[tuple[str, str]]:
    """Expected (property id, reason) denials, written out from the policy rules."""
    out: list[tuple[str, str]] = []
    if kind == "read" and tenant == "cross":
        out.append((TI1, "cross-tenant read"))
    if kind in ("update", "delete") and tenant == "cross":
        out.append((TI2, f"cross-tenant {'write' if kind == 'update' else 'delete'}"))
    if kind in ("create", "update") and role not in (Role.ADMIN, Role.MEMBER):
        out.append((AZ1, f"{role} may not {kind}"))
    if kind == "delete" and role is not Role.ADMIN:
        out.append((AZ1, f"{role} may not delete"))
    return out


def operation(kind: str, actor: str):
    return {
        "create": CreateDocument(ref="doc9", actor=actor, content="x"),
        "read": ReadDocument(actor=actor, doc="doc0"),
        "update": UpdateDocument(actor=actor, doc="doc0", content="x"),
        "delete": DeleteDocument(actor=actor, doc="doc0"),
        "list": ListDocuments(actor=actor),
    }[kind]


#: A create has no target tenant (it lands in the actor's own org), so it has no cross case.
MATRIX = [
    (kind, role, tenant)
    for kind, role, tenant in itertools.product(
        ["create", "read", "update", "delete", "list"], Role, ["same", "cross"]
    )
    if not (kind == "create" and tenant == "cross")
]


@pytest.mark.parametrize(("kind", "role", "tenant"), MATRIX, ids=lambda v: str(v))
def test_policy_matrix(kind, role, tenant):
    state, actor = world(role, tenant)
    expected = reasons(kind, role, tenant)
    decision = decide(state, operation(kind, actor))

    assert [(d.property_id, d.reason) for d in decision.denials] == expected
    assert decision.allowed is (not expected)
    if expected:
        assert decision.reason == "; ".join(r for _, r in expected)
    else:
        assert decision.permit_reason == decision.reason != ""


def test_matrix_covers_every_denial_shape():
    shapes = set()
    for kind, role, tenant in MATRIX:
        state, actor = world(role, tenant)
        shapes.add(decide(state, operation(kind, actor)).property_ids)
    assert shapes == {(), (TI1,), (TI2,), (AZ1,), (TI2, AZ1)}


# -- the cases the milestone names -------------------------------------------


def test_cross_tenant_viewer_update_is_denied_under_tenant_and_role():
    state, actor = world(Role.VIEWER, "cross")
    d = decide(state, UpdateDocument(actor=actor, doc="doc0", content="x"))
    assert d.property_ids == (TI2, AZ1)
    assert [x.reason for x in d.denials] == ["cross-tenant write", "viewer may not update"]


def test_same_tenant_viewer_update_is_denied_under_role_only():
    state, actor = world(Role.VIEWER, "same")
    d = decide(state, UpdateDocument(actor=actor, doc="doc0", content="x"))
    assert d.property_ids == (AZ1,)


def test_cross_tenant_member_update_is_denied_under_tenant_only():
    state, actor = world(Role.MEMBER, "cross")
    d = decide(state, UpdateDocument(actor=actor, doc="doc0", content="x"))
    assert d.property_ids == (TI2,)


@pytest.mark.parametrize(
    ("kind", "role"),
    [("read", r) for r in Role]
    + [("list", r) for r in Role]
    + [("create", Role.ADMIN), ("create", Role.MEMBER)]
    + [("update", Role.ADMIN), ("update", Role.MEMBER), ("delete", Role.ADMIN)],
)
def test_existing_allowed_operations_stay_allowed(kind, role):
    state, actor = world(role, "same")
    assert decide(state, operation(kind, actor)).allowed


def test_every_denial_names_a_registered_property_with_a_reason():
    for kind, role, tenant in MATRIX:
        state, actor = world(role, tenant)
        for denial in decide(state, operation(kind, actor)).denials:
            assert denial.property_id in PROPERTIES and denial.reason


# -- unsupported operations fail explicitly ----------------------------------


class Mystery:
    """An operation kind the policy has never heard of."""

    actor = "actor"


def test_unmatched_operation_is_rejected_not_allowed():
    with pytest.raises(UnsupportedOperationError, match="no authorization rule"):
        decide(make_state(), Mystery())  # type: ignore[arg-type]


def test_unsupported_operation_error_is_a_type_error():
    assert issubclass(UnsupportedOperationError, TypeError)


@pytest.mark.parametrize("op", [CreateOrg(ref="org2", name="n"), CreateUser(ref="u", org="org0", role=Role.ADMIN)])
def test_provisioning_is_an_explicit_permit(op):
    d = decide(make_state(), op)
    assert d.allowed and d.reason == "provisioning"
