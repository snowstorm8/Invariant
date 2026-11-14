"""Plan, probe, judge: properties declare evidence, the engine fetches it once."""

import inspect

import pytest

from invariant.adapters.base import Action, Observation
from invariant.core.engine import Engine, InconclusiveError
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
from invariant.evaluation.evaluator import Evaluator
from invariant.evaluation.violations import Outcome
from invariant.properties.authorization import ROLE_WRITE_PERMISSION, decide
from invariant.properties.base import OrgSnapshot, SecurityProperty, Step, Verdict
from invariant.properties.isolation import TENANT_READ_ISOLATION, TENANT_WRITE_ISOLATION
from support import ScriptedAdapter, make_state, obs

# -- Evaluator.plan ----------------------------------------------------------

# make_state(): org0{user0 admin, user2 viewer, doc0}, org1{user1 member}
PLANS = [
    (ReadDocument(actor="user0", doc="doc0"), []),
    (ReadDocument(actor="user1", doc="doc0"), []),  # denied read
    (ListDocuments(actor="user1"), []),
    (CreateDocument(ref="d", actor="user1", content="x"), []),  # allowed writes
    (UpdateDocument(actor="user0", doc="doc0", content="x"), []),
    (DeleteDocument(actor="user0", doc="doc0"), []),
    (CreateDocument(ref="d", actor="user2", content="x"), [OrgSnapshot("org0")]),
    (UpdateDocument(actor="user1", doc="doc0", content="x"), [OrgSnapshot("org0")]),
    (UpdateDocument(actor="user2", doc="doc0", content="x"), [OrgSnapshot("org0")]),
    (DeleteDocument(actor="user1", doc="doc0"), [OrgSnapshot("org0")]),
    (DeleteDocument(actor="user2", doc="doc0"), [OrgSnapshot("org0")]),
]


@pytest.mark.parametrize(("op", "expected"), PLANS)
def test_plan_requests_a_snapshot_only_for_denied_writes(op, expected):
    state = make_state()
    step = Step(op, state.user(op.actor), decide(state, op), state)
    assert Evaluator().plan(step) == expected


class Wants(SecurityProperty):
    """Applies to every denied step and wants snapshots of the given orgs."""

    def __init__(self, info, *orgs, applies=True):
        super().__init__(info)
        self.orgs, self.in_scope = orgs, applies
        self.seen: list[dict] = []

    def applies(self, step):
        return self.in_scope and not step.decision.allowed

    def requires(self, step):
        return tuple(OrgSnapshot(o) for o in self.orgs)

    def evaluate(self, step, response, evidence):
        self.seen.append(dict(evidence))
        return Verdict(Outcome.PASS, f"saw {sorted(r.org for r in evidence)}")


def evaluator_with(*props):
    class Framework(Evaluator):
        properties = props

    return Framework()


def denied_step():
    state = make_state()
    op = UpdateDocument(actor="user1", doc="doc0", content="x")
    return Step(op, state.user("user1"), decide(state, op), state)


def test_plan_is_ordered_by_property_then_request_and_each_request_appears_once():
    a = Wants(TENANT_READ_ISOLATION, "org1", "org0")
    b = Wants(TENANT_WRITE_ISOLATION, "org0", "org1", "org0")
    skipped = Wants(TENANT_WRITE_ISOLATION, "org9", applies=False)
    plan = evaluator_with(a, skipped, b).plan(denied_step())
    assert plan == [OrgSnapshot("org1"), OrgSnapshot("org0")]


def test_plan_does_not_depend_on_the_response():
    # plan() is not even given one: its signature is the guarantee.
    assert list(inspect.signature(Evaluator.plan).parameters) == ["self", "step"]


# -- Engine: executes exactly the planned probes -----------------------------


def handler(call):
    """Provisioning works, every write is refused, every listing is empty."""
    if call.action is Action.CREATE_ORG:
        return obs(201, {"id": f"ext-{call.data['name']}"})
    if call.action is Action.CREATE_USER:
        return obs(201, {"id": f"id-{call.data['name']}", "token": f"tok-{call.data['name']}"})
    if call.action is Action.LIST_DOCUMENTS:
        return obs(200, [])
    return obs(403, {"detail": "denied"})


def engine_with(*props, strict=True):
    adapter = ScriptedAdapter(handler)
    engine = Engine(adapter, evaluator_with(*props), strict=strict)
    engine.reset()
    engine.apply(CreateOrg(ref="org0", name="org0"))
    engine.apply(CreateOrg(ref="org1", name="org1"))
    engine.apply(CreateOrg(ref="empty", name="empty"))  # an org with no members
    engine.apply(CreateUser(ref="viewer0", org="org0", role=Role.VIEWER))
    engine.apply(CreateUser(ref="admin0", org="org0", role=Role.ADMIN))
    engine.apply(CreateUser(ref="member1", org="org1", role=Role.MEMBER))
    return engine, adapter


#: Denied under AZ-1 only. The guard in ``Evaluator`` requires every denial of a
#: write to be judged by a property that took evidence, so the stand-ins that
#: should judge it are registered under that id.
DENIED_CREATE = CreateDocument(ref="doc0", actor="viewer0", content="x")


def calls_for_last_step(adapter, before):
    return [(c.action, c.credential) for c in adapter.calls[before:]]


def test_two_properties_wanting_the_same_snapshot_cost_one_request():
    a = Wants(TENANT_READ_ISOLATION, "org0")
    b = Wants(ROLE_WRITE_PERMISSION, "org0")
    engine, adapter = engine_with(a, b)
    before = len(adapter.calls)

    record = engine.apply(DENIED_CREATE)

    assert calls_for_last_step(adapter, before) == [
        (Action.CREATE_DOCUMENT, "tok-viewer0"),
        (Action.LIST_DOCUMENTS, "tok-viewer0"),  # org0's first member, once
    ]
    # Both properties were judged independently, on the same evidence.
    assert a.seen == b.seen == [{OrgSnapshot("org0"): {}}]
    assert [(e.property_id, e.outcome) for e in record.evaluations] == [
        ("TI-1", Outcome.PASS),
        ("AZ-1", Outcome.PASS),
    ]


def test_distinct_requests_are_executed_in_plan_order_each_as_a_member_of_its_org():
    a = Wants(TENANT_READ_ISOLATION, "org1")
    b = Wants(ROLE_WRITE_PERMISSION, "org0", "org1")
    engine, adapter = engine_with(a, b)
    before = len(adapter.calls)

    engine.apply(DENIED_CREATE)

    assert calls_for_last_step(adapter, before) == [
        (Action.CREATE_DOCUMENT, "tok-viewer0"),
        (Action.LIST_DOCUMENTS, "tok-member1"),
        (Action.LIST_DOCUMENTS, "tok-viewer0"),
    ]
    assert a.seen == [{OrgSnapshot("org1"): {}}]
    assert b.seen == [{OrgSnapshot("org0"): {}, OrgSnapshot("org1"): {}}]


def test_no_probe_is_executed_when_nothing_in_scope_asks_for_one():
    engine, adapter = engine_with(Wants(TENANT_WRITE_ISOLATION, "org0"))
    before = len(adapter.calls)
    engine.apply(ListDocuments(actor="viewer0"))  # allowed: the property is out of scope
    assert calls_for_last_step(adapter, before) == [(Action.LIST_DOCUMENTS, "tok-viewer0")]


def test_a_request_that_cannot_be_executed_is_inconclusive_for_the_properties_needing_it():
    needs_empty = Wants(TENANT_READ_ISOLATION, "org0", "empty")
    fine = Wants(ROLE_WRITE_PERMISSION, "org0")
    engine, adapter = engine_with(needs_empty, fine, strict=False)
    before = len(adapter.calls)

    record = engine.apply(DENIED_CREATE)

    # Nobody to list ``empty`` as: no call is made for it.
    assert calls_for_last_step(adapter, before) == [
        (Action.CREATE_DOCUMENT, "tok-viewer0"),
        (Action.LIST_DOCUMENTS, "tok-viewer0"),
    ]
    assert needs_empty.seen == []  # never asked to judge without its evidence
    assert fine.seen == [{OrgSnapshot("org0"): {}}]  # unaffected by the other's gap
    assert [(e.property_id, e.outcome, e.summary) for e in record.evaluations] == [
        ("TI-1", Outcome.INCONCLUSIVE, "no state probe was taken after a forbidden write"),
        ("AZ-1", Outcome.PASS, "saw ['org0']"),
    ]
    assert record.outcome is Outcome.INCONCLUSIVE


def test_planned_probes_are_taken_even_when_the_operation_got_no_response():
    prop = Wants(ROLE_WRITE_PERMISSION, "org0")  # claims the AZ-1 denial; the guard checks it

    def no_answer_to_writes(call):
        if call.action is Action.CREATE_DOCUMENT:
            return Observation(error="ConnectError: boom")
        return handler(call)

    engine, adapter = engine_with(prop)
    adapter.handler = no_answer_to_writes
    before = len(adapter.calls)
    with pytest.raises(InconclusiveError) as exc:
        engine.apply(DENIED_CREATE)
    assert len(adapter.calls) - before == 2
    assert prop.seen == []
    assert [e.property_id for e in exc.value.record.evaluations] == ["EXEC"]


def test_engine_hands_the_evaluator_the_probes_it_took():
    seen = []

    class Recording(Evaluator):
        def evaluate(self, state, step):
            seen.append(step)
            return super().evaluate(state, step)

    adapter = ScriptedAdapter(handler)
    engine = Engine(adapter, Recording())
    engine.reset()
    engine.apply(CreateOrg(ref="org0", name="org0"))
    engine.apply(CreateUser(ref="viewer0", org="org0", role=Role.VIEWER))
    engine.apply(DENIED_CREATE)
    engine.apply(ListDocuments(actor="viewer0"))

    denied, listed = seen
    assert list(denied.probes) == [OrgSnapshot("org0")]
    assert denied.probes[OrgSnapshot("org0")].status == 200
    assert listed.probes == {}
