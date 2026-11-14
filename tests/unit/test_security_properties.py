"""The SecurityProperty contract and its three implementations, in isolation."""

import pytest

from invariant.adapters.base import Observation
from invariant.core.scenario import (
    CreateDocument,
    DeleteDocument,
    ListDocuments,
    ReadDocument,
    UpdateDocument,
)
from invariant.evaluation.evaluator import Evaluator, ExecutedStep
from invariant.evaluation.violations import Outcome
from invariant.properties.authorization import ROLE_WRITE_PERMISSION, decide
from invariant.properties.base import OrgSnapshot, SecurityProperty, Step, Verdict
from invariant.properties.checks import (
    CHECKS,
    ROLE_WRITE_PERMISSION_CHECK,
    TENANT_READ_ISOLATION_CHECK,
    TENANT_WRITE_ISOLATION_CHECK,
    RuleCheck,
)
from invariant.properties.isolation import TENANT_READ_ISOLATION, TENANT_WRITE_ISOLATION
from invariant.properties.registry import PROPERTIES
from support import make_state, obs

TI1, TI2, AZ1 = TENANT_READ_ISOLATION_CHECK, TENANT_WRITE_ISOLATION_CHECK, ROLE_WRITE_PERMISSION_CHECK

# make_state(): org0{user0 admin, user2 viewer, doc0 = doc_6}, org1{user1 member}
UNCHANGED = {"doc_6": ("secret <<INV:3>>", 1)}


def step_for(op, state=None) -> Step:
    state = state or make_state()
    return Step(op, state.user(op.actor), decide(state, op), state)


# -- identity ---------------------------------------------------------------


def test_checks_are_the_registered_properties_in_evaluation_order():
    assert [p.id for p in CHECKS] == ["TI-1", "TI-2", "AZ-1"]
    assert Evaluator.properties is CHECKS
    # Each check carries the existing metadata object, untouched.
    assert [p.info for p in CHECKS] == [
        TENANT_READ_ISOLATION,
        TENANT_WRITE_ISOLATION,
        ROLE_WRITE_PERMISSION,
    ]
    assert {p.id: p.info for p in CHECKS} == PROPERTIES


def test_every_builtin_check_is_an_interpreted_rule():
    # No property has a Python implementation of its own any more: all three are
    # rules from integrations/document_saas.rules, judged by one interpreter.
    assert TI2 is not AZ1 and (TI2.id, AZ1.id) == ("TI-2", "AZ-1")
    assert type(TI1) is type(TI2) is type(AZ1) is RuleCheck


# -- scope comes from the policy decision -----------------------------------

#: (operation, ids of the properties that apply, org whose snapshot is required)
SCOPE = [
    (ReadDocument(actor="user0", doc="doc0"), ["TI-1"], None),
    (ReadDocument(actor="user1", doc="doc0"), ["TI-1"], None),  # denied read: no integrity
    (ListDocuments(actor="user1"), ["TI-1"], None),
    (CreateDocument(ref="d", actor="user1", content="x"), ["TI-1"], None),  # allowed
    (UpdateDocument(actor="user0", doc="doc0", content="x"), ["TI-1"], None),  # allowed
    (DeleteDocument(actor="user0", doc="doc0"), ["TI-1"], None),  # allowed
    (CreateDocument(ref="d", actor="user2", content="x"), ["TI-1", "AZ-1"], "org0"),
    (UpdateDocument(actor="user1", doc="doc0", content="x"), ["TI-1", "TI-2"], "org0"),
    (UpdateDocument(actor="user2", doc="doc0", content="x"), ["TI-1", "AZ-1"], "org0"),
    # cross-tenant member delete also lacks the admin role: denied under both
    (DeleteDocument(actor="user1", doc="doc0"), ["TI-1", "TI-2", "AZ-1"], "org0"),
    (DeleteDocument(actor="user2", doc="doc0"), ["TI-1", "AZ-1"], "org0"),
]


@pytest.mark.parametrize(("op", "applicable", "org"), SCOPE)
def test_scope_and_requirements_follow_the_decision(op, applicable, org):
    step = step_for(op)
    assert [p.id for p in CHECKS if p.applies(step)] == applicable
    # A denied write is judged by exactly the properties the decision denies it under.
    assert [i for i in applicable if i != "TI-1"] == ([] if org is None else list(step.decision.property_ids))
    assert TI1.requires(step) == ()
    for prop in (TI2, AZ1):
        if prop.applies(step):
            assert prop.requires(step) == (OrgSnapshot(org),)


def test_denied_create_requires_the_actors_org_and_denied_update_the_documents_org():
    state = make_state()
    state.users["user1"].role = state.users["user2"].role  # org1 viewer
    create = step_for(CreateDocument(ref="d", actor="user1", content="x"), state)
    assert AZ1.applies(create) and AZ1.requires(create) == (OrgSnapshot("org1"),)
    update = step_for(UpdateDocument(actor="user1", doc="doc0", content="x"), state)
    # Cross-tenant and wrong role: denied under both, so both apply, and both ask
    # for the same snapshot (the framework runs it once).
    assert TI2.applies(update) and AZ1.applies(update)
    assert TI2.requires(update) == AZ1.requires(update) == (OrgSnapshot("org0"),)


# -- verdicts ---------------------------------------------------------------


def test_ti1_verdicts():
    step = step_for(ReadDocument(actor="user1", doc="doc0"))
    clean = TI1.evaluate(step, obs(404, {"detail": "not found"}), {})
    assert clean == Verdict(
        Outcome.PASS, "no data of other organizations observed in the response"
    )
    leak = TI1.evaluate(step, obs(404, "no such doc secret <<INV:3>>"), {})
    assert leak.outcome is Outcome.VIOLATION
    assert leak.summary == "user1 (org1) received data of doc0 (owned by org0)"
    assert leak.evidence == {
        "leaked": [{"doc": "doc0", "owner_org": "org0", "marker": "<<INV:3>>"}],
        "status": 404,
        "response_excerpt": "no such doc secret <<INV:3>>",
    }
    # The same body is not a leak to a member of the owning org.
    own = step_for(ReadDocument(actor="user0", doc="doc0"))
    assert TI1.evaluate(own, obs(200, "secret <<INV:3>>"), {}).outcome is Outcome.PASS


@pytest.mark.parametrize(
    ("prop", "op", "reason"),
    [
        (TI2, UpdateDocument(actor="user1", doc="doc0", content="x"), "cross-tenant write"),
        (AZ1, UpdateDocument(actor="user2", doc="doc0", content="x"), "viewer may not update"),
    ],
)
def test_integrity_verdicts(prop, op, reason):
    step = step_for(op)
    request = OrgSnapshot("org0")
    unchanged = prop.evaluate(step, obs(403), {request: UNCHANGED})
    assert unchanged == Verdict(
        Outcome.PASS, f"state of org0 unchanged after forbidden operation ({reason})"
    )
    # Judged from the snapshot, not the status: a 403 that changed state violates.
    changed = prop.evaluate(step, obs(403, "no"), {request: {"doc_6": ("x", 2)}})
    difference = "doc_6 expected (content='secret <<INV:3>>', version=1) observed (content='x', version=2)"
    assert changed.outcome is Outcome.VIOLATION
    assert changed.summary == (
        f"forbidden operation ({reason}) changed application state of org0: {difference}"
    )
    assert changed.evidence == {
        "reason": reason,
        "differences": [difference],
        "response_status": 403,
        "response_excerpt": "no",
    }
    # ...and a 200 that changed nothing does not.
    assert prop.evaluate(step, obs(200), {request: UNCHANGED}).outcome is Outcome.PASS


def test_verdict_carries_no_property_id():
    assert not hasattr(Verdict(Outcome.PASS, "ok"), "property_id")


# -- what the framework guarantees a property -------------------------------


class Spy(SecurityProperty):
    """Claims to be TI-2, wants org0's snapshot, records how it is called."""

    def __init__(self, verdict: Verdict) -> None:
        super().__init__(TENANT_WRITE_ISOLATION)
        self.verdict = verdict
        self.evaluated: list[tuple[Step, Observation, dict]] = []

    def applies(self, step):
        return not step.decision.allowed

    def requires(self, step):
        return (OrgSnapshot("org0"),)

    def evaluate(self, step, response, evidence):
        self.evaluated.append((step, response, dict(evidence)))
        return self.verdict


def evaluate_with(spy, response, probe, probe_org="org0"):
    probes = {} if probe is None else {OrgSnapshot(probe_org): probe}
    class Framework(Evaluator):
        properties = (spy,)

    state = make_state()
    op = UpdateDocument(actor="user1", doc="doc0", content="x")
    step = ExecutedStep(op, state.user("user1"), decide(state, op), response, probes)
    return state, Framework().evaluate(state, step)


def test_framework_stamps_the_property_id_and_passes_parsed_evidence():
    spy = Spy(Verdict(Outcome.VIOLATION, "bad", {"k": 1}))
    listing = obs(200, [{"id": "doc_6", "content": "secret <<INV:3>>", "version": 1}])
    response = obs(403, "no")
    state, results = evaluate_with(spy, response, listing)
    assert [e.model_dump() for e in results] == [
        {"property_id": "TI-2", "outcome": Outcome.VIOLATION, "summary": "bad", "evidence": {"k": 1}}
    ]
    (step, seen_response, evidence) = spy.evaluated[0]
    assert (step.state, step.actor, step.decision.property_ids) == (
        state,
        state.user("user1"),
        ("TI-2",),
    )
    assert seen_response is response
    assert evidence == {OrgSnapshot("org0"): UNCHANGED}


@pytest.mark.parametrize(
    ("probe", "probe_org", "summary", "evidence"),
    [
        (None, "org0", "no state probe was taken after a forbidden write", {}),
        # A usable probe of some other org does not answer the request.
        (obs(200, []), "org1", "no state probe was taken after a forbidden write", {}),
        (
            obs(200, "not json"),
            "org0",
            "state probe unusable",
            {"status": 200, "error": None, "body": "not json"},
        ),
        (
            Observation(error="ReadTimeout"),
            "org0",
            "state probe unusable",
            {"status": None, "error": "ReadTimeout", "body": ""},
        ),
    ],
)
def test_property_is_never_asked_to_judge_without_its_evidence(probe, probe_org, summary, evidence):
    spy = Spy(Verdict(Outcome.PASS, "would have passed"))
    _, results = evaluate_with(spy, obs(403), probe, probe_org)
    assert spy.evaluated == []  # missing evidence can never become the spy's PASS
    assert [(e.property_id, e.outcome, e.summary, e.evidence) for e in results] == [
        ("TI-2", Outcome.INCONCLUSIVE, summary, evidence)
    ]


def test_property_is_not_consulted_when_the_target_did_not_respond():
    spy = Spy(Verdict(Outcome.PASS, "would have passed"))
    _, results = evaluate_with(spy, Observation(error="boom"), obs(200, []))
    assert spy.evaluated == []
    assert [(e.property_id, e.outcome) for e in results] == [("EXEC", Outcome.INCONCLUSIVE)]
