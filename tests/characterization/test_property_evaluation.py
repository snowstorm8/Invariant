"""Characterization of property evaluation as it behaves today.

These tests pin the *current* behaviour of TI-1, TI-2, AZ-1, EXEC and the
engine's probe execution, ahead of moving property logic behind an explicit
interface. They describe what the code does, including behaviour that looks
inelegant; they do not state what it ought to do. A failure here means
externally observable behaviour changed: evaluation order, property
attribution, summaries, evidence, or the sequence of calls sent to the target.

The target is the real demo app behind an instrumented adapter, so every
assertion is about a concrete call trace and nothing depends on Hypothesis.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from invariant.adapters.base import Action, Adapter, Call, Observation
from invariant.analysis.reproduction import replay
from invariant.core.engine import (
    Engine,
    EngineInvalidatedError,
    InconclusiveError,
    PropertyViolationError,
    RunFailure,
    StepRecord,
)
from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    ListDocuments,
    ReadDocument,
    Role,
    Scenario,
    UpdateDocument,
)
from invariant.evaluation.evaluator import Evaluator, ExecutedStep
from invariant.evaluation.violations import Outcome
from invariant.properties.authorization import decide
from invariant.properties.base import OrgSnapshot
from invariant.reporting.reporter import build_report
from support import make_state, obs
from vulnerable_saas.target import adapter_for

PINNED = Path(__file__).parent.parent / "regression" / "scenarios" / "stale_cache_read.json"

TI1_PASS = "no data of other organizations observed in the response"
SERVER_ERROR = "server error 500; outcome of the operation is unknown"

Scripted = Observation | Callable[[Observation], Observation] | None


class Instrumented(Adapter):
    """The demo app, recording every call, with optional scripted responses.

    ``script`` is consumed one entry per call, in order:

    * an ``Observation`` replaces the response; the target is *not* called;
    * a callable receives the real response and returns the one to report;
    * ``None`` lets the call through untouched (used to reach a later call).
    """

    def __init__(self, defects: frozenset[str] = frozenset()) -> None:
        self.inner = adapter_for(defects)
        self.calls: list[Call] = []
        self.script: list[Scripted] = []

    def reset(self) -> None:
        self.inner.reset()

    def execute(self, call: Call) -> Observation:
        self.calls.append(call)
        scripted = self.script.pop(0) if self.script else None
        if isinstance(scripted, Observation):
            return scripted
        real = self.inner.execute(call)
        return real if scripted is None else scripted(real)

    def close(self) -> None:
        self.inner.close()


class CountingEvaluator(Evaluator):
    def __init__(self) -> None:
        self.steps: list[ExecutedStep] = []

    def evaluate(self, state, step):
        self.steps.append(step)
        return super().evaluate(state, step)


#: org0: admin0 (first member), viewer0, member0, owns doc0.
#: org1: member1 (first member), viewer1, owns doc1.
USERS = [
    CreateOrg(ref="org0", name="a"),
    CreateOrg(ref="org1", name="b"),
    CreateUser(ref="admin0", org="org0", role=Role.ADMIN),
    CreateUser(ref="viewer0", org="org0", role=Role.VIEWER),
    CreateUser(ref="member0", org="org0", role=Role.MEMBER),
    CreateUser(ref="member1", org="org1", role=Role.MEMBER),
    CreateUser(ref="viewer1", org="org1", role=Role.VIEWER),
]
DOCS = [
    CreateDocument(ref="doc0", actor="admin0", content="alpha"),
    CreateDocument(ref="doc1", actor="member1", content="beta"),
]
#: Index of the first operation applied by a test after USERS + DOCS.
NEXT = len(USERS) + len(DOCS)


class Rig:
    def __init__(self, *, strict: bool = True, docs: bool = True) -> None:
        self.adapter = Instrumented()
        self.evaluator = CountingEvaluator()
        self.engine = Engine(self.adapter, self.evaluator, strict=strict)
        self.engine.reset()
        for op in [*USERS, *(DOCS if docs else [])]:
            self.engine.apply(op)
        self.mark = len(self.adapter.calls)

    def token(self, user: str) -> str:
        return self.engine.state.user(user).token

    def apply(self, op) -> tuple[StepRecord, RunFailure | None]:
        """Apply ``op``; return its record and the failure it raised, if any."""
        self.mark = len(self.adapter.calls)
        try:
            return self.engine.apply(op), None
        except RunFailure as failure:
            return failure.record, failure

    def trace(self) -> list[tuple[Action, str | None]]:
        """(action, credential) of every call made by the last ``apply``."""
        return [(c.action, c.credential) for c in self.adapter.calls[self.mark :]]

    def listing(self, org: str, **changed: tuple[str, int]) -> Observation:
        """A listing of ``org`` as the model expects it, with per-doc overrides."""
        items = []
        for d in self.engine.state.docs.values():
            if d.org == org and not d.deleted:
                content, version = changed.get(d.ref, (d.content, d.version))
                items.append({"id": d.external_id, "content": content, "version": version})
        return obs(200, items)


@pytest.fixture
def rig():
    r = Rig()
    yield r
    r.engine.close()


@pytest.fixture
def lenient():
    r = Rig(strict=False)
    yield r
    r.engine.close()


def ids(record: StepRecord) -> list[str]:
    return [e.property_id for e in record.evaluations]


def outcomes(record: StepRecord) -> list[Outcome]:
    return [e.outcome for e in record.evaluations]


CROSS_TENANT_UPDATE = UpdateDocument(actor="member1", doc="doc0", content="evil")


# == 1. Evaluation ordering and attribution =================================


def test_exec_precedes_ti1_on_a_server_error(lenient):
    lenient.adapter.script = [obs(500, "boom")]
    record, failure = lenient.apply(ReadDocument(actor="admin0", doc="doc0"))
    assert failure is None  # non-strict: recorded, not raised
    assert ids(record) == ["EXEC", "TI-1"]
    assert outcomes(record) == [Outcome.INCONCLUSIVE, Outcome.PASS]
    exec_eval, ti1 = record.evaluations
    assert exec_eval.summary == SERVER_ERROR
    assert exec_eval.evidence == {"body": "boom"}
    assert (ti1.summary, ti1.evidence) == (TI1_PASS, {})
    assert record.outcome is Outcome.INCONCLUSIVE


def test_one_step_can_violate_ti1_and_ti2_and_ti1_comes_first(rig):
    doc0 = rig.engine.state.doc("doc0")
    leak = obs(403, {"detail": f"denied: {doc0.content}"})
    rig.adapter.script = [leak, rig.listing("org0", doc0=("evil", 2))]

    record, failure = rig.apply(CROSS_TENANT_UPDATE)

    assert ids(record) == ["TI-1", "TI-2"]
    assert outcomes(record) == [Outcome.VIOLATION, Outcome.VIOLATION]
    ti1, ti2 = record.evaluations

    assert ti1.summary == "member1 (org1) received data of doc0 (owned by org0)"
    assert list(ti1.evidence) == ["leaked", "status", "response_excerpt"]
    assert ti1.evidence["leaked"] == [{"doc": "doc0", "owner_org": "org0", "marker": doc0.marker}]
    assert ti1.evidence["status"] == 403
    assert ti1.evidence["response_excerpt"] == leak.body

    difference = (
        f"{doc0.external_id} expected (content={doc0.content!r}, version=1) "
        "observed (content='evil', version=2)"
    )
    assert ti2.summary == (
        "forbidden operation (cross-tenant write) changed application state of org0: "
        + difference
    )
    assert list(ti2.evidence) == ["reason", "differences", "response_status", "response_excerpt"]
    assert ti2.evidence == {
        "reason": "cross-tenant write",
        "differences": [difference],
        "response_status": 403,
        "response_excerpt": leak.body,
    }

    # The first violation, TI-1, determines every downstream attribution.
    assert isinstance(failure, PropertyViolationError)
    assert str(failure) == f"TI-1 violated at step {NEXT}: {ti1.summary}"
    report = build_report(target="t", failure=failure, executions=1, seed=None, reproduced=None)
    assert report.outcome is Outcome.VIOLATION
    assert (report.finding.property_id, report.finding.property_name) == (
        "TI-1",
        "tenant-read-isolation",
    )
    assert report.finding.step_index == NEXT
    assert report.finding.summary == ti1.summary
    assert report.finding.evidence == ti1.evidence
    # The model is not touched by a denied operation, violation or not.
    assert (doc0.content, doc0.version) == ("alpha <<INV:7>>", 1)


def test_ti1_precedes_az1_when_both_are_violated(rig):
    doc1 = rig.engine.state.doc("doc1")  # foreign to viewer0
    rig.adapter.script = [obs(403, f"nope {doc1.marker}"), rig.listing("org0", doc0=("v", 2))]
    record, failure = rig.apply(UpdateDocument(actor="viewer0", doc="doc0", content="v"))
    assert ids(record) == ["TI-1", "AZ-1"]
    assert outcomes(record) == [Outcome.VIOLATION, Outcome.VIOLATION]
    assert record.evaluations[1].evidence["reason"] == "viewer may not update"
    assert str(failure).startswith(f"TI-1 violated at step {NEXT}: ")


def test_exec_then_ti1_then_ti2_and_a_violation_outranks_the_inconclusive_exec(lenient):
    doc0 = lenient.engine.state.doc("doc0")
    lenient.adapter.script = [
        obs(500, f"trace: {doc0.marker}"),
        lenient.listing("org0", doc0=("evil", 2)),
    ]
    record, failure = lenient.apply(CROSS_TENANT_UPDATE)
    assert ids(record) == ["EXEC", "TI-1", "TI-2"]
    assert outcomes(record) == [Outcome.INCONCLUSIVE, Outcome.VIOLATION, Outcome.VIOLATION]
    assert record.outcome is Outcome.VIOLATION
    # Violations raise even when the engine is not strict, and are never
    # reported as the inconclusive EXEC entry that precedes them.
    assert isinstance(failure, PropertyViolationError)
    assert str(failure).startswith(f"TI-1 violated at step {NEXT}: ")
    report = build_report(target="t", failure=failure, executions=1, seed=None, reproduced=None)
    assert (report.outcome, report.finding.property_id) == (Outcome.VIOLATION, "TI-1")


def test_inconclusive_finding_is_attributed_to_the_first_inconclusive_evaluation(rig):
    rig.adapter.script = [None, obs(200, "not json")]  # primary real, probe unusable
    record, failure = rig.apply(CROSS_TENANT_UPDATE)
    assert ids(record) == ["TI-1", "TI-2"]
    assert outcomes(record) == [Outcome.PASS, Outcome.INCONCLUSIVE]
    assert isinstance(failure, InconclusiveError)
    assert not isinstance(failure, PropertyViolationError)
    assert str(failure) == f"inconclusive at step {NEXT}: state probe unusable"
    report = build_report(target="t", failure=failure, executions=1, seed=None, reproduced=None)
    # Attributed to the property that could not be judged, not to EXEC.
    assert (report.outcome, report.finding.property_id, report.finding.property_name) == (
        Outcome.INCONCLUSIVE,
        "TI-2",
        "tenant-write-isolation",
    )


# == 2. Probe behaviour and 3. scope ========================================

#: (operation, allowed, policy reason, status, expected property ids, user whose
#: credential the follow-up listing uses or None if there is no second call,
#: org named by the integrity evaluation or None).
STEP_TABLE = [
    # reads and listings: one call, TI-1 only, whether allowed or denied
    (ReadDocument(actor="admin0", doc="doc0"), True, "same-org read", 200, ["TI-1"], None, None),
    (
        ReadDocument(actor="member1", doc="doc0"),
        False,
        "cross-tenant read",
        404,
        ["TI-1"],
        None,
        None,
    ),
    (
        ListDocuments(actor="viewer0"),
        True,
        "listing is scoped to the caller's own org",
        200,
        ["TI-1"],
        None,
        None,
    ),
    # allowed writes: TI-1 only; the second call is the engine's own
    # verification listing, issued as the *actor*
    (
        CreateDocument(ref="doc2", actor="member0", content="new"),
        True,
        "member of own org with write role",
        201,
        ["TI-1"],
        "member0",
        None,
    ),
    (
        UpdateDocument(actor="member0", doc="doc0", content="new"),
        True,
        "same-org update with write role",
        200,
        ["TI-1"],
        "member0",
        None,
    ),
    (
        DeleteDocument(actor="admin0", doc="doc0"),
        True,
        "same-org delete with admin role",
        200,
        ["TI-1"],
        "admin0",
        None,
    ),
    # denied create: probes the ACTOR's org, as that org's first member
    (
        CreateDocument(ref="doc2", actor="viewer0", content="x"),
        False,
        "viewer may not create",
        403,
        ["TI-1", "AZ-1"],
        "admin0",
        "org0",
    ),
    (
        CreateDocument(ref="doc2", actor="viewer1", content="x"),
        False,
        "viewer may not create",
        403,
        ["TI-1", "AZ-1"],
        "member1",
        "org1",
    ),
    # denied update/delete: probes the DOCUMENT's org, as that org's first member
    (
        UpdateDocument(actor="member1", doc="doc0", content="x"),
        False,
        "cross-tenant write",
        404,
        ["TI-1", "TI-2"],
        "admin0",
        "org0",
    ),
    (
        UpdateDocument(actor="viewer0", doc="doc0", content="x"),
        False,
        "viewer may not update",
        403,
        ["TI-1", "AZ-1"],
        "admin0",
        "org0",
    ),
    # cross-tenant AND wrong role: denied under both rules since the multi-denial
    # policy; the integrity check runs once per property but lists the org once
    (
        UpdateDocument(actor="viewer1", doc="doc0", content="x"),
        False,
        "cross-tenant write; viewer may not update",
        404,
        ["TI-1", "TI-2", "AZ-1"],
        "admin0",
        "org0",
    ),
    (
        DeleteDocument(actor="member1", doc="doc0"),
        False,
        "cross-tenant delete; member may not delete",
        404,
        ["TI-1", "TI-2", "AZ-1"],
        "admin0",
        "org0",
    ),
    (
        DeleteDocument(actor="member0", doc="doc0"),
        False,
        "member may not delete",
        403,
        ["TI-1", "AZ-1"],
        "admin0",
        "org0",
    ),
    (
        DeleteDocument(actor="viewer0", doc="doc1"),
        False,
        "cross-tenant delete; viewer may not delete",
        404,
        ["TI-1", "TI-2", "AZ-1"],
        "member1",
        "org1",
    ),
]


@pytest.mark.parametrize(
    ("op", "allowed", "reason", "status", "expected_ids", "second_caller", "probed_org"),
    STEP_TABLE,
    ids=[f"{row[0].actor}-{row[0].kind}-{'allowed' if row[1] else 'denied'}" for row in STEP_TABLE],
)
def test_evaluations_and_call_trace_for_each_kind_of_step_on_a_correct_target(
    rig, op, allowed, reason, status, expected_ids, second_caller, probed_org
):
    record, failure = rig.apply(op)

    assert failure is None
    assert (record.allowed_by_policy, record.policy_reason, record.status) == (
        allowed,
        reason,
        status,
    )
    # Scope: TI-1 exactly once, first, on every responded actor operation; a
    # denied write additionally under every property id the decision denied it
    # under, each judged on its own denial's reason.
    assert ids(record) == expected_ids
    assert outcomes(record) == [Outcome.PASS] * len(expected_ids)
    assert (record.evaluations[0].summary, record.evaluations[0].evidence) == (TI1_PASS, {})
    if probed_org is not None:
        # Safe to ask after the fact: a denied operation never changes the model.
        decision = decide(rig.engine.state, op)
        integrity = record.evaluations[1:]
        assert [e.property_id for e in integrity] == list(decision.property_ids)
        for e in integrity:
            own_reason = decision.denial_for(e.property_id).reason
            assert e.summary == (
                f"state of {probed_org} unchanged after forbidden operation ({own_reason})"
            )
            assert e.evidence == {}

    # Call trace: the primary call as the actor, then at most one listing.
    primary = (ACTION[type(op)], rig.token(op.actor))
    if second_caller is None:
        assert rig.trace() == [primary]
    else:
        assert rig.trace() == [primary, (Action.LIST_DOCUMENTS, rig.token(second_caller))]

    # The evaluator saw the same probe decision the trace shows.
    step = rig.evaluator.steps[-1]
    assert list(step.probes) == ([] if probed_org is None else [OrgSnapshot(probed_org)])


ACTION = {
    CreateDocument: Action.CREATE_DOCUMENT,
    ReadDocument: Action.READ_DOCUMENT,
    UpdateDocument: Action.UPDATE_DOCUMENT,
    DeleteDocument: Action.DELETE_DOCUMENT,
    ListDocuments: Action.LIST_DOCUMENTS,
}


def test_ti1_passes_even_when_no_foreign_document_exists():
    rig = Rig(docs=False)
    record, failure = rig.apply(ListDocuments(actor="admin0"))
    assert failure is None and rig.engine.state.docs == {}
    assert ids(record) == ["TI-1"] and outcomes(record) == [Outcome.PASS]
    assert record.evaluations[0].summary == TI1_PASS
    rig.engine.close()


def test_setup_operations_never_reach_the_evaluator():
    rig = Rig()
    setup_records = [r for r in rig.engine.history if isinstance(r.operation, CreateOrg | CreateUser)]
    assert len(setup_records) == len(USERS)
    for record in setup_records:
        assert record.evaluations == []
        assert (record.allowed_by_policy, record.policy_reason) == (True, "provisioning")
    # Exactly the two document creations were evaluated.
    assert [type(s.op) for s in rig.evaluator.steps] == [CreateDocument, CreateDocument]
    rig.engine.close()


def test_failed_setup_is_exec_inconclusive_without_property_evaluation(lenient):
    evaluated = len(lenient.evaluator.steps)
    lenient.adapter.script = [obs(503, "down")]
    record, failure = lenient.apply(CreateUser(ref="late", org="org0", role=Role.ADMIN))
    assert isinstance(failure, InconclusiveError)  # raised although not strict
    assert ids(record) == ["EXEC"]
    assert record.evaluations[0].summary == "provisioning failed for late"
    assert record.evaluations[0].evidence == {"status": 503, "error": None, "body": "down"}
    assert len(lenient.evaluator.steps) == evaluated
    assert lenient.trace() == [(Action.CREATE_USER, None)]


def test_denied_write_still_probes_when_the_primary_call_got_no_response(lenient):
    lenient.adapter.script = [Observation(error="ConnectError: boom")]
    record, failure = lenient.apply(CROSS_TENANT_UPDATE)

    # The probe is issued, as org0's first member, although nothing will use it.
    assert lenient.trace() == [
        (Action.UPDATE_DOCUMENT, lenient.token("member1")),
        (Action.LIST_DOCUMENTS, lenient.token("admin0")),
    ]
    step = lenient.evaluator.steps[-1]
    assert list(step.probes) == [OrgSnapshot("org0")]
    assert step.probes[OrgSnapshot("org0")].status == 200

    # Only EXEC is reported: no TI-1 and no TI-2 evaluation at all.
    assert failure is None
    assert ids(record) == ["EXEC"] and outcomes(record) == [Outcome.INCONCLUSIVE]
    assert record.evaluations[0].summary == "no response: ConnectError: boom"
    assert record.evaluations[0].evidence == {}
    assert (record.status, record.error) == (None, "ConnectError: boom")

    # A denied operation with no response does not invalidate the engine.
    again, failure = lenient.apply(ReadDocument(actor="admin0", doc="doc0"))
    assert failure is None and again.outcome is Outcome.PASS


def test_denied_write_with_no_response_raises_inconclusive_when_strict(rig):
    rig.adapter.script = [Observation(error="ConnectError: boom")]
    record, failure = rig.apply(CROSS_TENANT_UPDATE)
    assert isinstance(failure, InconclusiveError)
    assert str(failure) == f"inconclusive at step {NEXT}: no response: ConnectError: boom"
    assert len(rig.trace()) == 2  # the probe was still issued


LONG = "x" * 250

#: (probe response, evidence the TI-2 INCONCLUSIVE evaluation carries)
BAD_PROBES = [
    (
        Observation(error="ReadTimeout: slow"),
        {"status": None, "error": "ReadTimeout: slow", "body": ""},
    ),
    (obs(500, "boom"), {"status": 500, "error": None, "body": "boom"}),
    (obs(403, []), {"status": 403, "error": None, "body": "[]"}),
    (obs(200, "not json"), {"status": 200, "error": None, "body": "not json"}),
    (obs(200, {"docs": []}), {"status": 200, "error": None, "body": '{"docs": []}'}),
    (obs(200, [1, 2]), {"status": 200, "error": None, "body": "[1, 2]"}),
    (
        obs(200, [{"id": "d", "content": "x"}]),
        {"status": 200, "error": None, "body": '[{"id": "d", "content": "x"}]'},
    ),
    (obs(200, LONG), {"status": 200, "error": None, "body": "x" * 200 + "..."}),
]


@pytest.mark.parametrize(("probe", "evidence"), BAD_PROBES)
def test_unusable_probe_keeps_its_outcome_summary_and_evidence(lenient, probe, evidence):
    lenient.adapter.script = [None, probe]
    record, failure = lenient.apply(CROSS_TENANT_UPDATE)

    assert failure is None  # non-strict: recorded only
    assert ids(record) == ["TI-1", "TI-2"]
    assert outcomes(record) == [Outcome.PASS, Outcome.INCONCLUSIVE]
    ti2 = record.evaluations[1]
    assert ti2.summary == "state probe unusable"
    assert list(ti2.evidence) == ["status", "error", "body"]
    assert ti2.evidence == evidence
    assert len(lenient.trace()) == 2

    # Not terminal: the engine stays usable and the model is unchanged.
    assert lenient.engine.state.doc("doc0").version == 1
    again, failure = lenient.apply(ReadDocument(actor="admin0", doc="doc0"))
    assert failure is None and again.outcome is Outcome.PASS


def test_unusable_probe_after_a_denied_az1_write_is_inconclusive_under_az1(rig):
    rig.adapter.script = [None, obs(500, "boom")]
    record, failure = rig.apply(DeleteDocument(actor="member0", doc="doc0"))
    assert ids(record) == ["TI-1", "AZ-1"]
    assert outcomes(record) == [Outcome.PASS, Outcome.INCONCLUSIVE]
    assert isinstance(failure, InconclusiveError)
    assert str(failure) == f"inconclusive at step {NEXT}: state probe unusable"


def test_evaluator_without_a_probe_reports_that_none_was_taken():
    # Not reachable through the engine (the affected org always has a member),
    # so this is pinned at the evaluator boundary.
    state = make_state()
    op = UpdateDocument(actor="user1", doc="doc0", content="evil")
    step = ExecutedStep(op, state.user("user1"), decide(state, op), obs(403))
    results = Evaluator().evaluate(state, step)
    assert [(e.property_id, e.outcome) for e in results] == [
        ("TI-1", Outcome.PASS),
        ("TI-2", Outcome.INCONCLUSIVE),
    ]
    assert results[1].summary == "no state probe was taken after a forbidden write"
    assert results[1].evidence == {}


# -- allowed writes ----------------------------------------------------------


def test_allowed_write_that_cannot_be_verified_appends_exec_after_ti1(lenient):
    lenient.adapter.script = [obs(200, {})]  # claims success; the target never saw it
    record, failure = lenient.apply(UpdateDocument(actor="member0", doc="doc0", content="new"))

    # Unlike the 5xx case, this EXEC entry comes *after* the property evaluation.
    assert ids(record) == ["TI-1", "EXEC"]
    assert outcomes(record) == [Outcome.PASS, Outcome.INCONCLUSIVE]
    unverified = record.evaluations[1]
    assert unverified.summary.startswith(
        "authorised update_document not verified: reported success but the observed "
        "state does not match the expected transition: "
    )
    assert unverified.evidence == {"status": 200, "error": None, "body": "{}"}
    assert lenient.trace() == [
        (Action.UPDATE_DOCUMENT, lenient.token("member0")),
        (Action.LIST_DOCUMENTS, lenient.token("member0")),
    ]
    # Terminal even when not strict.
    assert isinstance(failure, InconclusiveError)
    assert lenient.engine.state.doc("doc0").version == 1
    with pytest.raises(EngineInvalidatedError):
        lenient.engine.apply(ReadDocument(actor="admin0", doc="doc0"))


@pytest.mark.parametrize(
    ("response", "expected_ids"),
    [(obs(500, "boom"), ["EXEC", "TI-1"]), (Observation(error="ConnectError: x"), ["EXEC"])],
)
def test_allowed_write_with_unknown_outcome_issues_no_verification_listing(
    lenient, response, expected_ids
):
    lenient.adapter.script = [response]
    record, failure = lenient.apply(UpdateDocument(actor="member0", doc="doc0", content="new"))
    assert ids(record) == expected_ids
    assert lenient.trace() == [(Action.UPDATE_DOCUMENT, lenient.token("member0"))]
    assert isinstance(failure, InconclusiveError)  # terminal even when not strict
    assert lenient.engine.state.doc("doc0").version == 1


def test_ti1_violation_on_an_allowed_write_still_verifies_and_commits_the_write(rig):
    doc1 = rig.engine.state.doc("doc1")  # foreign to member0
    rig.adapter.script = [lambda real: Observation(status=real.status, body=real.body + doc1.marker)]
    record, failure = rig.apply(UpdateDocument(actor="member0", doc="doc0", content="new"))

    assert ids(record) == ["TI-1"] and outcomes(record) == [Outcome.VIOLATION]
    assert record.evaluations[0].summary == "member0 (org0) received data of doc1 (owned by org1)"
    assert isinstance(failure, PropertyViolationError)
    # The verification listing ran and the model took the write.
    assert rig.trace() == [
        (Action.UPDATE_DOCUMENT, rig.token("member0")),
        (Action.LIST_DOCUMENTS, rig.token("member0")),
    ]
    doc0 = rig.engine.state.doc("doc0")
    assert (doc0.content, doc0.version) == (f"new <<INV:{NEXT}>>", 2)
    # A violation is not terminal for the engine.
    again, failure = rig.apply(ReadDocument(actor="admin0", doc="doc0"))
    assert failure is None and again.outcome is Outcome.PASS


# == 4. Demo defects and the pinned scenario ================================

DEMO_SETUP = [
    CreateOrg(ref="org0", name="a"),
    CreateOrg(ref="org1", name="b"),
    CreateUser(ref="owner", org="org0", role=Role.ADMIN),
    CreateUser(ref="viewer", org="org0", role=Role.VIEWER),
    CreateUser(ref="outsider", org="org1", role=Role.ADMIN),
    CreateDocument(ref="doc0", actor="owner", content="top secret"),
]

#: defect -> (attack ops, property, ids on the failing step, its outcomes,
#:            status, actions of the failing step, summary prefix)
DEFECTS = {
    "stale-cache-read": (
        [
            UpdateDocument(actor="owner", doc="doc0", content="v2"),
            ReadDocument(actor="outsider", doc="doc0"),
        ],
        "TI-1",
        ["TI-1"],
        [Outcome.VIOLATION],
        200,
        [Action.READ_DOCUMENT],
        "outsider (org1) received data of doc0 (owned by org0)",
    ),
    "update-missing-tenant-check": (
        [UpdateDocument(actor="outsider", doc="doc0", content="pwned")],
        "TI-2",
        ["TI-1", "TI-2"],
        [Outcome.PASS, Outcome.VIOLATION],
        200,
        [Action.UPDATE_DOCUMENT, Action.LIST_DOCUMENTS],
        "forbidden operation (cross-tenant write) changed application state of org0: ",
    ),
    "viewer-can-update": (
        [UpdateDocument(actor="viewer", doc="doc0", content="oops")],
        "AZ-1",
        ["TI-1", "AZ-1"],
        [Outcome.PASS, Outcome.VIOLATION],
        200,
        [Action.UPDATE_DOCUMENT, Action.LIST_DOCUMENTS],
        "forbidden operation (viewer may not update) changed application state of org0: ",
    ),
}


def run(scenario: Scenario, defects: frozenset[str], strict: bool):
    """Replay on a fresh instrumented target; return the result and its adapter."""
    made: list[Instrumented] = []

    def factory() -> Instrumented:
        made.append(Instrumented(defects))
        return made[-1]

    result = replay(scenario, factory, strict=strict)
    assert len(made) == 1
    return result, made[0]


@pytest.mark.parametrize("strict", [True, False])
@pytest.mark.parametrize("defect", DEFECTS)
def test_demo_defect_evaluations_and_trace(defect, strict):
    ops, prop, expected_ids, expected_outcomes, status, actions, summary = DEFECTS[defect]
    scenario = Scenario(operations=[*DEMO_SETUP, *ops])
    result, adapter = run(scenario, frozenset({defect}), strict)

    last = len(scenario.operations) - 1
    assert result.outcome is Outcome.VIOLATION and result.valid
    assert isinstance(result.failure, PropertyViolationError)  # also when not strict
    record = result.failure.record
    assert record is result.history[-1] and record.index == last
    assert (ids(record), outcomes(record), record.status) == (
        expected_ids,
        expected_outcomes,
        status,
    )
    violation = record.evaluations[-1]
    assert violation.property_id == prop and violation.summary.startswith(summary)
    assert str(result.failure) == f"{prop} violated at step {last}: {violation.summary}"
    # Every earlier step was judged PASS.
    assert all(r.outcome is Outcome.PASS for r in result.history[:-1])
    # Calls made for the failing step: denied writes are followed by one listing.
    assert [c.action for c in adapter.calls[-len(actions) :]] == actions
    if len(actions) == 2:
        owner_create = next(c for c in adapter.calls if c.action is Action.CREATE_DOCUMENT)
        assert adapter.calls[-1].credential == owner_create.credential  # org0's first member


@pytest.mark.parametrize("strict", [True, False])
@pytest.mark.parametrize("defect", DEFECTS)
def test_demo_attack_on_the_fixed_build_passes_with_the_same_evaluation_shape(defect, strict):
    ops, _, expected_ids, _, _, actions, _ = DEFECTS[defect]
    scenario = Scenario(operations=[*DEMO_SETUP, *ops])
    result, adapter = run(scenario, frozenset(), strict)
    assert result.outcome is Outcome.PASS and result.failure is None
    record = result.history[-1]
    assert ids(record) == expected_ids
    assert outcomes(record) == [Outcome.PASS] * len(expected_ids)
    assert record.status == (404 if expected_ids != ["TI-1", "AZ-1"] else 403)
    assert [c.action for c in adapter.calls[-len(actions) :]] == actions


PINNED_TRACE = [
    Action.CREATE_ORG,
    Action.CREATE_ORG,
    Action.CREATE_USER,
    Action.CREATE_DOCUMENT,
    Action.LIST_DOCUMENTS,  # verification of the create
    Action.UPDATE_DOCUMENT,
    Action.LIST_DOCUMENTS,  # verification of the update
    Action.CREATE_USER,
    Action.READ_DOCUMENT,
]
PINNED_IDS = [[], [], [], ["TI-1"], ["TI-1"], [], ["TI-1"]]


@pytest.mark.parametrize("strict", [True, False])
def test_pinned_stale_cache_scenario_on_the_defective_build(strict):
    scenario = Scenario.model_validate_json(PINNED.read_text())
    result, adapter = run(scenario, frozenset({"stale-cache-read"}), strict)

    assert result.outcome is Outcome.VIOLATION
    assert [c.action for c in adapter.calls] == PINNED_TRACE
    assert [ids(r) for r in result.history] == PINNED_IDS
    assert [r.outcome for r in result.history] == [Outcome.PASS] * 6 + [Outcome.VIOLATION]
    assert [r.status for r in result.history] == [201, 201, 201, 201, 200, 201, 200]

    record = result.failure.record
    assert (record.index, record.allowed_by_policy, record.policy_reason) == (
        6,
        False,
        "cross-tenant read",
    )
    ti1 = record.evaluations[0]
    assert ti1.summary == "user5 (org0) received data of doc0 (owned by org1)"
    # The leaked marker is the one written by the update (step 4), not the create.
    assert [(x["doc"], x["owner_org"], x["marker"]) for x in ti1.evidence["leaked"]] == [
        ("doc0", "org1", "<<INV:4>>")
    ]
    assert ti1.evidence["status"] == 200
    assert json.loads(ti1.evidence["response_excerpt"])["content"] == "yyz <<INV:4>>"

    report = build_report(
        target="t", failure=result.failure, executions=1, seed=None, reproduced=True
    )
    assert (report.outcome, report.finding.property_id, report.finding.step_index) == (
        Outcome.VIOLATION,
        "TI-1",
        6,
    )
    assert report.scenario == scenario
    assert [s.index for s in report.steps] == list(range(7))


@pytest.mark.parametrize("strict", [True, False])
def test_pinned_stale_cache_scenario_on_the_fixed_build(strict):
    scenario = Scenario.model_validate_json(PINNED.read_text())
    result, adapter = run(scenario, frozenset(), strict)
    assert result.outcome is Outcome.PASS and result.failure is None
    assert [c.action for c in adapter.calls] == PINNED_TRACE  # same calls either way
    assert [ids(r) for r in result.history] == PINNED_IDS
    assert [r.status for r in result.history] == [201, 201, 201, 201, 200, 201, 404]
    assert result.history[-1].evaluations[0].summary == TI1_PASS
