"""Operations denied under several properties, against the real demo app.

A cross-tenant viewer update breaks the tenant rule (TI-2) and the role rule
(AZ-1). Both integrity properties apply; they ask for the same snapshot, so the
target is listed once, and each judges that snapshot on its own denial.
"""

import pytest

from invariant.adapters.base import Action, Adapter, Call
from invariant.analysis.minimizer import violates
from invariant.analysis.reproduction import replay
from invariant.core.engine import Engine, PropertyViolationError
from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    Role,
    Scenario,
    UpdateDocument,
)
from invariant.evaluation.violations import Outcome
from vulnerable_saas.target import adapter_for

SETUP = [
    CreateOrg(ref="org0", name="a"),
    CreateOrg(ref="org1", name="b"),
    CreateUser(ref="admin0", org="org0", role=Role.ADMIN),
    CreateUser(ref="outsider_viewer", org="org1", role=Role.VIEWER),
    CreateUser(ref="outsider_member", org="org1", role=Role.MEMBER),
    CreateUser(ref="outsider_admin", org="org1", role=Role.ADMIN),
    CreateDocument(ref="doc0", actor="admin0", content="secret"),
]
BOTH_BUGS = frozenset({"viewer-can-update", "update-missing-tenant-check"})


class Recording(Adapter):
    def __init__(self, defects: frozenset[str] = frozenset()) -> None:
        self.inner = adapter_for(defects)
        self.calls: list[Call] = []

    def reset(self) -> None:
        self.inner.reset()

    def execute(self, call: Call):
        self.calls.append(call)
        return self.inner.execute(call)

    def close(self) -> None:
        self.inner.close()


def run(defects, *ops, strict=True):
    adapter = Recording(defects)
    engine = Engine(adapter, strict=strict)
    engine.reset()
    for op in SETUP:
        engine.apply(op)
    start = len(adapter.calls)
    try:
        return engine, adapter, engine.apply(ops[-1]), None, start
    except PropertyViolationError as failure:
        return engine, adapter, failure.record, failure, start


CROSS_VIEWER_UPDATE = UpdateDocument(actor="outsider_viewer", doc="doc0", content="x")
CROSS_MEMBER_DELETE = DeleteDocument(actor="outsider_member", doc="doc0")


@pytest.mark.parametrize("op", [CROSS_VIEWER_UPDATE, CROSS_MEMBER_DELETE])
def test_two_integrity_properties_on_one_denied_write_cost_one_probe(op):
    engine, adapter, record, failure, start = run(frozenset(), op)
    assert failure is None and record.outcome is Outcome.PASS
    assert [e.property_id for e in record.evaluations] == ["TI-1", "TI-2", "AZ-1"]
    assert not record.allowed_by_policy
    listings = [c for c in adapter.calls[start:] if c.action is Action.LIST_DOCUMENTS]
    assert len(listings) == 1  # one OrgSnapshot request, executed once
    assert listings[0].credential == engine.state.user("admin0").token  # as org0's member
    # Each property judged the snapshot on its own denial.
    summaries = [e.summary for e in record.evaluations[1:]]
    first, second = record.policy_reason.split("; ")
    assert summaries == [
        f"state of org0 unchanged after forbidden operation ({first})",
        f"state of org0 unchanged after forbidden operation ({second})",
    ]


def test_single_denial_writes_still_run_one_integrity_property():
    cross_admin = UpdateDocument(actor="outsider_admin", doc="doc0", content="x")  # TI-2 only
    same_org_viewer = CreateDocument(ref="doc9", actor="outsider_viewer", content="x")  # AZ-1 only
    for op, expected in ((cross_admin, ["TI-1", "TI-2"]), (same_org_viewer, ["TI-1", "AZ-1"])):
        _, adapter, record, failure, start = run(frozenset(), op)
        assert failure is None
        assert [e.property_id for e in record.evaluations] == expected
        assert [c.action for c in adapter.calls[start:]].count(Action.LIST_DOCUMENTS) == 1


def test_simultaneous_denials_both_report_the_same_state_change():
    _, adapter, record, failure, start = run(BOTH_BUGS, CROSS_VIEWER_UPDATE)

    assert [e.property_id for e in record.evaluations] == ["TI-1", "TI-2", "AZ-1"]
    assert [e.outcome for e in record.evaluations] == [
        Outcome.PASS,
        Outcome.VIOLATION,
        Outcome.VIOLATION,
    ]
    ti2, az1 = record.evaluations[1:]
    assert ti2.evidence["reason"] == "cross-tenant write"
    assert az1.evidence["reason"] == "viewer may not update"
    assert ti2.evidence["differences"] == az1.evidence["differences"]  # one snapshot, two verdicts
    assert [c.action for c in adapter.calls[start:]].count(Action.LIST_DOCUMENTS) == 1

    # The first violation, TI-2, still decides how the failure is attributed.
    assert isinstance(failure, PropertyViolationError)
    assert str(failure).startswith("TI-2 violated at step")


def test_replay_attributes_the_violation_to_both_properties():
    result = replay(Scenario(operations=[*SETUP, CROSS_VIEWER_UPDATE]), lambda: adapter_for(BOTH_BUGS))
    assert result.outcome is Outcome.VIOLATION
    assert violates(result, "TI-2") and violates(result, "AZ-1")
    assert not violates(result, "TI-1")


@pytest.mark.parametrize(
    ("defects", "op", "violated"),
    [
        # each bug alone is a single, correctly attributed violation
        (frozenset({"update-missing-tenant-check"}), UpdateDocument(actor="outsider_admin", doc="doc0", content="x"), {"TI-2"}),
        (frozenset({"viewer-can-update"}), UpdateDocument(actor="outsider_viewer", doc="doc0", content="x"), set()),
    ],
)
def test_single_defects_keep_their_attribution(defects, op, violated):
    _, _, record, _, _ = run(defects, op)
    assert {e.property_id for e in record.evaluations if e.outcome is Outcome.VIOLATION} == violated
