"""Differential check: the property-based evaluator against the legacy one.

``Evaluator._legacy_evaluate`` is the implementation from before properties
were extracted. Every combination below is run through both and the complete,
ordered results must be identical: property ids, outcomes, summaries, and
evidence including the order of its keys. The matrix is a fixed cartesian
product, so the test is deterministic. It is evidence over these inputs, not a
proof of equivalence.

This file is temporary: it goes away together with ``_legacy_evaluate``.
"""

import copy
import itertools

import pytest
from support import obs

from invariant.adapters.base import Observation
from invariant.core.scenario import (
    CreateDocument,
    DeleteDocument,
    ListDocuments,
    ReadDocument,
    Role,
    UpdateDocument,
)
from invariant.core.state import DocModel, ModelState, OrgModel, UserModel
from invariant.evaluation.evaluator import Evaluator, ExecutedStep
from invariant.evaluation.violations import Outcome
from invariant.properties.authorization import Decision, decide

M0, M1, M2 = "<<INV:5>>", "<<INV:6>>", "<<INV:7>>"


def world() -> ModelState:
    """org0{admin, viewer, member; doc0, deleted doc2}, org1{member, viewer; doc1}."""
    s = ModelState()
    s.orgs = {"org0": OrgModel("org0", "org_1"), "org1": OrgModel("org1", "org_2")}
    s.users = {
        "admin0": UserModel("admin0", "org0", Role.ADMIN, "u1", "t1"),
        "viewer0": UserModel("viewer0", "org0", Role.VIEWER, "u2", "t2"),
        "member0": UserModel("member0", "org0", Role.MEMBER, "u3", "t3"),
        "member1": UserModel("member1", "org1", Role.MEMBER, "u4", "t4"),
        "viewer1": UserModel("viewer1", "org1", Role.VIEWER, "u5", "t5"),
    }
    s.docs = {
        "doc0": DocModel("doc0", "org0", "d0", f"alpha {M0}", M0, version=2),
        "doc1": DocModel("doc1", "org1", "d1", f"beta {M1}", M1),
        "doc2": DocModel("doc2", "org0", "d2", f"gone {M2}", M2, deleted=True),
    }
    return s


STATE = world()

OPS = [
    op
    for actor in STATE.users
    for op in (
        ReadDocument(actor=actor, doc="doc0"),
        ReadDocument(actor=actor, doc="doc1"),
        ListDocuments(actor=actor),
        CreateDocument(ref="new", actor=actor, content="x"),
        UpdateDocument(actor=actor, doc="doc0", content="x"),
        UpdateDocument(actor=actor, doc="doc1", content="x"),
        UpdateDocument(actor=actor, doc="doc2", content="x"),  # deleted document
        DeleteDocument(actor=actor, doc="doc0"),
        DeleteDocument(actor=actor, doc="doc1"),
    )
]

RESPONSES = [
    Observation(error="ConnectError: boom"),  # no response
    obs(200, {"ok": True}),
    obs(200, {"content": f"alpha {M0}"}),  # org0's live document
    obs(200, {"content": f"beta {M1}"}),  # org1's document
    obs(200, f"{M0} {M1} {M2}"),  # everything, including the deleted document
    obs(201, {"id": "d9"}),
    obs(204, ""),
    obs(403, {"detail": "denied"}),
    obs(404, {"detail": f"no such doc: gone {M2}"}),  # leak inside a 4xx
    obs(500, "boom"),
    obs(500, f"trace: {M0} {M1}"),  # leak inside a 5xx
    obs(503, "x" * 300),  # excerpt truncation
]


def affected_org(op) -> str | None:
    """The org the engine probes for a write (engine.py), else None."""
    if isinstance(op, CreateDocument):
        return STATE.user(op.actor).org
    if isinstance(op, UpdateDocument | DeleteDocument):
        return STATE.doc(op.doc).org
    return None


def probes_for(org: str) -> list[Observation | None]:
    expected = STATE.expected_snapshot(org)
    items = [{"id": i, "content": c, "version": v} for i, (c, v) in expected.items()]
    first = items[0]
    return [
        None,  # no probe taken
        obs(200, items),  # unchanged
        obs(200, [{**first, "content": "evil"}, *items[1:]]),  # content changed
        obs(200, [{**first, "version": first["version"] + 1}, *items[1:]]),  # version changed
        obs(200, items[1:]),  # a document disappeared
        obs(200, [*items, {"id": "zz", "content": "x", "version": 1}]),  # one appeared
        obs(200, []),
        # unusable
        Observation(error="ReadTimeout: slow"),
        obs(500, items),
        obs(403, {"detail": "no"}),
        obs(200, "not json"),
        obs(200, {"docs": items}),
        obs(200, [1, 2]),
        obs(200, [{"id": "d0", "content": "x"}]),
        obs(200, "y" * 300),
    ]


def cases():
    for op, response in itertools.product(OPS, RESPONSES):
        org = affected_org(op)
        if org is None:
            yield op, response, None, None
            # A probe handed over for a non-write must be ignored by both.
            yield op, response, obs(200, []), STATE.user(op.actor).org
        else:
            for probe in probes_for(org):
                yield op, response, probe, org


def run(evaluate, op, response, probe, probe_org, decision=None):
    state = copy.deepcopy(STATE)
    step = ExecutedStep(
        op=op,
        actor=state.user(op.actor),
        decision=decision or decide(state, op),
        observation=response,
        probe=probe,
        probe_org=probe_org,
    )
    results = evaluate(state, step)
    assert state == STATE  # neither implementation touches the model
    return results


def dump(results) -> list[str]:
    # JSON keeps key order, so evidence ordering is compared too.
    return [e.model_dump_json() for e in results]


def test_new_evaluator_matches_legacy_over_the_whole_matrix():
    evaluator = Evaluator()
    seen: set[tuple[tuple[str, Outcome], ...]] = set()
    count = 0
    for op, response, probe, org in cases():
        new = run(evaluator.evaluate, op, response, probe, org)
        old = run(evaluator._legacy_evaluate, op, response, probe, org)
        assert dump(new) == dump(old), (op, response, probe, org)
        assert new == old
        seen.add(tuple((e.property_id, e.outcome) for e in new))
        count += 1

    # The matrix really exercised every shape of result it is meant to cover.
    P, V, I = Outcome.PASS, Outcome.VIOLATION, Outcome.INCONCLUSIVE  # noqa: E741
    required = {
        (("EXEC", I),),  # no response
        (("TI-1", P),),
        (("TI-1", V),),
        (("EXEC", I), ("TI-1", P)),  # 5xx
        (("EXEC", I), ("TI-1", V)),  # leak inside a 5xx
        (("TI-1", P), ("TI-2", P)),
        (("TI-1", P), ("TI-2", V)),
        (("TI-1", P), ("TI-2", I)),  # missing or unusable probe
        (("TI-1", V), ("TI-2", V)),  # simultaneous violations
        (("TI-1", V), ("TI-2", I)),
        (("TI-1", P), ("AZ-1", P)),
        (("TI-1", P), ("AZ-1", V)),
        (("TI-1", P), ("AZ-1", I)),
        (("TI-1", V), ("AZ-1", V)),
        (("EXEC", I), ("TI-1", V), ("TI-2", V)),
        (("EXEC", I), ("TI-1", V), ("AZ-1", V)),
        (("EXEC", I), ("TI-1", P), ("AZ-1", I)),
    }
    assert required <= seen, required - seen
    assert count == sum(1 for _ in cases()) > 4000


def test_matrix_covers_every_policy_outcome():
    decisions = {(d.allowed, d.property_id) for d in (decide(STATE, op) for op in OPS)}
    assert decisions == {(True, None), (False, "TI-1"), (False, "TI-2"), (False, "AZ-1")}


@pytest.mark.parametrize("property_id", [None, "NOPE", "EXEC"])
def test_denied_write_with_an_unjudgeable_attribution_fails_loudly_in_both(property_id):
    evaluator = Evaluator()
    op = UpdateDocument(actor="member1", doc="doc0", content="x")
    decision = Decision(False, "made up", property_id)
    for evaluate in (evaluator.evaluate, evaluator._legacy_evaluate):
        with pytest.raises(AssertionError):
            run(evaluate, op, obs(403), obs(200, []), "org0", decision)


# -- inputs on which the two knowingly differ --------------------------------
# Neither can be produced by the engine or by decide(). They are pinned so the
# difference is explicit rather than silent.


def test_known_difference_probe_of_an_org_other_than_the_affected_one():
    # The engine always probes the affected org. Handed a probe of some other
    # org, the legacy code compared it against that org's expected state; the
    # property asks for the affected org's snapshot and finds none.
    evaluator = Evaluator()
    op = UpdateDocument(actor="member1", doc="doc0", content="x")  # affects org0
    wrong = obs(200, [{"id": "d1", "content": f"beta {M1}", "version": 1}])  # org1, unchanged
    old = run(evaluator._legacy_evaluate, op, obs(403), wrong, "org1")
    new = run(evaluator.evaluate, op, obs(403), wrong, "org1")
    assert [(e.property_id, e.outcome) for e in old] == [
        ("TI-1", Outcome.PASS),
        ("TI-2", Outcome.PASS),
    ]
    assert old[1].summary.startswith("state of org1 unchanged")
    assert [(e.property_id, e.outcome) for e in new] == [
        ("TI-1", Outcome.PASS),
        ("TI-2", Outcome.INCONCLUSIVE),
    ]
    assert new[1].summary == "no state probe was taken after a forbidden write"


def test_known_difference_denied_write_attributed_to_ti1():
    # decide() never attributes a denied write to TI-1. If it did, the legacy
    # code ran the integrity check under the TI-1 id (two TI-1 evaluations);
    # no integrity property claims that decision, so the new code refuses.
    evaluator = Evaluator()
    op = UpdateDocument(actor="member1", doc="doc0", content="x")
    decision = Decision(False, "made up", "TI-1")
    old = run(evaluator._legacy_evaluate, op, obs(403), obs(200, []), "org0", decision)
    assert [e.property_id for e in old] == ["TI-1", "TI-1"]
    with pytest.raises(AssertionError):
        run(evaluator.evaluate, op, obs(403), obs(200, []), "org0", decision)
