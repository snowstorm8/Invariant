"""The evaluator must judge structured observations, not status codes."""

import json

import pytest
from support import make_state, obs

from invariant.core.scenario import CreateDocument, DeleteDocument, ReadDocument, UpdateDocument
from invariant.evaluation.evaluator import Evaluator, ExecutedStep
from invariant.evaluation.violations import Outcome, worst
from invariant.properties.authorization import decide
from invariant.properties.base import OrgSnapshot

LEAK = {"id": "doc_6", "org_id": "org_1", "content": "secret <<INV:3>>", "version": 1}


def step(state, op, observation, probe=None, probe_org=None):
    taken = probe is not None and probe_org is not None
    return ExecutedStep(
        op=op,
        actor=state.user(op.actor),
        decision=decide(state, op),
        observation=observation,
        probes={OrgSnapshot(probe_org): probe} if taken else {},
    )


def evaluate(state, st):
    return {e.property_id: e for e in Evaluator().evaluate(state, st)}


READ = ReadDocument(actor="user1", doc="doc0")  # cross-tenant


def test_cross_tenant_read_with_leaked_marker_is_violation():
    s = make_state()
    ev = evaluate(s, step(s, READ, obs(200, LEAK)))
    assert ev["TI-1"].outcome is Outcome.VIOLATION
    assert ev["TI-1"].evidence["leaked"][0]["doc"] == "doc0"


def test_status_code_alone_is_not_trusted_leak_inside_a_404_is_violation():
    s = make_state()
    ev = evaluate(s, step(s, READ, obs(404, {"detail": "no such doc secret <<INV:3>>"})))
    assert ev["TI-1"].outcome is Outcome.VIOLATION


def test_status_code_alone_is_not_trusted_200_without_foreign_data_passes():
    s = make_state()
    ev = evaluate(s, step(s, READ, obs(200, {"id": "doc_9", "content": "mine"})))
    assert ev["TI-1"].outcome is Outcome.PASS


def test_clean_denial_passes():
    s = make_state()
    ev = evaluate(s, step(s, READ, obs(404, {"detail": "not found"})))
    assert ev["TI-1"].outcome is Outcome.PASS


def test_own_org_data_in_response_is_not_a_leak():
    s = make_state()
    own = ReadDocument(actor="user0", doc="doc0")
    ev = evaluate(s, step(s, own, obs(200, LEAK)))
    assert ev["TI-1"].outcome is Outcome.PASS


def test_marker_of_a_deleted_foreign_doc_still_counts_as_leak():
    s = make_state()
    s.docs["doc0"].deleted = True
    ev = evaluate(s, step(s, READ, obs(200, LEAK)))
    assert ev["TI-1"].outcome is Outcome.VIOLATION


def test_no_response_is_inconclusive_not_pass():
    s = make_state()
    results = Evaluator().evaluate(s, step(s, READ, obs(None, "", error="ConnectError: boom")))
    assert [r.outcome for r in results] == [Outcome.INCONCLUSIVE]
    assert "boom" in results[0].summary


def test_server_error_is_inconclusive_even_without_leak():
    s = make_state()
    results = Evaluator().evaluate(s, step(s, READ, obs(500, "Internal Server Error")))
    assert worst([r.outcome for r in results]) is Outcome.INCONCLUSIVE


def test_leak_in_a_500_body_is_still_a_violation():
    s = make_state()
    results = Evaluator().evaluate(s, step(s, READ, obs(500, "trace: secret <<INV:3>>")))
    assert worst([r.outcome for r in results]) is Outcome.VIOLATION


# -- integrity (TI-2 / AZ-1) ------------------------------------------------

UPDATE = UpdateDocument(actor="user1", doc="doc0", content="evil")  # cross-tenant


def listing(content="secret <<INV:3>>", version=1, extra=()):
    docs = [{"id": "doc_6", "content": content, "version": version}, *extra]
    return obs(200, docs)


def test_forbidden_write_that_changed_state_is_violation_even_if_response_says_403():
    s = make_state()
    ev = evaluate(s, step(s, UPDATE, obs(403, {"detail": "no"}), listing("evil", 2), "org0"))
    assert ev["TI-2"].outcome is Outcome.VIOLATION
    assert "doc_6" in ev["TI-2"].evidence["differences"][0]


def test_forbidden_write_with_unchanged_state_passes_even_if_response_says_200():
    s = make_state()
    ev = evaluate(s, step(s, UPDATE, obs(200, {"ok": True}), listing(), "org0"))
    assert ev["TI-2"].outcome is Outcome.PASS


def test_forbidden_delete_that_removed_doc_is_violation():
    s = make_state()
    op = DeleteDocument(actor="user1", doc="doc0")
    ev = evaluate(s, step(s, op, obs(404), obs(200, []), "org0"))
    assert ev["TI-2"].outcome is Outcome.VIOLATION
    assert "missing" in ev["TI-2"].summary


def test_viewer_write_that_changed_state_violates_az1():
    s = make_state()
    op = UpdateDocument(actor="user2", doc="doc0", content="v")
    ev = evaluate(s, step(s, op, obs(200), listing("v", 2), "org0"))
    assert ev["AZ-1"].outcome is Outcome.VIOLATION


def test_forbidden_create_that_added_a_doc_is_violation():
    s = make_state()
    op = CreateDocument(ref="doc1", actor="user2", content="x")
    extra = [{"id": "doc_7", "content": "x", "version": 1}]
    ev = evaluate(s, step(s, op, obs(201), listing(extra=extra), "org0"))
    assert ev["AZ-1"].outcome is Outcome.VIOLATION
    assert "present but not expected" in ev["AZ-1"].summary


@pytest.mark.parametrize(
    "probe",
    [
        None,
        obs(None, "", error="timeout"),
        obs(500, "boom"),
        obs(200, "not json"),
        obs(200, {"docs": []}),
        obs(200, [1, 2]),
        obs(200, [{"id": "doc_6", "content": "x"}]),  # missing version
    ],
)
def test_missing_or_unusable_probe_is_inconclusive_not_pass(probe):
    s = make_state()
    ev = evaluate(s, step(s, UPDATE, obs(403), probe, "org0"))
    assert ev["TI-2"].outcome is Outcome.INCONCLUSIVE


def test_allowed_write_is_not_integrity_checked():
    s = make_state()
    op = UpdateDocument(actor="user0", doc="doc0", content="ok")
    ev = evaluate(s, step(s, op, obs(200, LEAK)))
    assert set(ev) == {"TI-1"}


def test_worst_orders_outcomes():
    assert worst([]) is Outcome.PASS
    assert worst([Outcome.PASS, Outcome.INCONCLUSIVE]) is Outcome.INCONCLUSIVE
    assert worst([Outcome.INCONCLUSIVE, Outcome.VIOLATION, Outcome.PASS]) is Outcome.VIOLATION
    assert json.dumps(Outcome.PASS) == '"PASS"'
