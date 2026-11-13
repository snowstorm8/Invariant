"""An operation the policy has no rule for must stop the run, not pass as allowed."""

import pytest
from support import ScriptedAdapter, make_state, obs

from invariant.adapters.base import Action, Observation
from invariant.core.engine import Engine
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
from invariant.evaluation.evaluator import Evaluator, ExecutedStep
from invariant.evaluation.violations import Outcome
from invariant.properties.authorization import (
    Decision,
    Denial,
    UnsupportedOperationError,
    decide,
)
from invariant.properties.base import OrgSnapshot


class Mystery:
    """Looks like an actor operation, but is not one the policy knows."""

    actor = "user0"


def handler(call):
    if call.action is Action.CREATE_ORG:
        return obs(201, {"id": "o1"})
    if call.action is Action.CREATE_USER:
        return obs(201, {"id": "u1", "token": "t1"})
    return obs(200, [])


def test_engine_raises_before_any_call_reaches_the_target():
    adapter = ScriptedAdapter(handler)
    engine = Engine(adapter)
    engine.reset()
    engine.apply(CreateOrg(ref="org0", name="a"))
    engine.apply(CreateUser(ref="user0", org="org0", role=Role.ADMIN))
    calls, history = len(adapter.calls), list(engine.history)

    with pytest.raises(UnsupportedOperationError):
        engine.apply(Mystery())  # type: ignore[arg-type]

    assert len(adapter.calls) == calls  # nothing was sent
    assert engine.history == history  # and nothing was recorded or committed
    assert engine.state.docs == {}


# -- the evaluator refuses a denial no property judges -----------------------

WRITE = UpdateDocument(actor="user1", doc="doc0", content="x")  # member of org1, doc in org0


def executed(decision):
    state = make_state()
    return state, ExecutedStep(WRITE, state.user("user1"), decision, obs(403))


@pytest.mark.parametrize(
    "denials",
    [
        (Denial("TI-1", "made up"),),  # TI-1 judges the response, not a write's effect
        (Denial("NOPE", "unregistered"),),
        (Denial("TI-2", "cross-tenant write"), Denial("NOPE", "unregistered")),  # one of two
    ],
)
def test_a_denial_of_a_write_that_no_property_judges_fails_loudly(denials):
    state, step = executed(Decision.deny(*denials))
    with pytest.raises(AssertionError, match="no property evaluates"):
        Evaluator().evaluate(state, step)


# -- the guard does not depend on whether the target responded ---------------

NO_RESPONSE = Observation(error="ConnectError: boom")
UNCOVERED = [
    (Denial("TI-1", "made up"),),
    (Denial("NOPE", "unregistered"),),
    (Denial("TI-2", "cross-tenant write"), Denial("NOPE", "unregistered")),
]


@pytest.mark.parametrize("denials", UNCOVERED)
@pytest.mark.parametrize(
    "response",
    [NO_RESPONSE, obs(500, "boom"), obs(403), obs(200)],
    ids=["no-response", "5xx", "4xx", "2xx"],
)
def test_uncovered_denial_fails_the_guard_whatever_the_response(denials, response):
    state = make_state()
    step = ExecutedStep(WRITE, state.user("user1"), Decision.deny(*denials), response)
    with pytest.raises(AssertionError, match="no property evaluates"):
        Evaluator().evaluate(state, step)


def test_the_guard_runs_before_any_probe_is_looked_at():
    state = make_state()
    step = ExecutedStep(
        WRITE,
        state.user("user1"),
        Decision.deny(Denial("NOPE", "unregistered")),
        NO_RESPONSE,
        probes={OrgSnapshot("org0"): Observation(error="ReadTimeout")},
    )
    with pytest.raises(AssertionError, match=r"\['NOPE'\]"):
        Evaluator().evaluate(state, step)


def covered(op, actor):
    state = make_state()
    return state, op, state.user(actor), decide(state, op)


COVERED = [
    (UpdateDocument(actor="user1", doc="doc0", content="x"), "user1", ("TI-2",)),
    (UpdateDocument(actor="user2", doc="doc0", content="x"), "user2", ("AZ-1",)),
    (DeleteDocument(actor="user1", doc="doc0"), "user1", ("TI-2", "AZ-1")),  # multi-denial
    (CreateDocument(ref="d", actor="user2", content="x"), "user2", ("AZ-1",)),
]


@pytest.mark.parametrize(("op", "actor", "denied_under"), COVERED)
def test_covered_denials_with_no_response_remain_exec_inconclusive(op, actor, denied_under):
    state, op, user, decision = covered(op, actor)
    assert decision.property_ids == denied_under
    # An unusable probe must not matter either: nothing else is evaluated.
    step = ExecutedStep(op, user, decision, NO_RESPONSE, probes={OrgSnapshot("org0"): obs(500)})
    results = Evaluator().evaluate(state, step)
    assert [(e.property_id, e.outcome, e.summary) for e in results] == [
        ("EXEC", Outcome.INCONCLUSIVE, "no response: ConnectError: boom")
    ]


@pytest.mark.parametrize(("op", "actor", "denied_under"), COVERED)
def test_covered_denials_with_a_server_error_keep_their_ordering(op, actor, denied_under):
    state, op, user, decision = covered(op, actor)
    step = ExecutedStep(op, user, decision, obs(500, "boom"), probes={OrgSnapshot("org0"): obs(200, [])})
    results = Evaluator().evaluate(state, step)
    assert [e.property_id for e in results] == ["EXEC", "TI-1", *denied_under]
    assert results[0].summary == "server error 500; outcome of the operation is unknown"


@pytest.mark.parametrize("response", [NO_RESPONSE, obs(500, "boom")], ids=["no-response", "5xx"])
def test_reads_lists_and_allowed_writes_have_nothing_to_cover(response):
    state = make_state()
    for op in (
        ReadDocument(actor="user1", doc="doc0"),  # denied read: TI-1 judges the response itself
        ListDocuments(actor="user0"),
        UpdateDocument(actor="user0", doc="doc0", content="x"),  # allowed write
    ):
        step = ExecutedStep(op, state.user(op.actor), decide(state, op), response)
        assert Evaluator().evaluate(state, step)  # no AssertionError
