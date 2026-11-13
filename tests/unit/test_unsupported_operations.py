"""An operation the policy has no rule for must stop the run, not pass as allowed."""

import pytest
from support import ScriptedAdapter, make_state, obs

from invariant.adapters.base import Action
from invariant.core.engine import Engine
from invariant.core.scenario import CreateOrg, CreateUser, Role, UpdateDocument
from invariant.evaluation.evaluator import Evaluator, ExecutedStep
from invariant.properties.authorization import (
    Decision,
    Denial,
    UnsupportedOperationError,
)


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
