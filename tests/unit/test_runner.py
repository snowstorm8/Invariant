"""explore() must surface non-security failures as INCONCLUSIVE, never PASS."""

import pytest
from support import ScriptedAdapter, obs

from invariant.adapters.base import Action, AdapterError
from invariant.evaluation.violations import Outcome
from invariant.exploration.runner import explore


def handler_with_broken_reads(call):
    match call.action:
        case Action.CREATE_ORG:
            return obs(201, {"id": "o"})
        case Action.CREATE_USER:
            return obs(201, {"id": "u", "token": "t"})
        case Action.CREATE_DOCUMENT:
            return obs(201, {"id": "d"})
        case _:
            return obs(500, "boom")


def test_unjudgeable_target_is_inconclusive_not_pass():
    result = explore(lambda: ScriptedAdapter(handler_with_broken_reads), seed=0, max_examples=30)
    assert result.outcome is Outcome.INCONCLUSIVE
    assert result.report.finding.property_id == "EXEC"
    assert result.report.reproduced is True


def test_provisioning_failure_is_inconclusive():
    result = explore(lambda: ScriptedAdapter(lambda c: obs(503, "down")), seed=0, max_examples=5)
    assert result.outcome is Outcome.INCONCLUSIVE


def test_infrastructure_errors_are_not_swallowed():
    class BadReset(ScriptedAdapter):
        def reset(self):
            raise AdapterError("cannot reset")

    with pytest.raises(AdapterError):
        explore(lambda: BadReset(lambda c: obs(200)), seed=0, max_examples=5)
