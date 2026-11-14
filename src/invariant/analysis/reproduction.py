"""Deterministic replay of a scenario, independent of Hypothesis."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from invariant.adapters.base import Adapter
from invariant.core.engine import Engine, RunFailure, StepRecord
from invariant.core.scenario import Scenario
from invariant.core.state import UnknownRefError
from invariant.evaluation.evaluator import Evaluator
from invariant.evaluation.violations import Outcome


@dataclass
class ReplayResult:
    """How a replay of a scenario ended: its outcome, the failure if any, and the steps taken."""
    outcome: Outcome
    history: list[StepRecord]
    failure: RunFailure | None = None
    #: False if the scenario referenced entities it never created (e.g. after
    #: operations were removed); such a replay says nothing about the target.
    valid: bool = True


def replay(
    scenario: Scenario,
    adapter_factory: Callable[[], Adapter],
    *,
    strict: bool = True,
    evaluator: Evaluator | None = None,
) -> ReplayResult:
    """Run ``scenario`` on a fresh, reset target and report the first failure.

    ``evaluator`` selects the rules to judge with (default: the built-in set).
    """
    engine = Engine(adapter_factory(), evaluator, strict=strict)
    try:
        engine.reset()
        for op in scenario.operations:
            engine.apply(op)
    except RunFailure as failure:
        outcome = (
            Outcome.VIOLATION
            if failure.record.outcome is Outcome.VIOLATION
            else Outcome.INCONCLUSIVE
        )
        return ReplayResult(outcome, list(engine.history), failure)
    except UnknownRefError:
        return ReplayResult(Outcome.INCONCLUSIVE, list(engine.history), valid=False)
    finally:
        engine.close()
    worst_outcome = max(
        (r.outcome for r in engine.history),
        key=[Outcome.PASS, Outcome.INCONCLUSIVE, Outcome.VIOLATION].index,
        default=Outcome.PASS,
    )
    return ReplayResult(worst_outcome, list(engine.history))
