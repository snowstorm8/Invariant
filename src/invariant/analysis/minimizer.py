"""Scenario minimisation by deterministic greedy deletion.

Hypothesis' own shrinking is disabled for exploration because stateful shrinking
is heuristic: removing a step shifts later draws, so redundant operations can
survive. This pass works on the
symbolic scenario directly: delete one operation at a time and keep the deletion
iff replaying on a fresh target still violates the *same property*.
"""

from __future__ import annotations

from collections.abc import Callable

from invariant.adapters.base import Adapter
from invariant.core.engine import PropertyViolationError
from invariant.core.scenario import Scenario

from .reproduction import ReplayResult, replay


def violates(result: ReplayResult, property_id: str) -> bool:
    failure = result.failure
    return (
        result.valid
        and isinstance(failure, PropertyViolationError)
        and any(
            e.property_id == property_id and e.outcome.value == "VIOLATION"
            for e in failure.record.evaluations
        )
    )


def minimize(
    scenario: Scenario,
    adapter_factory: Callable[[], Adapter],
    *,
    property_id: str,
    strict: bool = True,
) -> tuple[Scenario, ReplayResult]:
    """Return a scenario no operation of which can be removed, plus its replay.

    The result is 1-minimal (not necessarily globally minimal). If ``scenario``
    does not reproduce on replay, it is returned unchanged with that result.
    """
    best = replay(scenario, adapter_factory, strict=strict)
    if not violates(best, property_id):
        return scenario, best
    ops = list(scenario.operations)
    changed = True
    while changed:
        changed = False
        for i in reversed(range(len(ops))):
            candidate = ops[:i] + ops[i + 1 :]
            result = replay(Scenario(operations=candidate), adapter_factory, strict=strict)
            if violates(result, property_id):
                ops, best, changed = candidate, result, True
    return Scenario(operations=ops), best
