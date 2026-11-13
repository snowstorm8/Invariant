"""Run an exploration end to end: explore, minimise, replay, report."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from hypothesis import HealthCheck, Phase, settings
from hypothesis import seed as hypothesis_seed
from hypothesis.stateful import get_state_machine_test, run_state_machine_as_test

from invariant.adapters.base import Adapter
from invariant.analysis.minimizer import minimize, violates
from invariant.analysis.reproduction import replay
from invariant.core.engine import PropertyViolationError, RunFailure
from invariant.evaluation.violations import Outcome
from invariant.reporting.models import Report
from invariant.reporting.reporter import build_report

from .state_machine import ExplorationSink, build_state_machine


@dataclass
class ExplorationResult:
    outcome: Outcome
    report: Report


def _pick(failures: list[RunFailure]) -> RunFailure | None:
    """Prefer violations over inconclusive runs; within a class, the shortest scenario.

    Hypothesis shrinks and then replays the minimal example last, so among equally
    short candidates the latest one is the final minimal run.
    """
    if not failures:
        return None
    violations = [f for f in failures if isinstance(f, PropertyViolationError)]
    pool = violations or failures
    shortest = min(len(f.history) for f in pool)
    return [f for f in pool if len(f.history) == shortest][-1]


def explore(
    adapter_factory: Callable[[], Adapter],
    *,
    target: str = "target",
    max_examples: int = 200,
    step_count: int = 25,
    seed: int | None = None,
    num_orgs: int = 2,
    strict: bool = True,
) -> ExplorationResult:
    """Search for a violation. ``seed`` makes the search itself repeatable."""
    sink = ExplorationSink()
    machine = build_state_machine(adapter_factory, sink=sink, num_orgs=num_orgs, strict=strict)
    config = settings(
        max_examples=max_examples,
        stateful_step_count=step_count,
        deadline=None,
        database=None,
        report_multiple_bugs=False,
        print_blob=False,
        # Minimisation is done by invariant.analysis.minimizer, which is
        # deterministic and property-aware; Hypothesis' own shrinking only
        # repeats work (and takes minutes on stateful machines).
        phases=[Phase.generate],
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
    )
    try:
        if seed is None:
            run_state_machine_as_test(machine, settings=config)
        else:
            test: Any = get_state_machine_test(machine, settings=config)
            hypothesis_seed(seed)(test)()
    except Exception:
        # Our own failures are reported below; anything else is an infrastructure
        # error and must not be swallowed.
        if not sink.failures:
            raise

    failure = _pick(sink.failures)
    reproduced: bool | None = None
    if failure is not None:
        if isinstance(failure, PropertyViolationError):
            prop_id = next(
                e.property_id for e in failure.record.evaluations if e.outcome is Outcome.VIOLATION
            )
            _, minimal = minimize(
                failure.scenario, adapter_factory, property_id=prop_id, strict=strict
            )
            if minimal.failure is not None and violates(minimal, prop_id):
                failure = minimal.failure
        # Independent replay of exactly what the report will contain.
        again = replay(failure.scenario, adapter_factory, strict=strict)
        reproduced = again.outcome == failure.record.outcome
    report = build_report(
        target=target,
        failure=failure,
        executions=sink.executions,
        seed=seed,
        reproduced=reproduced,
    )
    return ExplorationResult(report.outcome, report)
