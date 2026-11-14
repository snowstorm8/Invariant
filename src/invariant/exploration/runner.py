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
from invariant.evaluation.evaluator import Evaluator
from invariant.evaluation.violations import Outcome
from invariant.reporting.models import Report
from invariant.reporting.reporter import Confirmed, build_report, primary_evaluation
from invariant.rules.engine import RuleSet

from .state_machine import ExplorationSink, build_state_machine


@dataclass
class ExplorationResult:
    """The outcome of an exploration and its report."""
    outcome: Outcome
    report: Report


def _pick(failures: list[RunFailure]) -> RunFailure | None:
    """Prefer violations over inconclusive runs; within a class, the shortest scenario.

    Failures are collected in the order they occurred (Hypothesis runs generate-only,
    so there is no shrink phase); among equally short candidates the latest one wins.
    """
    if not failures:
        return None
    violations = [f for f in failures if isinstance(f, PropertyViolationError)]
    pool = violations or failures
    shortest = min(len(f.history) for f in pool)
    return [f for f in pool if len(f.history) == shortest][-1]


def _search(
    adapter_factory: Callable[[], Adapter],
    evaluator: Evaluator,
    *,
    max_examples: int,
    step_count: int,
    seed: int | None,
    num_orgs: int,
    strict: bool,
) -> tuple[ExplorationSink, RunFailure | None]:
    """One Hypothesis search; the failure it picked, if any."""
    sink = ExplorationSink()
    machine = build_state_machine(
        adapter_factory, sink=sink, num_orgs=num_orgs, strict=strict, evaluator=evaluator
    )
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
    return sink, _pick(sink.failures)


def explore(
    adapter_factory: Callable[[], Adapter],
    *,
    target: str = "target",
    max_examples: int = 200,
    step_count: int = 25,
    seed: int | None = None,
    num_orgs: int = 2,
    strict: bool = True,
    rules: RuleSet | None = None,
) -> ExplorationResult:
    """Search for violations. ``seed`` makes the search itself repeatable.

    ``rules`` is the rule set to hold the target to: any mix of built-in and
    user-defined rules. Every step of every generated sequence is judged by all
    of them.

    Every rule that fails is reported, each with its own minimal counterexample,
    not just the first. A search stops at the first failing step, so once rules
    have failed the search is repeated with those rules muted (still evaluated,
    but no longer stopping the run) until a search finds nothing new or every
    rule has been reported.
    """
    evaluator = Evaluator.for_rules(rules) if rules is not None else Evaluator()
    confirmed: list[Confirmed] = []
    reported: list[str] = []
    executions = 0
    held: dict[str, int] = {}
    for _ in range(len(evaluator.properties) + 1):
        sink, failure = _search(
            adapter_factory,
            evaluator.muting(reported),
            max_examples=max_examples,
            step_count=step_count,
            seed=seed,
            num_orgs=num_orgs,
            strict=strict,
        )
        executions += sink.executions
        for rule_id, count in sink.held.items():
            held[rule_id] = max(held.get(rule_id, 0), count)
        if failure is None:
            break
        if not isinstance(failure, PropertyViolationError):
            # Nothing could be judged. That is the answer only if nothing else
            # was found; otherwise the findings stand.
            if not confirmed:
                again = replay(failure.scenario, adapter_factory, strict=strict, evaluator=evaluator)
                confirmed.append(
                    Confirmed(
                        failure,
                        primary_evaluation(failure.record).property_id,
                        again.outcome == failure.record.outcome,
                    )
                )
            break
        violated = [
            e.property_id
            for e in failure.record.evaluations
            if e.outcome is Outcome.VIOLATION and e.property_id not in reported
        ]
        reported += violated
        for prop_id in violated:
            confirmed.append(
                _confirm(
                    failure,
                    prop_id,
                    adapter_factory,
                    # Everything else already reported is muted, so the replay
                    # stops on this rule and no other.
                    evaluator.muting(set(reported) - {prop_id}),
                    strict=strict,
                )
            )
    report = build_report(
        target=target,
        failure=confirmed[0].failure if confirmed else None,
        executions=executions,
        seed=seed,
        reproduced=confirmed[0].reproduced if confirmed else None,
        properties=evaluator.catalog,
        rules=rules,
        confirmed=confirmed,
        held=held,
    )
    return ExplorationResult(report.outcome, report)


def _confirm(
    failure: RunFailure,
    prop_id: str,
    adapter_factory: Callable[[], Adapter],
    evaluator: Evaluator,
    *,
    strict: bool,
) -> Confirmed:
    """Minimise ``failure`` for ``prop_id`` alone and replay what the report will hold."""
    _, minimal = minimize(
        failure.scenario, adapter_factory, property_id=prop_id, strict=strict, evaluator=evaluator
    )
    if minimal.failure is not None and violates(minimal, prop_id):
        failure = minimal.failure
    # Independent replay of exactly what the report will contain.
    again = replay(failure.scenario, adapter_factory, strict=strict, evaluator=evaluator)
    return Confirmed(failure, prop_id, again.outcome == failure.record.outcome)
