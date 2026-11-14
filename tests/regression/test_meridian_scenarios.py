"""Pinned scenarios for the hidden defects of the Meridian Docs demo application.

Each JSON file is the minimal counterexample Invariant reported for one defect (found with only
that release flag on). It must violate its rule on a build with the flag, and the same sequence
must pass every default rule on the build without it.
"""

from pathlib import Path

import pytest
from meridian_support import DEFECTS, MeridianAdapter, shipped_rules

from invariant.analysis.reproduction import replay
from invariant.core.scenario import Scenario
from invariant.evaluation.evaluator import Evaluator
from invariant.evaluation.violations import Outcome

DIR = Path(__file__).parent / "scenarios" / "meridian"


def _scenario(flag: str) -> Scenario:
    return Scenario.model_validate_json((DIR / f"{flag}.json").read_text())


def test_every_defect_has_a_pinned_scenario():
    assert {p.stem for p in DIR.glob("*.json")} == set(DEFECTS)


@pytest.mark.parametrize(("flag", "rule"), DEFECTS.items())
def test_pinned_scenario_violates_on_the_defective_build(flag, rule):
    evaluator = Evaluator.for_rules(shipped_rules())
    result = replay(_scenario(flag), lambda: MeridianAdapter(frozenset({flag})), evaluator=evaluator)
    assert result.outcome is Outcome.VIOLATION
    assert any(
        e.property_id == rule and e.outcome is Outcome.VIOLATION
        for e in result.failure.record.evaluations
    )


@pytest.mark.parametrize("flag", DEFECTS)
def test_pinned_scenario_passes_on_the_fixed_build(flag):
    evaluator = Evaluator.for_rules(shipped_rules())
    result = replay(_scenario(flag), lambda: MeridianAdapter(frozenset()), evaluator=evaluator)
    assert result.outcome is Outcome.PASS


@pytest.mark.parametrize("flag", DEFECTS)
def test_pinned_scenario_is_minimal(flag):
    """Dropping any single operation either breaks the references or loses the violation."""
    evaluator = Evaluator.for_rules(shipped_rules())
    rule = DEFECTS[flag]
    ops = _scenario(flag).operations
    for i in range(len(ops)):
        shorter = Scenario(operations=[o for j, o in enumerate(ops) if j != i])
        result = replay(shorter, lambda: MeridianAdapter(frozenset({flag})), evaluator=evaluator)
        violated = result.failure is not None and any(
            e.property_id == rule and e.outcome is Outcome.VIOLATION
            for e in result.failure.record.evaluations
        )
        assert not (result.valid and violated), f"{flag}: operation {i} is not needed"
