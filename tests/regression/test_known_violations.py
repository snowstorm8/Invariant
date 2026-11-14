"""Pinned scenarios: once a violation is found, it must stay reproducible.

Each JSON file is a minimal scenario captured from an Invariant report. It must
violate the named property on the defective build and pass on the fixed build.
"""

from pathlib import Path

import pytest

from invariant.analysis.reproduction import replay
from invariant.core.scenario import Scenario
from invariant.evaluation.violations import Outcome
from vulnerable_saas.target import adapter_for, fixed_adapter

DIR = Path(__file__).parent / "scenarios"

CASES = [("stale_cache_read.json", "stale-cache-read", "TI-1")]


@pytest.mark.parametrize(("file", "defect", "prop"), CASES)
def test_pinned_scenario_violates_on_defective_build(file, defect, prop):
    scenario = Scenario.model_validate_json((DIR / file).read_text())
    result = replay(scenario, lambda: adapter_for(frozenset({defect})))
    assert result.outcome is Outcome.VIOLATION
    assert any(
        e.property_id == prop and e.outcome is Outcome.VIOLATION
        for e in result.failure.record.evaluations
    )


@pytest.mark.parametrize(("file", "defect", "prop"), CASES)
def test_pinned_scenario_passes_on_fixed_build(file, defect, prop):
    scenario = Scenario.model_validate_json((DIR / file).read_text())
    assert replay(scenario, fixed_adapter).outcome is Outcome.PASS
