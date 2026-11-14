"""Structured findings."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from invariant.core.engine import StepRecord
from invariant.core.scenario import Scenario
from invariant.evaluation.violations import Outcome

DISCLAIMER = (
    "Invariant performs bounded, randomized testing. A PASS means no violation was "
    "found within the explored scenarios; it is not a proof or security guarantee."
)


class Finding(BaseModel):
    property_id: str
    property_name: str
    statement: str
    outcome: Outcome
    summary: str
    step_index: int
    evidence: dict[str, Any] = Field(default_factory=dict)
    #: Severity the rule declares (critical, high, medium, low, info), if any.
    severity: str | None = None
    #: The minimal scenario for this rule alone, the steps it produced and whether
    #: a fresh replay reproduced it. Set on every entry of ``Report.findings``;
    #: ``Report.scenario`` and friends repeat the first one.
    scenario: Scenario | None = None
    steps: list[StepRecord] = Field(default_factory=list)
    reproduced: bool | None = None


class Report(BaseModel):
    tool: str = "invariant"
    tool_version: str
    target: str
    outcome: Outcome
    executions: int = 0
    seed: int | None = None
    finding: Finding | None = None
    #: Every rule that failed, each with its own minimal counterexample. The
    #: first entry is ``finding``. A run that only had inconclusive steps lists
    #: that single finding.
    findings: list[Finding] = Field(default_factory=list)
    #: Operation sequence that triggers the finding (replayable JSON).
    scenario: Scenario | None = None
    #: Every executed step of the minimal failing run, with its evaluations.
    steps: list[StepRecord] = Field(default_factory=list)
    #: True/False if the scenario was replayed on a fresh target; None if not attempted.
    reproduced: bool | None = None
    #: The rule set the run was judged with, in the JSON rule format, when it
    #: was chosen explicitly. None means the integration's built-in rules.
    #: Replaying the report re-applies exactly these rules.
    rules: list[dict[str, Any]] | None = None
    #: Per rule id, on how many steps the rule was in scope and held (PASS).
    #: A rule absent or at 0 was never exercised, so passing says little.
    held: dict[str, int] = Field(default_factory=dict)
    note: str = DISCLAIMER
