"""Deterministic evaluation of security properties.

Verdicts come from structured observations compared against the expected-state
model, not from HTTP status codes. Properties are rules, interpreted by
``invariant.properties.checks``; which rules are active is decided at run time
(``Evaluator.for_rules``). This module is the framework around them:

* ``plan``: which probes the properties in scope need for a step.
* ``judge``: run each property in scope on the response and its evidence, and
  stamp its id on the result.

The framework, not the properties, decides what missing evidence means.
Anything that prevents a judgement (no response, 5xx, a probe that was not
taken or cannot be parsed) is INCONCLUSIVE, never PASS.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from invariant.adapters.base import Observation
from invariant.core.scenario import CreateDocument, DeleteDocument, Operation, UpdateDocument
from invariant.core.state import ModelState, UserModel
from invariant.properties.authorization import Decision
from invariant.integrations.document_saas import DOCUMENT_SAAS
from invariant.properties.base import ProbeRequest, Property, SecurityProperty, Step
from invariant.properties.checks import CHECKS, checks_for
from invariant.properties.registry import EXECUTION
from invariant.rules.binding import RuleBinding
from invariant.rules.engine import RuleSet

from .snapshots import Snapshot, diff_snapshots, parse_snapshot
from .violations import Evaluation, Outcome


@dataclass
class ExecutedStep:
    """Everything the evaluator may look at for one operation."""

    op: Operation
    actor: UserModel
    decision: Decision
    observation: Observation
    #: Every probe taken for this step, keyed by the request it answers. A
    #: request that could not be executed at all is simply absent.
    probes: Mapping[ProbeRequest, Observation] = field(default_factory=dict)
    #: Earlier actor operations of the run (see ``Step.history``).
    history: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class ProbeFailure:
    """A probe that was taken but cannot be used as evidence."""

    observation: Observation


ProbeResult = Snapshot | ProbeFailure


class Evaluator:
    #: Properties judged on every actor step, in evaluation order. The default
    #: is the integration's built-in rule set; ``for_rules`` replaces it.
    properties: Sequence[SecurityProperty] = CHECKS
    #: Builds the context rules see, and the records kept of finished steps.
    binding: RuleBinding = DOCUMENT_SAAS
    #: The rule set behind ``properties`` when it was chosen at run time.
    rules: RuleSet | None = None
    #: Which policy denials of a write must be judged by a property that asked
    #: for evidence. "all": every one (the built-in set is expected to be
    #: complete). "active": only those naming a property in this evaluator; a
    #: rule the developer switched off is not an error.
    denial_coverage: Literal["all", "active"] = "all"

    def __init__(self, properties: Sequence[SecurityProperty] | None = None) -> None:
        if properties is not None:
            self.properties = tuple(properties)

    @classmethod
    def for_rules(cls, rules: RuleSet, binding: RuleBinding = DOCUMENT_SAAS) -> Evaluator:
        """An evaluator that judges exactly ``rules`` (built-in or user-defined)."""
        evaluator = cls(checks_for(rules, binding))
        evaluator.binding = binding
        evaluator.rules = rules
        evaluator.denial_coverage = "active"
        return evaluator

    @property
    def catalog(self) -> dict[str, Property]:
        """Metadata of every property this evaluator judges, by id."""
        return {prop.id: prop.info for prop in self.properties}

    def plan(self, step: Step) -> list[ProbeRequest]:
        """The probes needed to judge ``step``: what every property in scope
        requires, in evaluation order, each request once.

        Pure, and independent of the target's response, so the calls a scenario
        makes are a function of the scenario and the model alone.
        """
        requests: dict[ProbeRequest, None] = {}
        for prop in self.properties:
            if prop.applies(step):
                requests.update(dict.fromkeys(prop.requires(step)))
        return list(requests)

    def judge(
        self, step: Step, response: Observation, probes: Mapping[ProbeRequest, Observation]
    ) -> list[Evaluation]:
        """Judge one step against every property in scope.

        ``probes`` holds the raw observation for each planned request that was
        executed. The framework owns EXEC, evidence validation, property id
        attribution and ordering; each property only supplies its scope, its
        evidence requirements and a verdict. No I/O happens here.
        """
        # Whether the property set can account for the policy's denials does not
        # depend on the target, so it is checked before anything else, including
        # the no-response shortcut below.
        self._require_denials_covered(step)
        if not response.responded:
            return [self._inconclusive(EXECUTION.id, f"no response: {response.error}")]

        results: list[Evaluation] = []
        if response.status is not None and response.status >= 500:
            results.append(
                self._inconclusive(
                    EXECUTION.id,
                    f"server error {response.status}; outcome of the operation is unknown",
                    {"body": response.excerpt()},
                )
            )
        parsed = {request: self._probe_result(probe) for request, probe in probes.items()}
        for prop in self.properties:
            if not prop.applies(step):
                continue
            results.append(self._judge(prop, step, response, prop.requires(step), parsed))
        return results

    def _require_denials_covered(self, step: Step) -> None:
        """A write the policy denied can only be judged from the state it left
        behind. If a denial names a property that did not ask for that
        evidence, the property is not implemented: fail loudly rather than
        report nothing about it. Depends only on the step and the configured
        properties, never on the response."""
        if not isinstance(step.op, (CreateDocument, UpdateDocument, DeleteDocument)):
            return
        judged_from_evidence = {
            prop.id for prop in self.properties if prop.applies(step) and prop.requires(step)
        }
        unjudged = [i for i in step.decision.property_ids if i not in judged_from_evidence]
        if self.denial_coverage == "active":
            active = {prop.id for prop in self.properties}
            unjudged = [i for i in unjudged if i in active]
        assert not unjudged, f"denied write attributed to {unjudged}, which no property evaluates"

    def evaluate(self, state: ModelState, step: ExecutedStep) -> list[Evaluation]:
        """Judge an executed step: ``judge`` on the probes it carries."""
        planned = Step(step.op, step.actor, step.decision, state, step.history)
        return self.judge(planned, step.observation, step.probes)

    @staticmethod
    def _probe_result(probe: Observation) -> ProbeResult:
        snapshot = parse_snapshot(probe)
        return ProbeFailure(probe) if snapshot is None else snapshot

    def _judge(
        self,
        prop: SecurityProperty,
        step: Step,
        response: Observation,
        requests: tuple[ProbeRequest, ...],
        probes: Mapping[ProbeRequest, ProbeResult],
    ) -> Evaluation:
        """One property's evaluation. Missing or unusable evidence is decided
        here, so a property is never asked to judge without it."""
        evidence: dict[ProbeRequest, Snapshot] = {}
        for request in requests:
            result = probes.get(request)
            if result is None:
                return self._inconclusive(
                    prop.id, "no state probe was taken after a forbidden write"
                )
            if isinstance(result, ProbeFailure):
                probe = result.observation
                return self._inconclusive(
                    prop.id,
                    "state probe unusable",
                    {"status": probe.status, "error": probe.error, "body": probe.excerpt()},
                )
            evidence[request] = result
        verdict = prop.evaluate(step, response, evidence)
        return Evaluation(
            property_id=prop.id,
            outcome=verdict.outcome,
            summary=verdict.summary,
            evidence=verdict.evidence,
        )

    def snapshot_diff(self, probe: Observation, expected: Snapshot) -> list[str] | None:
        """Differences between a listing observation and ``expected``.

        None means the probe is unusable (no response, non-200, malformed).
        """
        observed = parse_snapshot(probe)
        return None if observed is None else diff_snapshots(expected, observed)

    @staticmethod
    def _inconclusive(
        property_id: str, summary: str, evidence: dict[str, Any] | None = None
    ) -> Evaluation:
        return Evaluation(
            property_id=property_id,
            outcome=Outcome.INCONCLUSIVE,
            summary=summary,
            evidence=evidence or {},
        )


def evaluator_for_report(
    rules: list[dict[str, Any]] | None, binding: RuleBinding = DOCUMENT_SAAS
) -> Evaluator:
    """The evaluator a saved report was judged with.

    ``rules`` is ``Report.rules``: the rule set in JSON form, or None when the
    run used the integration's built-in rules. Raises ``RuleError`` if the
    stored rules no longer validate.
    """
    if rules is None:
        return Evaluator()
    return Evaluator.for_rules(RuleSet.from_json({"rules": rules}, binding.schema), binding)
