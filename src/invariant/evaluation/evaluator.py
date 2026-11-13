"""Deterministic evaluation of security properties.

Verdicts come from structured observations compared against the expected-state
model, not from HTTP status codes. How each property is judged lives in
``invariant.properties.checks``; this module is the framework around them:

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
from typing import Any

from invariant.adapters.base import Observation
from invariant.core.scenario import CreateDocument, DeleteDocument, Operation, UpdateDocument
from invariant.core.state import ModelState, UserModel
from invariant.properties.authorization import Decision
from invariant.properties.base import ProbeRequest, SecurityProperty, Step
from invariant.properties.checks import CHECKS
from invariant.properties.registry import EXECUTION

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


@dataclass(frozen=True)
class ProbeFailure:
    """A probe that was taken but cannot be used as evidence."""

    observation: Observation


ProbeResult = Snapshot | ProbeFailure


class Evaluator:
    #: Properties judged on every actor step, in evaluation order.
    properties: Sequence[SecurityProperty] = CHECKS

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
        requested_evidence = False
        for prop in self.properties:
            if not prop.applies(step):
                continue
            requests = prop.requires(step)
            requested_evidence = requested_evidence or bool(requests)
            results.append(self._judge(prop, step, response, requests, parsed))
        # A write the policy denied can only be judged from the state it left
        # behind. If no property asked for that evidence, the decision names a
        # property that is not implemented: fail loudly rather than report
        # nothing about the write.
        if not step.decision.allowed and isinstance(
            step.op, (CreateDocument, UpdateDocument, DeleteDocument)
        ):
            assert requested_evidence, (
                f"denied write attributed to {step.decision.property_id!r}, "
                "which no property evaluates"
            )
        return results

    def evaluate(self, state: ModelState, step: ExecutedStep) -> list[Evaluation]:
        """Judge an executed step: ``judge`` on the probes it carries."""
        planned = Step(step.op, step.actor, step.decision, state)
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
