"""Deterministic evaluation of security properties.

Verdicts come from structured observations compared against the expected-state
model, not from HTTP status codes:

* Confidentiality (TI-1): every response body is scanned for the unique marker
  of documents owned by *other* organizations. A 404 whose body leaks a marker
  is a violation; a 200 that contains none is not.
* Integrity (TI-2, AZ-1): after an operation the policy forbids, the evaluator
  inspects a *state probe* (a legitimate listing of the affected org) and
  compares it with the model. A 403 that still changed state is a violation.

Anything that prevents a judgement (no response, 5xx, unusable probe) is
INCONCLUSIVE, never PASS.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from invariant.adapters.base import Observation
from invariant.core.scenario import CreateDocument, DeleteDocument, Operation, UpdateDocument
from invariant.core.state import ModelState, UserModel
from invariant.properties.authorization import Decision
from invariant.properties.base import OrgSnapshot, ProbeRequest, SecurityProperty, Step
from invariant.properties.checks import CHECKS
from invariant.properties.isolation import TENANT_READ_ISOLATION
from invariant.properties.registry import EXECUTION, PROPERTIES

from .snapshots import Snapshot, diff_snapshots, parse_snapshot
from .violations import Evaluation, Outcome


@dataclass
class ExecutedStep:
    """Everything the evaluator may look at for one operation."""

    op: Operation
    actor: UserModel
    decision: Decision
    observation: Observation
    #: Observation of a legitimate listing of ``probe_org``, taken after an
    #: operation that the policy forbids. None if no probe was taken.
    probe: Observation | None = None
    probe_org: str | None = None


@dataclass(frozen=True)
class ProbeFailure:
    """A probe that was taken but cannot be used as evidence."""

    observation: Observation


ProbeResult = Snapshot | ProbeFailure


class Evaluator:
    #: Properties judged on every actor step, in evaluation order.
    properties: Sequence[SecurityProperty] = CHECKS

    def evaluate(self, state: ModelState, step: ExecutedStep) -> list[Evaluation]:
        """Judge one executed step against every property in scope.

        The framework owns EXEC, evidence validation, property id attribution
        and ordering; each property only supplies its scope, its evidence
        requirements and a verdict. No I/O happens here: the probe the engine
        already took is adapted into the evidence the properties asked for.
        """
        obs = step.observation
        if not obs.responded:
            return [self._inconclusive(EXECUTION.id, f"no response: {obs.error}")]

        results: list[Evaluation] = []
        if obs.status is not None and obs.status >= 500:
            results.append(
                self._inconclusive(
                    EXECUTION.id,
                    f"server error {obs.status}; outcome of the operation is unknown",
                    {"body": obs.excerpt()},
                )
            )
        planned = Step(step.op, step.actor, step.decision, state)
        probes = self._probe_results(step)
        requested_evidence = False
        for prop in self.properties:
            if not prop.applies(planned):
                continue
            requests = prop.requires(planned)
            requested_evidence = requested_evidence or bool(requests)
            results.append(self._judge(prop, planned, obs, requests, probes))
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

    @staticmethod
    def _probe_results(step: ExecutedStep) -> dict[ProbeRequest, ProbeResult]:
        """The probe the engine took, keyed by the request it answers."""
        if step.probe is None or step.probe_org is None:
            return {}
        snapshot = parse_snapshot(step.probe)
        return {
            OrgSnapshot(step.probe_org): (
                ProbeFailure(step.probe) if snapshot is None else snapshot
            )
        }

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

    # -- legacy reference ---------------------------------------------------
    # The implementation before properties were extracted. Kept only so the
    # differential tests can compare against it; nothing in src/ calls it.

    def _legacy_evaluate(self, state: ModelState, step: ExecutedStep) -> list[Evaluation]:
        obs = step.observation
        if not obs.responded:
            return [self._inconclusive(EXECUTION.id, f"no response: {obs.error}")]

        results: list[Evaluation] = []
        if obs.status is not None and obs.status >= 500:
            results.append(
                self._inconclusive(
                    EXECUTION.id,
                    f"server error {obs.status}; outcome of the operation is unknown",
                    {"body": obs.excerpt()},
                )
            )
        results.append(self._legacy_confidentiality(state, step))
        if not step.decision.allowed and isinstance(
            step.op, (CreateDocument, UpdateDocument, DeleteDocument)
        ):
            results.append(self._legacy_integrity(state, step))
        return results


    def _legacy_confidentiality(self, state: ModelState, step: ExecutedStep) -> Evaluation:
        obs = step.observation
        leaked = [
            {"doc": d.ref, "owner_org": d.org, "marker": d.marker}
            for d in state.foreign_docs(step.actor.org)
            if d.marker in obs.body
        ]
        if leaked:
            return Evaluation(
                property_id=TENANT_READ_ISOLATION.id,
                outcome=Outcome.VIOLATION,
                summary=(
                    f"{step.actor.ref} ({step.actor.org}) received data of "
                    + ", ".join(f"{x['doc']} (owned by {x['owner_org']})" for x in leaked)
                ),
                evidence={
                    "leaked": leaked,
                    "status": obs.status,
                    "response_excerpt": obs.excerpt(),
                },
            )
        return Evaluation(
            property_id=TENANT_READ_ISOLATION.id,
            outcome=Outcome.PASS,
            summary="no data of other organizations observed in the response",
        )


    def _legacy_integrity(self, state: ModelState, step: ExecutedStep) -> Evaluation:
        prop_id = step.decision.property_id
        assert prop_id is not None and prop_id in PROPERTIES
        probe, org = step.probe, step.probe_org
        if probe is None or org is None:
            return self._inconclusive(prop_id, "no state probe was taken after a forbidden write")
        observed = parse_snapshot(probe)
        if observed is None:
            return self._inconclusive(
                prop_id,
                "state probe unusable",
                {"status": probe.status, "error": probe.error, "body": probe.excerpt()},
            )
        expected = state.expected_snapshot(org)
        diffs = diff_snapshots(expected, observed)
        if diffs:
            return Evaluation(
                property_id=prop_id,
                outcome=Outcome.VIOLATION,
                summary=(
                    f"forbidden operation ({step.decision.reason}) changed application state "
                    f"of {org}: " + "; ".join(diffs)
                ),
                evidence={
                    "reason": step.decision.reason,
                    "differences": diffs,
                    "response_status": step.observation.status,
                    "response_excerpt": step.observation.excerpt(),
                },
            )
        return Evaluation(
            property_id=prop_id,
            outcome=Outcome.PASS,
            summary=f"state of {org} unchanged after forbidden operation ({step.decision.reason})",
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
