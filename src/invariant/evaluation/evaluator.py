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

from dataclasses import dataclass
from typing import Any

from invariant.adapters.base import Observation
from invariant.core.scenario import CreateDocument, DeleteDocument, Operation, UpdateDocument
from invariant.core.state import ModelState, UserModel
from invariant.properties.authorization import Decision
from invariant.properties.isolation import TENANT_READ_ISOLATION
from invariant.properties.registry import EXECUTION, PROPERTIES

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


class Evaluator:
    def evaluate(self, state: ModelState, step: ExecutedStep) -> list[Evaluation]:
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
        results.append(self._confidentiality(state, step))
        if not step.decision.allowed and isinstance(
            step.op, (CreateDocument, UpdateDocument, DeleteDocument)
        ):
            results.append(self._integrity(state, step))
        return results

    # -- TI-1 -------------------------------------------------------------

    def _confidentiality(self, state: ModelState, step: ExecutedStep) -> Evaluation:
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

    # -- TI-2 / AZ-1 ------------------------------------------------------

    def _integrity(self, state: ModelState, step: ExecutedStep) -> Evaluation:
        prop_id = step.decision.property_id
        assert prop_id is not None and prop_id in PROPERTIES
        probe, org = step.probe, step.probe_org
        if probe is None or org is None:
            return self._inconclusive(prop_id, "no state probe was taken after a forbidden write")
        observed = self._parse_snapshot(probe)
        if observed is None:
            return self._inconclusive(
                prop_id,
                "state probe unusable",
                {"status": probe.status, "error": probe.error, "body": probe.excerpt()},
            )
        expected = state.expected_snapshot(org)
        diffs = self._diff(expected, observed)
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

    @staticmethod
    def _parse_snapshot(probe: Observation) -> dict[str, tuple[str, int]] | None:
        if probe.status != 200:
            return None
        body: Any = probe.json_body()
        if not isinstance(body, list):
            return None
        snapshot: dict[str, tuple[str, int]] = {}
        for item in body:
            if not isinstance(item, dict):
                return None
            doc_id, content, version = item.get("id"), item.get("content"), item.get("version")
            if not (
                isinstance(doc_id, str) and isinstance(content, str) and isinstance(version, int)
            ):
                return None
            snapshot[doc_id] = (content, version)
        return snapshot

    @staticmethod
    def _diff(
        expected: dict[str, tuple[str, int]], observed: dict[str, tuple[str, int]]
    ) -> list[str]:
        diffs: list[str] = []
        for doc_id in sorted(expected.keys() - observed.keys()):
            diffs.append(f"{doc_id} expected but missing")
        for doc_id in sorted(observed.keys() - expected.keys()):
            diffs.append(f"{doc_id} present but not expected")
        for doc_id in sorted(expected.keys() & observed.keys()):
            if expected[doc_id] != observed[doc_id]:
                diffs.append(
                    f"{doc_id} expected (content={expected[doc_id][0]!r}, "
                    f"version={expected[doc_id][1]}) observed (content="
                    f"{observed[doc_id][0]!r}, version={observed[doc_id][1]})"
                )
        return diffs

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
