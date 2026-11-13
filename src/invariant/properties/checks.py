"""Implementations of the security properties (TI-1, TI-2, AZ-1).

Metadata and the reference policy live in ``isolation.py`` and
``authorization.py``; this module holds only how each property is judged.
"""

from __future__ import annotations

from invariant.adapters.base import Observation
from invariant.core.scenario import CreateDocument, DeleteDocument, UpdateDocument
from invariant.evaluation.snapshots import diff_snapshots
from invariant.evaluation.violations import Outcome

from .authorization import ROLE_WRITE_PERMISSION
from .base import Evidence, OrgSnapshot, ProbeRequest, SecurityProperty, Step, Verdict
from .isolation import TENANT_READ_ISOLATION, TENANT_WRITE_ISOLATION


class ForeignDataDisclosure(SecurityProperty):
    """No response may contain the marker of another organization's document.

    Judged from the response body alone: a 404 that leaks a marker is a
    violation, a 200 that contains none is not.
    """

    def applies(self, step: Step) -> bool:
        return True

    def evaluate(self, step: Step, response: Observation, evidence: Evidence) -> Verdict:
        leaked = [
            {"doc": d.ref, "owner_org": d.org, "marker": d.marker}
            for d in step.state.foreign_docs(step.actor.org)
            if d.marker in response.body
        ]
        if leaked:
            return Verdict(
                Outcome.VIOLATION,
                (
                    f"{step.actor.ref} ({step.actor.org}) received data of "
                    + ", ".join(f"{x['doc']} (owned by {x['owner_org']})" for x in leaked)
                ),
                {
                    "leaked": leaked,
                    "status": response.status,
                    "response_excerpt": response.excerpt(),
                },
            )
        return Verdict(Outcome.PASS, "no data of other organizations observed in the response")


class ForbiddenWriteIntegrity(SecurityProperty):
    """A write the policy denied must leave the affected organization unchanged.

    Scope comes from the policy decision: the property applies to a write
    exactly when the decision holds a denial for this property, and it reports
    that denial's reason. An operation denied under several properties is
    judged by each of them, on the same snapshot. The expected state is the
    pre-operation model, which is the right expectation only because the
    operation was denied.
    """

    def applies(self, step: Step) -> bool:
        return (
            isinstance(step.op, (CreateDocument, UpdateDocument, DeleteDocument))
            and step.decision.denial_for(self.id) is not None
        )

    def requires(self, step: Step) -> tuple[ProbeRequest, ...]:
        return (OrgSnapshot(self._affected_org(step)),)

    def evaluate(self, step: Step, response: Observation, evidence: Evidence) -> Verdict:
        org = self._affected_org(step)
        denial = step.decision.denial_for(self.id)
        assert denial is not None, "evaluate() is only called when applies() is true"
        reason = denial.reason
        diffs = diff_snapshots(step.state.expected_snapshot(org), evidence[OrgSnapshot(org)])
        if diffs:
            return Verdict(
                Outcome.VIOLATION,
                (
                    f"forbidden operation ({reason}) changed application state "
                    f"of {org}: " + "; ".join(diffs)
                ),
                {
                    "reason": reason,
                    "differences": diffs,
                    "response_status": response.status,
                    "response_excerpt": response.excerpt(),
                },
            )
        return Verdict(
            Outcome.PASS, f"state of {org} unchanged after forbidden operation ({reason})"
        )

    @staticmethod
    def _affected_org(step: Step) -> str:
        """A create lands in the actor's org; an update or delete hits the document's."""
        op = step.op
        if isinstance(op, (UpdateDocument, DeleteDocument)):
            return step.state.doc(op.doc).org
        return step.actor.org


TENANT_READ_ISOLATION_CHECK = ForeignDataDisclosure(TENANT_READ_ISOLATION)
TENANT_WRITE_ISOLATION_CHECK = ForbiddenWriteIntegrity(TENANT_WRITE_ISOLATION)
ROLE_WRITE_PERMISSION_CHECK = ForbiddenWriteIntegrity(ROLE_WRITE_PERMISSION)

#: Evaluation order. The first violation on a step determines how a failure is
#: attributed, so this order is part of observable behaviour.
CHECKS: tuple[SecurityProperty, ...] = (
    TENANT_READ_ISOLATION_CHECK,
    TENANT_WRITE_ISOLATION_CHECK,
    ROLE_WRITE_PERMISSION_CHECK,
)
