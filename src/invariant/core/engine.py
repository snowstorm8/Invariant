"""Execution engine: runs operations against an adapter and judges the result.

The engine is independent of Hypothesis. The state machine (exploration) and
replay (analysis) both drive it, so a scenario found by exploration behaves
identically when replayed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from pydantic import BaseModel, Field

from invariant.adapters.base import Action, Adapter, Call, Observation
from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    ListDocuments,
    Operation,
    ReadDocument,
    Scenario,
    UpdateDocument,
)
from invariant.core.state import DocModel, ModelState, OrgModel, UserModel
from invariant.evaluation.evaluator import Evaluator, ExecutedStep
from invariant.evaluation.violations import Evaluation, Outcome, worst
from invariant.properties.authorization import Decision, decide
from invariant.properties.base import ProbeRequest, Step
from invariant.properties.registry import EXECUTION


class StepRecord(BaseModel):
    """Audit record of one executed operation."""

    index: int
    operation: Operation
    allowed_by_policy: bool
    policy_reason: str
    status: int | None
    error: str | None = None
    response_excerpt: str = ""
    evaluations: list[Evaluation] = Field(default_factory=list)

    @property
    def outcome(self) -> Outcome:
        return worst([e.outcome for e in self.evaluations])


class RunFailure(AssertionError):
    """Base for failures that must stop a run. Carries the evidence."""

    def __init__(self, message: str, record: StepRecord, history: list[StepRecord]) -> None:
        super().__init__(message)
        self.record = record
        self.history = history

    @property
    def scenario(self) -> Scenario:
        return Scenario(operations=[r.operation for r in self.history])


class PropertyViolationError(RunFailure):
    """A security property was violated."""


class InconclusiveError(RunFailure):
    """The run could not be judged; this is never treated as a pass."""


class EngineInvalidatedError(RuntimeError):
    """The engine's reference model is untrustworthy; call ``reset()`` first."""


class Engine:
    def __init__(
        self,
        adapter: Adapter,
        evaluator: Evaluator | None = None,
        *,
        strict: bool = True,
    ) -> None:
        self.adapter = adapter
        self.evaluator = evaluator or Evaluator()
        #: strict: INCONCLUSIVE steps raise, as violations do.
        self.strict = strict
        self.state = ModelState()
        self.history: list[StepRecord] = []
        self._ref_counts: dict[str, int] = {}
        #: Record of every actor operation so far, as rules will see it in
        #: ``events``. Built by the evaluator's binding, never by the engine.
        self._events: list[Mapping[str, Any]] = []
        #: Why the run became invalid (an authorised write could not be verified).
        #: Terminal: only a successful ``reset()`` clears it, because the model
        #: can no longer be trusted and must not be built upon.
        self._invalid: str | None = None
        #: True once a step violated a muted property in a way that may have left the
        #: model and the target disagreeing (a write that went through, or a failed
        #: state check). Callers stop the run there instead of building on it. A muted
        #: violation that only concerns the shape of a response (a header, a status)
        #: leaves the state alone, so the run goes on.
        self.muted_violation = False
        self._state_probing: frozenset[str] = frozenset()

    # -- lifecycle ----------------------------------------------------------

    def reset(self) -> None:
        """Reset the target (verified by the adapter) and forget all model state."""
        # Unusable from the moment a reset starts: if adapter.reset() raises, the
        # target may be partially reset and the engine must not run against it.
        self._invalid = self._invalid or "reset in progress or failed"
        self.adapter.reset()
        self.state = ModelState()
        self.history = []
        self._ref_counts = {}
        self._events = []
        self.muted_violation = False
        self._invalid = None

    def close(self) -> None:
        self.adapter.close()

    def new_ref(self, prefix: str) -> str:
        n = self._ref_counts.get(prefix, 0)
        self._ref_counts[prefix] = n + 1
        return f"{prefix}{n}"

    @property
    def scenario(self) -> Scenario:
        return Scenario(operations=[r.operation for r in self.history])

    # -- execution ----------------------------------------------------------

    def apply(self, op: Operation) -> StepRecord:
        if self._invalid is not None:
            raise EngineInvalidatedError(
                f"engine is invalid ({self._invalid}); reset() before applying more operations"
            )
        index = len(self.history)
        if isinstance(op, (CreateOrg, CreateUser)):
            record = self._apply_setup(index, op)
        else:
            record = self._apply_actor_op(index, op)
        self.history.append(record)
        self._raise_if_failed(record)
        return record

    def _apply_setup(self, index: int, op: CreateOrg | CreateUser) -> StepRecord:
        if isinstance(op, CreateOrg):
            call = Call(action=Action.CREATE_ORG, data={"name": op.name})
        else:
            org = self.state.org(op.org)
            call = Call(
                action=Action.CREATE_USER,
                org_id=org.external_id,
                data={"name": op.ref, "role": op.role.value},
            )
        obs = self.adapter.execute(call)
        body: Any = obs.json_body()
        ok = obs.status is not None and 200 <= obs.status < 300 and isinstance(body, dict)
        if ok and isinstance(op, CreateOrg) and isinstance(body.get("id"), str):
            self.state.orgs[op.ref] = OrgModel(op.ref, body["id"])
        elif (
            ok
            and isinstance(op, CreateUser)
            and isinstance(body.get("id"), str)
            and isinstance(body.get("token"), str)
        ):
            self.state.users[op.ref] = UserModel(op.ref, op.org, op.role, body["id"], body["token"])
        else:
            # Without provisioning the model cannot continue: always inconclusive.
            evaluation = Evaluation(
                property_id=EXECUTION.id,
                outcome=Outcome.INCONCLUSIVE,
                summary=f"provisioning failed for {op.ref}",
                evidence={"status": obs.status, "error": obs.error, "body": obs.excerpt()},
            )
            return self._record(index, op, Decision.permit("provisioning"), obs, [evaluation])
        return self._record(index, op, Decision.permit("provisioning"), obs, [])

    def _apply_actor_op(self, index: int, op: Operation) -> StepRecord:
        assert not isinstance(op, (CreateOrg, CreateUser))
        actor = self.state.user(op.actor)
        decision = decide(self.state, op)
        content = self._payload_content(index, op)
        obs = self.adapter.execute(self._build_call(op, actor, content))

        # Plan, probe, judge. The properties in scope say which evidence they
        # need; the engine only performs the I/O. Planning does not depend on
        # the response, so the probes are taken even if the operation itself
        # got no answer.
        planned = Step(op, actor, decision, self.state, tuple(self._events))
        self._state_probing = self.evaluator.probing(planned)
        probes: dict[ProbeRequest, Observation] = {}
        for request in self.evaluator.plan(planned):
            probe = self._run_probe(request)
            if probe is not None:
                probes[request] = probe

        step = ExecutedStep(op, actor, decision, obs, probes=probes, history=planned.history)
        evaluations = self.evaluator.evaluate(self.state, step)
        # Recorded before the model is updated: later rules see this operation
        # with the resource as it was when the operation was made.
        self._events.append(self.evaluator.binding.event(planned, obs))
        # The model changes only for authorised operations whose effect on the
        # target has been verified; otherwise the run stops as INCONCLUSIVE.
        if decision.allowed and isinstance(op, (CreateDocument, UpdateDocument, DeleteDocument)):
            unverified = self._verify_and_commit(op, actor, obs, content)
            if unverified is not None:
                evaluations.append(unverified)
            if unverified is not None or not obs.responded or (obs.status or 0) >= 500:
                self._invalid = (
                    unverified.summary if unverified is not None else "uncertain write outcome"
                )
        return self._record(index, op, decision, obs, evaluations)

    def _run_probe(self, request: ProbeRequest) -> Observation | None:
        """List the requested org as one of its members.

        None if the org has no member to ask as: the probe cannot be taken, and
        the evaluator reports the properties that needed it as INCONCLUSIVE.
        """
        member = self.state.member_of(request.org)
        if member is None:
            return None
        return self.adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential=member.token))

    @staticmethod
    def _payload_content(index: int, op: Operation) -> str | None:
        """Content to send, tagged with a marker unique to this step."""
        if isinstance(op, (CreateDocument, UpdateDocument)):
            return f"{op.content} <<INV:{index}>>"
        return None

    def _build_call(self, op: Operation, actor: UserModel, content: str | None) -> Call:
        match op:
            case CreateDocument():
                return Call(
                    action=Action.CREATE_DOCUMENT,
                    credential=actor.token,
                    data={"content": content},
                )
            case ReadDocument():
                return self._doc_call(Action.READ_DOCUMENT, actor, op.doc)
            case UpdateDocument():
                return self._doc_call(Action.UPDATE_DOCUMENT, actor, op.doc, {"content": content})
            case DeleteDocument():
                return self._doc_call(Action.DELETE_DOCUMENT, actor, op.doc)
            case ListDocuments():
                return Call(action=Action.LIST_DOCUMENTS, credential=actor.token)
        raise TypeError(f"not an actor operation: {op!r}")

    def _doc_call(
        self, action: Action, actor: UserModel, doc_ref: str, data: dict[str, Any] | None = None
    ) -> Call:
        return Call(
            action=action,
            credential=actor.token,
            resource_id=self.state.doc(doc_ref).external_id,
            data=data or {},
        )

    def _verify_and_commit(
        self,
        op: CreateDocument | UpdateDocument | DeleteDocument,
        actor: UserModel,
        obs: Observation,
        content: str | None,
    ) -> Evaluation | None:
        """Commit an authorised write to the model only if the target proves it.

        The actor lists its own org (every role may) and the listing must equal
        the snapshot the model predicts *after* the transition: a 2xx predicts
        the change, anything else predicts no change. The model is mutated only
        on a match. Returns None when verified (or when there is no usable
        response, which the evaluator already reports), else an INCONCLUSIVE
        evaluation. A failed authorised operation is never a violation.
        """
        if not obs.responded or (obs.status or 0) >= 500:
            return None
        succeeded = obs.status is not None and 200 <= obs.status < 300
        expected = dict(self.state.expected_snapshot(actor.org))
        commit: Callable[[], None] | None = None

        match op:
            case CreateDocument() if succeeded:
                body: Any = obs.json_body()
                doc_id = body.get("id") if isinstance(body, dict) else None
                if not isinstance(doc_id, str):
                    return self._unverified(op, "success response carries no document id", obs)
                assert content is not None
                expected[doc_id] = (content, 1)
                commit = lambda: self._commit_create(op, actor, doc_id, content)  # noqa: E731
            case UpdateDocument() if succeeded:
                doc = self.state.doc(op.doc)
                if not doc.deleted:
                    assert content is not None
                    expected[doc.external_id] = (content, doc.version + 1)
                    commit = lambda: self._commit_update(op, content)  # noqa: E731
            case DeleteDocument() if succeeded:
                doc = self.state.doc(op.doc)
                if not doc.deleted:
                    expected.pop(doc.external_id, None)
                    commit = lambda: self._commit_delete(op)  # noqa: E731

        probe = self.adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential=actor.token))
        diffs = self.evaluator.snapshot_diff(probe, expected)
        if diffs is None:
            return self._unverified(op, "state probe unusable", probe)
        if diffs:
            claim = "reported success" if succeeded else f"returned {obs.status}"
            return self._unverified(
                op,
                f"{claim} but the observed state does not match the expected transition: "
                + "; ".join(diffs),
                obs,
            )
        if commit is not None:
            commit()
        return None

    @staticmethod
    def _unverified(op: Operation, reason: str, obs: Observation) -> Evaluation:
        return Evaluation(
            property_id=EXECUTION.id,
            outcome=Outcome.INCONCLUSIVE,
            summary=f"authorised {op.kind} not verified: {reason}",
            evidence={"status": obs.status, "error": obs.error, "body": obs.excerpt()},
        )

    def _commit_create(
        self, op: CreateDocument, actor: UserModel, doc_id: str, content: str
    ) -> None:
        marker = content[content.rindex("<<INV:") :]
        self.state.docs[op.ref] = DocModel(op.ref, actor.org, doc_id, content, marker)

    def _commit_update(self, op: UpdateDocument, content: str) -> None:
        doc = self.state.doc(op.doc)
        doc.content = content
        doc.marker = content[content.rindex("<<INV:") :]
        doc.version += 1

    def _commit_delete(self, op: DeleteDocument) -> None:
        self.state.doc(op.doc).deleted = True

    def _record(
        self,
        index: int,
        op: Operation,
        decision: Decision,
        obs: Observation,
        evaluations: list[Evaluation],
    ) -> StepRecord:
        return StepRecord(
            index=index,
            operation=op,
            allowed_by_policy=decision.allowed,
            policy_reason=decision.reason,
            status=obs.status,
            error=obs.error,
            response_excerpt=obs.excerpt(),
            evaluations=evaluations,
        )

    def _may_diverge(self, record: StepRecord, evaluation: Evaluation) -> bool:
        """Could this (muted) violation have left the target different from the model?

        Yes for a failed state check, for a write the policy forbids that went through,
        for a write that failed with a server error (nobody knows whether it took
        effect), and when the engine could not verify an authorised write. A muted
        violation about the shape of a response (a header, a cookie, a status) does not.
        """
        if evaluation.property_id in self._state_probing:
            return True
        if not isinstance(record.operation, (CreateDocument, UpdateDocument, DeleteDocument)):
            return False
        if record.status is None or record.status >= 500:
            return True
        if record.status < 300 and not record.allowed_by_policy:
            return True
        return any(
            e.property_id == EXECUTION.id and e.outcome is Outcome.INCONCLUSIVE
            for e in record.evaluations
        )

    def _raise_if_failed(self, record: StepRecord) -> None:
        found = [e for e in record.evaluations if e.outcome is Outcome.VIOLATION]
        violations = [e for e in found if e.property_id not in self.evaluator.muted]
        diverged = any(
            self._may_diverge(record, e) for e in found if e.property_id in self.evaluator.muted
        )
        if diverged:
            self.muted_violation = True
        if violations:
            first = violations[0]
            raise PropertyViolationError(
                f"{first.property_id} violated at step {record.index}: {first.summary}",
                record,
                list(self.history),
            )
        if diverged:
            # The muted failure is why the state check could not be decided; the
            # caller ends this run quietly (``muted_violation``).
            return
        inconclusive = [e for e in record.evaluations if e.outcome is Outcome.INCONCLUSIVE]
        if inconclusive:
            is_setup = isinstance(record.operation, (CreateOrg, CreateUser))
            if self.strict or is_setup or self._invalid is not None:
                first = inconclusive[0]
                raise InconclusiveError(
                    f"inconclusive at step {record.index}: {first.summary}",
                    record,
                    list(self.history),
                )
