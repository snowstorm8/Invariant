"""Execution engine: runs operations against an adapter and judges the result.

The engine is independent of Hypothesis. The state machine (exploration) and
replay (analysis) both drive it, so a scenario found by exploration behaves
identically when replayed.
"""

from __future__ import annotations

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

    # -- lifecycle ----------------------------------------------------------

    def reset(self) -> None:
        """Reset the target (verified by the adapter) and forget all model state."""
        self.adapter.reset()
        self.state = ModelState()
        self.history = []
        self._ref_counts = {}

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
            return self._record(index, op, Decision(True, "provisioning"), obs, [evaluation])
        return self._record(index, op, Decision(True, "provisioning"), obs, [])

    def _apply_actor_op(self, index: int, op: Operation) -> StepRecord:
        assert not isinstance(op, (CreateOrg, CreateUser))
        actor = self.state.user(op.actor)
        decision = decide(self.state, op)
        content = self._payload_content(index, op)
        obs = self.adapter.execute(self._build_call(op, actor, content))

        probe: Observation | None = None
        probe_org: str | None = None
        if not decision.allowed and isinstance(
            op, (CreateDocument, UpdateDocument, DeleteDocument)
        ):
            probe_org = (
                actor.org if isinstance(op, CreateDocument) else self.state.doc(op.doc).org
            )
            member = self.state.member_of(probe_org)
            if member is not None:
                probe = self.adapter.execute(
                    Call(action=Action.LIST_DOCUMENTS, credential=member.token)
                )

        step = ExecutedStep(op, actor, decision, obs, probe, probe_org)
        evaluations = self.evaluator.evaluate(self.state, step)
        # The model changes only for operations the policy authorised.
        if decision.allowed:
            self._sync_model(op, actor, obs, content)
        return self._record(index, op, decision, obs, evaluations)

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

    def _sync_model(
        self, op: Operation, actor: UserModel, obs: Observation, content: str | None
    ) -> None:
        """Mirror an *authorised* operation into the expected state.

        This is the one place a status code is consulted, and only to keep the
        model in step with what the target accepted; it is never used to decide
        whether a property holds.
        """
        succeeded = obs.status is not None and 200 <= obs.status < 300
        if not succeeded:
            return
        body: Any = obs.json_body()
        match op:
            case CreateDocument() if isinstance(body, dict) and isinstance(body.get("id"), str):
                assert content is not None
                marker = content[content.rindex("<<INV:") :]
                self.state.docs[op.ref] = DocModel(
                    op.ref, actor.org, body["id"], content, marker
                )
            case UpdateDocument():
                doc = self.state.doc(op.doc)
                if not doc.deleted:
                    assert content is not None
                    doc.content = content
                    doc.marker = content[content.rindex("<<INV:") :]
                    doc.version += 1
            case DeleteDocument():
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

    def _raise_if_failed(self, record: StepRecord) -> None:
        violations = [e for e in record.evaluations if e.outcome is Outcome.VIOLATION]
        if violations:
            first = violations[0]
            raise PropertyViolationError(
                f"{first.property_id} violated at step {record.index}: {first.summary}",
                record,
                list(self.history),
            )
        inconclusive = [e for e in record.evaluations if e.outcome is Outcome.INCONCLUSIVE]
        if inconclusive:
            is_setup = isinstance(record.operation, (CreateOrg, CreateUser))
            if self.strict or is_setup:
                first = inconclusive[0]
                raise InconclusiveError(
                    f"inconclusive at step {record.index}: {first.summary}",
                    record,
                    list(self.history),
                )
