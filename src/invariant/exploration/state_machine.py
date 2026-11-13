"""Hypothesis stateful exploration.

Hypothesis only chooses *which operations to try and with which arguments*. It
knows nothing about security: every judgement is made by the Engine/Evaluator,
and a violation surfaces as an exception that Hypothesis then shrinks.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from hypothesis.stateful import (
    Bundle,
    MultipleResults,
    RuleBasedStateMachine,
    initialize,
    multiple,
    rule,
)

from invariant.adapters.base import Adapter
from invariant.core.engine import Engine, RunFailure, StepRecord
from invariant.core.scenario import (
    CreateDocument,
    CreateOrg,
    CreateUser,
    DeleteDocument,
    ListDocuments,
    Operation,
    ReadDocument,
    Role,
    UpdateDocument,
)

from .operations import contents, roles


@dataclass
class ExplorationSink:
    """Collects what happened across all Hypothesis executions of one exploration."""

    executions: int = 0
    failures: list[RunFailure] = field(default_factory=list)


def build_state_machine(
    adapter_factory: Callable[[], Adapter],
    *,
    sink: ExplorationSink,
    num_orgs: int = 2,
    strict: bool = True,
) -> type[RuleBasedStateMachine]:
    """Create a state machine class bound to a target.

    ``adapter_factory`` is called once per Hypothesis execution, so every
    execution starts from a fresh target; ``Engine.reset`` then verifies it.
    """

    class InvariantMachine(RuleBasedStateMachine):
        orgs: Bundle[str] = Bundle("orgs")
        users: Bundle[str] = Bundle("users")
        docs: Bundle[str] = Bundle("docs")

        def __init__(self) -> None:
            super().__init__()
            sink.executions += 1
            self.engine = Engine(adapter_factory(), strict=strict)
            self.engine.reset()

        def _apply(self, op: Operation) -> StepRecord:
            try:
                return self.engine.apply(op)
            except RunFailure as failure:
                sink.failures.append(failure)
                raise

        @initialize(target=orgs)
        def provision_orgs(self) -> MultipleResults[str]:
            refs = []
            for _ in range(num_orgs):
                ref = self.engine.new_ref("org")
                self._apply(CreateOrg(ref=ref, name=ref))
                refs.append(ref)
            return multiple(*refs)

        @rule(target=users, org=orgs, role=roles)
        def create_user(self, org: str, role: Role) -> str:
            ref = self.engine.new_ref("user")
            self._apply(CreateUser(ref=ref, org=org, role=role))
            return ref

        @rule(target=docs, actor=users, content=contents)
        def create_document(self, actor: str, content: str) -> str | MultipleResults[str]:
            ref = self.engine.new_ref("doc")
            self._apply(CreateDocument(ref=ref, actor=actor, content=content))
            return ref if ref in self.engine.state.docs else multiple()

        @rule(actor=users, doc=docs)
        def read_document(self, actor: str, doc: str) -> None:
            self._apply(ReadDocument(actor=actor, doc=doc))

        @rule(actor=users, doc=docs, content=contents)
        def update_document(self, actor: str, doc: str, content: str) -> None:
            self._apply(UpdateDocument(actor=actor, doc=doc, content=content))

        @rule(actor=users, doc=docs)
        def delete_document(self, actor: str, doc: str) -> None:
            self._apply(DeleteDocument(actor=actor, doc=doc))

        @rule(actor=users)
        def list_documents(self, actor: str) -> None:
            self._apply(ListDocuments(actor=actor))

        def teardown(self) -> None:
            self.engine.close()

    return InvariantMachine
