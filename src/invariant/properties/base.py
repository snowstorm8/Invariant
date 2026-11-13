"""Security property definitions and the contract a property implements.

A :class:`SecurityProperty` is a pure judge. It says whether a step is in its
scope, which evidence it needs, and what that evidence shows. It performs no
I/O and holds no state between steps. The framework (``evaluation/``) owns
everything else: taking probes, deciding what to do when evidence is missing or
unusable, stamping the property id on the result, and aggregating outcomes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from invariant.adapters.base import Observation
from invariant.core.scenario import Operation
from invariant.core.state import ModelState, UserModel
from invariant.evaluation.snapshots import Snapshot
from invariant.evaluation.violations import Outcome

if TYPE_CHECKING:
    # authorization.py imports this module; the policy code stays where it is.
    from .authorization import Decision


@dataclass(frozen=True)
class Property:
    id: str
    name: str
    statement: str  # what the software must never allow


@dataclass(frozen=True)
class Step:
    """One actor operation, as known before the target's response is judged."""

    op: Operation
    actor: UserModel
    #: The reference policy's ruling. Properties take authorization scope from
    #: here and never recompute it.
    decision: Decision
    #: Expected state *before* the operation. Read-only by contract.
    state: ModelState


@dataclass(frozen=True)
class OrgSnapshot:
    """Request for a legitimate listing of one organization's documents."""

    org: str  # symbolic org ref


#: The only kind of probe that exists today.
ProbeRequest = OrgSnapshot

#: Usable probe results, keyed by the request that asked for them. A property
#: only ever sees results that were taken and could be parsed.
Evidence = Mapping[ProbeRequest, Snapshot]


@dataclass(frozen=True)
class Verdict:
    """A property's judgement of one step. It carries no property id: the
    framework assigns that when it turns the verdict into an ``Evaluation``."""

    outcome: Outcome
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)


class SecurityProperty(ABC):
    def __init__(self, info: Property) -> None:
        self.info = info

    @property
    def id(self) -> str:
        return self.info.id

    @abstractmethod
    def applies(self, step: Step) -> bool:
        """Is ``step`` in this property's scope? Out of scope means no evaluation."""

    def requires(self, step: Step) -> tuple[ProbeRequest, ...]:
        """Evidence needed to judge ``step``. Only called when ``applies`` is true."""
        return ()

    @abstractmethod
    def evaluate(self, step: Step, response: Observation, evidence: Evidence) -> Verdict:
        """Judge ``step``. Only called when the target responded and every
        request from ``requires`` is present in ``evidence``."""
