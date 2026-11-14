"""The contract between the rule engine and an application integration.

The rule engine is application-agnostic: it evaluates expressions over whatever
named data it is given. A :class:`RuleBinding` is how an integration supplies
that data. It publishes a :class:`~invariant.rules.types.ContextSchema` (what
rules may refer to) and builds the matching values for each step.

The document SaaS used by the demo is one implementation
(``invariant.integrations.document_saas``); nothing in ``invariant.rules``
knows about organizations, documents or HTTP.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Hashable, Mapping, Sequence
from typing import Any

from .types import ContextSchema
from .values import Value


class RuleBinding(ABC):
    @property
    @abstractmethod
    def schema(self) -> ContextSchema:
        """The roots, fields and probes rules for this integration may use."""

    @abstractmethod
    def context(self, step: Any, response: Any | None) -> Mapping[str, Value]:
        """Values for the schema's roots at ``step``.

        ``response`` is None while the step is being planned; roots the schema
        marks ``late`` are then absent. The values must be plain data and must
        not change while a rule is being evaluated.
        """

    def event(self, step: Any, response: Any) -> Mapping[str, Value]:
        """A self-contained record of a finished step, as later steps will see
        it in their history. Must not alias state that changes afterwards."""
        raise NotImplementedError(f"{type(self).__name__} does not record events")

    def probe_request(self, probe: str, args: Sequence[Value]) -> Hashable:
        """Translate ``observe x = probe(args)`` into the integration's own
        request object, which its engine knows how to execute."""
        raise NotImplementedError(f"{type(self).__name__} offers no probes")

    def probe_value(self, probe: str, raw: Any) -> Value:
        """Turn the result of an executed probe into a rule value."""
        raise NotImplementedError(f"{type(self).__name__} offers no probes")
