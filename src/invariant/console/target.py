"""What the console needs to know about the application under test.

An integration describes its target once (a name, the builds it can produce and
how to make an adapter for one) and the console offers that in its Run panel.
The demo app's description lives with the demo, in
``examples/vulnerable_saas/target.py``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from invariant.adapters.base import Adapter
from invariant.integrations.document_saas import DOCUMENT_SAAS
from invariant.rules.binding import RuleBinding


@dataclass(frozen=True)
class TargetOption:
    """A switch on the target build (for the demo app: one seeded defect)."""

    id: str
    title: str
    description: str = ""
    #: Id of the built-in rule this option is expected to trip, if any.
    property: str = ""


@dataclass(frozen=True)
class ConsoleTarget:
    name: str
    #: Makes a fresh adapter for a build with exactly these options switched on.
    adapter_for: Callable[[frozenset[str]], Adapter]
    options: tuple[TargetOption, ...] = ()
    description: str = ""
    #: Supplies the context rules are written against.
    binding: RuleBinding = field(default=DOCUMENT_SAAS)
    #: Called when the console stops using this target (a project's process is stopped here).
    close: Callable[[], None] | None = None

    def label(self, options: frozenset[str]) -> str:
        if not self.options:
            return self.name  # an application as it is: there are no builds to choose from
        return f"{self.name}[" + (",".join(sorted(options)) or "fixed") + "]"

    def parse_options(self, raw: object) -> frozenset[str]:
        if not isinstance(raw, list) or not all(isinstance(o, str) for o in raw):
            raise ValueError("options must be a list of strings")
        chosen = frozenset(raw)
        unknown = chosen - {o.id for o in self.options}
        if unknown:
            raise ValueError(f"unknown options: {sorted(unknown)}")
        return chosen
