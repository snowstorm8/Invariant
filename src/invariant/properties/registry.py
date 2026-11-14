"""Metadata of the built-in rules, by id.

This is a catalog for display and for the reference policy's denial labels. It
is not what decides which rules are evaluated: that is the evaluator's rule set,
which is built at run time (see ``checks.py``).
"""

from __future__ import annotations

from invariant.integrations.builtin_rules import builtin_document

from .base import Property

PROPERTIES: dict[str, Property] = {
    rule.id: Property.from_rule(rule) for rule in builtin_document().rules
}
EXECUTION = Property(
    id="EXEC",
    name="execution-health",
    statement="Operations must yield a usable observation for the outcome to be judged.",
)
