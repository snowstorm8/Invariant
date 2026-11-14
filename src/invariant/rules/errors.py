"""Diagnostics raised by the rule language front end."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Diagnostic:
    """One problem in a rule definition, with where it is.

    Text rules are located by ``line``/``col`` (1-based); JSON rules by a
    ``path`` such as ``rules[0].when.args[1]``.
    """

    message: str
    line: int | None = None
    col: int | None = None
    path: str | None = None
    rule: str | None = None

    def __str__(self) -> str:
        where = []
        if self.rule:
            where.append(f'rule "{self.rule}"')
        if self.line is not None:
            where.append(f"line {self.line}" + (f", col {self.col}" if self.col else ""))
        if self.path:
            where.append(self.path)
        return (", ".join(where) + ": " if where else "") + self.message

    def to_json(self) -> dict[str, Any]:
        """JSON form with message, severity and position."""
        return {
            "message": self.message,
            "line": self.line,
            "col": self.col,
            "path": self.path,
            "rule": self.rule,
        }


class RuleError(ValueError):
    """A rule definition was rejected. ``diagnostics`` lists every problem found."""

    def __init__(self, diagnostics: list[Diagnostic]) -> None:
        self.diagnostics = list(diagnostics)
        super().__init__("; ".join(str(d) for d in self.diagnostics) or "invalid rule")


class RuleSyntaxError(RuleError):
    """The definition is not well formed (text grammar or JSON shape)."""


class RuleValidationError(RuleError):
    """The definition is well formed but does not make sense for the target's context."""
