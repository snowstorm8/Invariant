"""Intermediate representation of security rules.

Both front ends (the text language in ``parser.py`` and the JSON format in
``jsonio.py``) produce exactly these objects, and the interpreter evaluates
nothing else. Nodes are immutable and compare structurally; ``loc`` records
where a node came from and is ignored by comparison, so a rule written as text
equals the same rule imported from JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_SEVERITY = "medium"

UNARY_OPS = ("not", "-")
BINARY_OPS = ("and", "or", "implies", "==", "!=", "<", "<=", ">", ">=", "in", "+", "-", "*")
QUANTIFIERS = ("some", "every", "none")
ASSERTION_KINDS = ("always", "never")


@dataclass(frozen=True)
class Loc:
    line: int | None = None
    col: int | None = None
    path: str | None = None


def _loc() -> Any:
    return field(default=None, compare=False, repr=False, kw_only=True)


@dataclass(frozen=True)
class Literal:
    value: None | bool | int | float | str
    loc: Loc | None = _loc()

    def __eq__(self, other: object) -> bool:
        # bool is an int in Python; `true` and `1` are different literals here.
        return (
            isinstance(other, Literal)
            and type(self.value) is type(other.value)
            and self.value == other.value
        )

    def __hash__(self) -> int:
        return hash((type(self.value).__name__, self.value))


@dataclass(frozen=True)
class Ref:
    """A name: a context root, a ``let``, an ``observe`` or a bound variable."""

    name: str
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Member:
    target: Expr
    name: str
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Index:
    target: Expr
    key: Expr
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class ListExpr:
    items: tuple[Expr, ...]
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class RecordExpr:
    fields: tuple[tuple[str, Expr], ...]
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Unary:
    op: str
    operand: Expr
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Binary:
    op: str
    left: Expr
    right: Expr
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Call:
    function: str
    args: tuple[Expr, ...]
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Quantifier:
    """``some|every|none VAR in SOURCE : CONDITION``."""

    kind: str
    var: str
    source: Expr
    condition: Expr
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Comprehension:
    """``[VALUE for VAR in SOURCE where CONDITION]``."""

    value: Expr
    var: str
    source: Expr
    condition: Expr | None = None
    loc: Loc | None = _loc()


Expr = (
    Literal
    | Ref
    | Member
    | Index
    | ListExpr
    | RecordExpr
    | Unary
    | Binary
    | Call
    | Quantifier
    | Comprehension
)


@dataclass(frozen=True)
class Let:
    name: str
    value: Expr
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Observe:
    """Ask the integration for a named observation of application state,
    taken after the operation. ``args`` are decided before the response."""

    name: str
    probe: str
    args: tuple[Expr, ...]
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Assertion:
    kind: str  # "always" (must hold) or "never" (must not hold)
    condition: Expr
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Template:
    """Message text with interpolated expressions."""

    parts: tuple[str | Expr, ...]
    loc: Loc | None = _loc()


@dataclass(frozen=True)
class Rule:
    name: str
    id: str
    description: str = ""
    severity: str = DEFAULT_SEVERITY
    when: Expr | None = None
    bindings: tuple[Let | Observe, ...] = ()
    assertions: tuple[Assertion, ...] = ()
    message: Template | None = None
    pass_message: Template | None = None
    evidence: tuple[tuple[str, Expr], ...] | None = None
    loc: Loc | None = _loc()

    @property
    def lets(self) -> tuple[Let, ...]:
        return tuple(b for b in self.bindings if isinstance(b, Let))

    @property
    def observes(self) -> tuple[Observe, ...]:
        return tuple(b for b in self.bindings if isinstance(b, Observe))


@dataclass(frozen=True)
class RuleDocument:
    """What one source (a text buffer or a JSON file) defines."""

    rules: tuple[Rule, ...]
    #: Ids of rules the source marks as disabled (JSON ``"enabled": false``).
    disabled: frozenset[str] = frozenset()
