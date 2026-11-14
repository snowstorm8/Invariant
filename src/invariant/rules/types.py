"""Types and the context schema a rule is checked against.

The rule language itself knows no application. An integration describes the
data it will hand to rules as a :class:`ContextSchema` (named roots such as
``actor`` or ``response``, each with a type, and the probes it can take), and
supplies matching values at run time (see ``binding.py``). The validator uses
the schema to reject rules that reference fields that do not exist.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Type:
    def describe(self) -> str:
        return "any"


@dataclass(frozen=True)
class AnyType(Type):
    """Shape unknown until run time (e.g. a decoded response body)."""


@dataclass(frozen=True)
class NullType(Type):
    def describe(self) -> str:
        return "null"


@dataclass(frozen=True)
class BoolType(Type):
    def describe(self) -> str:
        return "bool"


@dataclass(frozen=True)
class NumberType(Type):
    integer: bool = False

    def describe(self) -> str:
        return "int" if self.integer else "number"


@dataclass(frozen=True)
class StringType(Type):
    #: If set, the only values the field can take.
    values: tuple[str, ...] | None = None

    def describe(self) -> str:
        if self.values:
            return " | ".join(f'"{v}"' for v in self.values)
        return "string"


@dataclass(frozen=True)
class ListType(Type):
    item: Type = field(default_factory=AnyType)

    def describe(self) -> str:
        return f"list<{self.item.describe()}>"


@dataclass(frozen=True)
class MapType(Type):
    """String-keyed map whose keys are not known in advance."""

    value: Type = field(default_factory=AnyType)

    def describe(self) -> str:
        return f"map<{self.value.describe()}>"


@dataclass(frozen=True)
class Field:
    type: Type
    doc: str = ""
    #: May be absent at run time; reading an absent field is *undefined*.
    optional: bool = False
    #: Root only: known only once the target has responded, so ``when`` and
    #: probe arguments (decided before the response) cannot use it.
    late: bool = False


@dataclass(frozen=True)
class RecordType(Type):
    fields: tuple[tuple[str, Field], ...] = ()

    def field(self, name: str) -> Field | None:
        return dict(self.fields).get(name)

    def describe(self) -> str:
        return "record"


ANY = AnyType()
NULL = NullType()
BOOL = BoolType()
INT = NumberType(integer=True)
NUMBER = NumberType()
STRING = StringType()


def enum(*values: str) -> StringType:
    return StringType(tuple(values))


def record(**fields: Field | Type) -> RecordType:
    return RecordType(
        tuple((name, f if isinstance(f, Field) else Field(f)) for name, f in fields.items())
    )


@dataclass(frozen=True)
class ProbeSpec:
    """An observation of application state the integration can take on request."""

    params: tuple[tuple[str, Type], ...]
    returns: Type
    doc: str = ""


@dataclass(frozen=True)
class ContextSchema:
    """Everything rules for one integration may refer to."""

    name: str
    roots: Mapping[str, Field]
    probes: Mapping[str, ProbeSpec] = field(default_factory=dict)
    description: str = ""

    def describe(self) -> dict[str, Any]:
        """JSON description, used by the console's field reference."""
        return {
            "name": self.name,
            "description": self.description,
            "roots": [_describe_field(name, f) for name, f in self.roots.items()],
            "probes": [
                {
                    "name": name,
                    "params": [{"name": n, "type": t.describe()} for n, t in spec.params],
                    "returns": spec.returns.describe(),
                    "doc": spec.doc,
                }
                for name, spec in self.probes.items()
            ],
        }


def _describe_field(name: str, f: Field, depth: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": name,
        "type": f.type.describe(),
        "doc": f.doc,
        "optional": f.optional,
        "late": f.late,
        "fields": [],
    }
    inner: Type = f.type
    while isinstance(inner, (ListType, MapType)):
        inner = inner.item if isinstance(inner, ListType) else inner.value
    if isinstance(inner, RecordType) and depth < 4:
        if inner is not f.type:
            out["type"] = f.type.describe().replace("record", "{…}")
        out["fields"] = [_describe_field(n, sub, depth + 1) for n, sub in inner.fields]
    return out
