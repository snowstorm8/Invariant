"""Run-time values of the rule language.

Values are plain JSON-like Python data: ``None``, ``bool``, ``int``, ``float``,
``str``, sequences and string-keyed mappings. The one addition is
:class:`Undefined`: the result of reading something that is not there (a field
the response does not carry, a resource the operation does not have). It is not
an error and not ``false``; it flows through expressions, and a rule whose
verdict depends on it is INCONCLUSIVE rather than PASS or VIOLATION.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any


class Undefined:
    """A value that is missing; verdicts depending on it are INCONCLUSIVE."""
    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def __repr__(self) -> str:
        return f"Undefined({self.reason!r})"

    def __bool__(self) -> bool:
        raise TypeError("an undefined rule value has no truth value")


Value = Any


def is_number(value: object) -> bool:
    """True for numbers (booleans are not numbers)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_list(value: object) -> bool:
    """True for rule lists."""
    return isinstance(value, (list, tuple))


def is_map(value: object) -> bool:
    """True for rule records."""
    return isinstance(value, Mapping)


def kind_of(value: object) -> str:
    """The rule-language name of a value's kind."""
    if isinstance(value, Undefined):
        return "undefined"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if is_number(value):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if is_list(value):
        return "a list"
    if is_map(value):
        return "an object"
    return type(value).__name__


def equal(a: Value, b: Value) -> bool:
    """Structural equality with no cross-type coercion (``1 != true``, ``1 == 1.0``)."""
    if is_number(a) and is_number(b):
        return bool(a == b)
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if is_list(a) and is_list(b):
        return len(a) == len(b) and all(equal(x, y) for x, y in zip(a, b, strict=True))
    if is_map(a) and is_map(b):
        return a.keys() == b.keys() and all(equal(a[k], b[k]) for k in a)
    return False


def plain(value: Value) -> Any:
    """A JSON-serialisable copy (for evidence). Undefined becomes ``None``."""
    if isinstance(value, Undefined):
        return None
    if is_map(value):
        return {str(k): plain(v) for k, v in value.items()}
    if is_list(value):
        return [plain(v) for v in value]
    return value


def render(value: Value) -> str:
    """Text of a value inside a message."""
    if isinstance(value, Undefined):
        return "<undefined>"
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if is_number(value):
        return str(value)
    return json.dumps(plain(value), ensure_ascii=False, default=str)


def show(value: Value) -> str:
    """Text of a value as a literal (strings quoted), used when listing differences."""
    if isinstance(value, str):
        return repr(value)
    if is_map(value):
        return "{" + ", ".join(f"{k}={show(v)}" for k, v in value.items()) + "}"
    if is_list(value):
        return "[" + ", ".join(show(v) for v in value) + "]"
    return render(value)


class LazyContext(Mapping[str, Value]):
    """Context roots computed on first use and then kept.

    Integrations build one per step; a rule that never mentions ``state`` never
    pays for it. ``extend`` layers further roots (the response, once known) over
    the same cache.
    """

    def __init__(
        self,
        factories: Mapping[str, Callable[[], Value]],
        parent: LazyContext | None = None,
    ) -> None:
        self._factories = dict(factories)
        self._parent = parent
        self._cache: dict[str, Value] = {}

    def extend(self, factories: Mapping[str, Callable[[], Value]]) -> LazyContext:
        """A context with extra lazily computed values."""
        return LazyContext(factories, parent=self)

    def __getitem__(self, name: str) -> Value:
        if name in self._cache:
            return self._cache[name]
        if name in self._factories:
            value = self._cache[name] = self._factories[name]()
            return value  # may be Undefined: "this root does not exist for this step"
        if self._parent is not None:
            return self._parent[name]
        raise KeyError(name)

    def __iter__(self) -> Iterator[str]:
        seen = set(self._factories)
        yield from self._factories
        if self._parent is not None:
            yield from (k for k in self._parent if k not in seen)

    def __len__(self) -> int:
        return len(set(self))


def as_sequence(value: Value) -> Sequence[Value] | None:
    """Elements to iterate: a list's items, or a map's ``{key, value}`` entries."""
    if is_list(value):
        return value  # type: ignore[no-any-return]
    if is_map(value):
        return [{"key": k, "value": v} for k, v in value.items()]
    return None
