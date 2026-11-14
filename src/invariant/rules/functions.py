"""Built-in functions of the rule language.

The table is closed: rules can call only what is listed here, and every
function is a total, side-effect-free Python function over rule values. There
is no way for a rule to reach arbitrary Python.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .types import (
    ANY,
    BOOL,
    INT,
    NUMBER,
    STRING,
    AnyType,
    ListType,
    MapType,
    NumberType,
    RecordType,
    StringType,
    Type,
)
from .values import Undefined, Value, equal, is_list, is_map, is_number, kind_of, render, show

Check = Callable[[list[Type]], "Type | str"]
Impl = Callable[[list[Value]], Value]


@dataclass(frozen=True)
class Function:
    name: str
    signature: str
    doc: str
    min_args: int
    max_args: int | None
    check: Check
    impl: Impl
    #: Strict functions are undefined as soon as any argument is.
    strict: bool = True


def _is(t: Type, *kinds: type) -> bool:
    return isinstance(t, AnyType) or isinstance(t, kinds)


def _bad(name: str, position: str, expected: str, got: Type) -> str:
    return f"{name}() expects {expected} as its {position} argument, found {got.describe()}"


def _undef(name: str, value: Value, expected: str) -> Undefined:
    return Undefined(f"{name}() expects {expected}, got {kind_of(value)}")


# -- implementations --------------------------------------------------------


def _count(a: list[Value]) -> Value:
    v = a[0]
    return len(v) if isinstance(v, str) or is_list(v) or is_map(v) else _undef("count", v, "a list, map or string")


def _contains(a: list[Value]) -> Value:
    hay, needle = a
    if isinstance(hay, str):
        return needle in hay if isinstance(needle, str) else _undef("contains", needle, "a string to search for")
    if is_list(hay):
        return any(equal(x, needle) for x in hay)
    if is_map(hay):
        return isinstance(needle, str) and needle in hay
    return _undef("contains", hay, "a string, list or map")


def _text2(name: str, fn: Callable[[str, str], Value]) -> Impl:
    def impl(a: list[Value]) -> Value:
        if not isinstance(a[0], str):
            return _undef(name, a[0], "a string")
        if not isinstance(a[1], str):
            return _undef(name, a[1], "a string")
        return fn(a[0], a[1])

    return impl


def _text1(name: str, fn: Callable[[str], Value]) -> Impl:
    def impl(a: list[Value]) -> Value:
        return fn(a[0]) if isinstance(a[0], str) else _undef(name, a[0], "a string")

    return impl


def _join(a: list[Value]) -> Value:
    items, sep = a
    if not is_list(items):
        return _undef("join", items, "a list")
    if not isinstance(sep, str):
        return _undef("join", sep, "a string separator")
    return sep.join(render(i) for i in items)


def _first(a: list[Value]) -> Value:
    if not is_list(a[0]):
        return _undef("first", a[0], "a list")
    return a[0][0] if a[0] else Undefined("first() of an empty list")


def _last(a: list[Value]) -> Value:
    if not is_list(a[0]):
        return _undef("last", a[0], "a list")
    return a[0][-1] if a[0] else Undefined("last() of an empty list")


def _keys(a: list[Value]) -> Value:
    return list(a[0].keys()) if is_map(a[0]) else _undef("keys", a[0], "a map")


def _values(a: list[Value]) -> Value:
    return list(a[0].values()) if is_map(a[0]) else _undef("values", a[0], "a map")


def _numbers(name: str, fn: Callable[[list[Value]], Value], empty: Value | None) -> Impl:
    def impl(a: list[Value]) -> Value:
        if not is_list(a[0]):
            return _undef(name, a[0], "a list of numbers")
        if not all(is_number(x) for x in a[0]):
            return Undefined(f"{name}() expects a list of numbers")
        if not a[0]:
            return Undefined(f"{name}() of an empty list") if empty is None else empty
        return fn(list(a[0]))

    return impl


def _distinct(a: list[Value]) -> Value:
    if not is_list(a[0]):
        return _undef("distinct", a[0], "a list")
    out: list[Value] = []
    for item in a[0]:
        if not any(equal(item, seen) for seen in out):
            out.append(item)
    return out


def _fields(value: Value) -> str:
    if is_map(value):
        return ", ".join(f"{k}={show(v)}" for k, v in value.items())
    return show(value)


def _diff(a: list[Value]) -> Value:
    """Differences between two maps, as readable lines in a fixed order:
    missing keys, then unexpected keys, then changed entries; each sorted by key."""
    expected, observed = a
    if not is_map(expected):
        return _undef("diff", expected, "a map of expected entries")
    if not is_map(observed):
        return _undef("diff", observed, "a map of observed entries")
    out: list[str] = []
    for key in sorted(expected.keys() - observed.keys()):
        out.append(f"{key} expected but missing")
    for key in sorted(observed.keys() - expected.keys()):
        out.append(f"{key} present but not expected")
    for key in sorted(expected.keys() & observed.keys()):
        if not equal(expected[key], observed[key]):
            out.append(
                f"{key} expected ({_fields(expected[key])}) observed ({_fields(observed[key])})"
            )
    return out


def _has(a: list[Value]) -> Value:
    return not isinstance(a[0], Undefined)


def _coalesce(a: list[Value]) -> Value:
    for value in a:
        if not isinstance(value, Undefined):
            return value
    return a[-1]


# -- static signatures ------------------------------------------------------


def _sig_count(t: list[Type]) -> Type | str:
    if not _is(t[0], ListType, MapType, RecordType, StringType):
        return _bad("count", "first", "a list, map or string", t[0])
    return INT


def _sig_contains(t: list[Type]) -> Type | str:
    if not _is(t[0], ListType, MapType, RecordType, StringType):
        return _bad("contains", "first", "a string, list or map", t[0])
    if isinstance(t[0], StringType) and not _is(t[1], StringType):
        return _bad("contains", "second", "a string", t[1])
    return BOOL


def _sig_strings(name: str, count: int, result: Type) -> Check:
    def check(t: list[Type]) -> Type | str:
        for i in range(count):
            if not _is(t[i], StringType):
                return _bad(name, ("first", "second")[i], "a string", t[i])
        return result

    return check


def _sig_list(name: str, result: Callable[[Type], Type]) -> Check:
    def check(t: list[Type]) -> Type | str:
        if not _is(t[0], ListType):
            return _bad(name, "first", "a list", t[0])
        return result(t[0].item if isinstance(t[0], ListType) else ANY)

    return check


def _sig_map(name: str, result: Callable[[Type], Type]) -> Check:
    def check(t: list[Type]) -> Type | str:
        if not _is(t[0], MapType, RecordType):
            return _bad(name, "first", "a map", t[0])
        return result(t[0].value if isinstance(t[0], MapType) else ANY)

    return check


def _sig_join(t: list[Type]) -> Type | str:
    if not _is(t[0], ListType):
        return _bad("join", "first", "a list", t[0])
    if not _is(t[1], StringType):
        return _bad("join", "second", "a string separator", t[1])
    return STRING


def _sig_numbers(name: str) -> Check:
    def check(t: list[Type]) -> Type | str:
        if not _is(t[0], ListType):
            return _bad(name, "first", "a list of numbers", t[0])
        if isinstance(t[0], ListType) and not _is(t[0].item, NumberType):
            return _bad(name, "first", "a list of numbers", t[0])
        return t[0].item if isinstance(t[0], ListType) and isinstance(t[0].item, NumberType) else NUMBER

    return check


def _sig_diff(t: list[Type]) -> Type | str:
    for i in (0, 1):
        if not _is(t[i], MapType, RecordType):
            return _bad("diff", ("first", "second")[i], "a map", t[i])
    return ListType(STRING)


def _sig_coalesce(t: list[Type]) -> Type | str:
    first = t[0]
    return first if all(type(x) is type(first) for x in t) else ANY


FUNCTIONS: dict[str, Function] = {
    f.name: f
    for f in (
        Function("has", "has(x) -> bool",
                 "True if x is defined (the field exists). Never undefined itself.",
                 1, 1, lambda t: BOOL, _has, strict=False),
        Function("coalesce", "coalesce(a, b, ...) -> value",
                 "The first argument that is defined.",
                 2, None, _sig_coalesce, _coalesce, strict=False),
        Function("count", "count(x) -> int",
                 "Number of items in a list, entries in a map, or characters in a string.",
                 1, 1, _sig_count, _count),
        Function("contains", "contains(haystack, needle) -> bool",
                 "Substring test on a string, membership on a list, key test on a map.",
                 2, 2, _sig_contains, _contains),
        Function("startswith", "startswith(text, prefix) -> bool", "Prefix test.",
                 2, 2, _sig_strings("startswith", 2, BOOL),
                 _text2("startswith", lambda s, p: s.startswith(p))),
        Function("endswith", "endswith(text, suffix) -> bool", "Suffix test.",
                 2, 2, _sig_strings("endswith", 2, BOOL),
                 _text2("endswith", lambda s, p: s.endswith(p))),
        Function("lower", "lower(text) -> string", "Lower-cased text.",
                 1, 1, _sig_strings("lower", 1, STRING), _text1("lower", str.lower)),
        Function("upper", "upper(text) -> string", "Upper-cased text.",
                 1, 1, _sig_strings("upper", 1, STRING), _text1("upper", str.upper)),
        Function("str", "str(x) -> string", "Text of any value, as it appears in messages.",
                 1, 1, lambda t: STRING, lambda a: render(a[0])),
        Function("join", "join(list, separator) -> string",
                 "Items of a list as text, separated by separator.",
                 2, 2, _sig_join, _join),
        Function("first", "first(list) -> item", "First item; undefined for an empty list.",
                 1, 1, _sig_list("first", lambda item: item), _first),
        Function("last", "last(list) -> item", "Last item; undefined for an empty list.",
                 1, 1, _sig_list("last", lambda item: item), _last),
        Function("distinct", "distinct(list) -> list", "The list without repeated items.",
                 1, 1, _sig_list("distinct", ListType), _distinct),
        Function("keys", "keys(map) -> list<string>", "Keys of a map.",
                 1, 1, _sig_map("keys", lambda v: ListType(STRING)), _keys),
        Function("values", "values(map) -> list", "Values of a map.",
                 1, 1, _sig_map("values", ListType), _values),
        Function("sum", "sum(list<number>) -> number", "Sum of the numbers (0 if empty).",
                 1, 1, _sig_numbers("sum"), _numbers("sum", sum, 0)),
        Function("min", "min(list<number>) -> number", "Smallest; undefined if empty.",
                 1, 1, _sig_numbers("min"), _numbers("min", min, None)),
        Function("max", "max(list<number>) -> number", "Largest; undefined if empty.",
                 1, 1, _sig_numbers("max"), _numbers("max", max, None)),
        Function("diff", "diff(expected, observed) -> list<string>",
                 "Readable differences between two maps: missing, unexpected and changed "
                 "entries. Empty when they are equal.",
                 2, 2, _sig_diff, _diff),
    )
}  # fmt: skip


def describe_functions() -> list[dict[str, str]]:
    return [{"name": f.name, "signature": f.signature, "doc": f.doc} for f in FUNCTIONS.values()]
