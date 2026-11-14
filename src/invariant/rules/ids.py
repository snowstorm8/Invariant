"""Deterministic rule ids of the form ``AA-11`` (two letters, a dash, two digits).

A rule that is written without an ``id`` gets one derived from its *name* alone,
by the algorithm the developer chose. Nothing is random and nothing depends on
the clock or on other rules, so the same name always yields the same id; the
only outside input is the set of ids already taken, used to resolve a collision
(see :func:`assign`).

Five algorithms are offered. They differ in what the id tells you:

* ``initials``  - the first letters of the name's first two words, then a length
  check. ``tenant-read-isolation`` reads as ``TR-19``: easiest to recognise.
* ``consonants`` - the name's first two consonants, then a letter-value sum.
  ``tenant-read-isolation`` reads as ``TN-..``: keeps the sound of the name.
* ``edges`` - the first letter of the first word and the first letter of the
  last word, then a position-weighted checksum. Good for long, similar names.
* ``crc32`` - a CRC-32 of the normalised name, spread over the id space.
  Uniform, so collisions are rare, but the letters say nothing about the rule.
* ``sha256`` - the same idea with SHA-256.

This module is application-agnostic and has no dependency on the rest of the
package.
"""

from __future__ import annotations

import hashlib
import re
import zlib
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass

ID_PATTERN = re.compile(r"[A-Z]{2}-[0-9]{2}")
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
VOWELS = frozenset("AEIOU")
#: Every possible id, as an index: letter1 * 26 * 100 + letter2 * 100 + number.
SPACE = 26 * 26 * 100
DEFAULT_ALGORITHM = "initials"


def _words(name: str) -> list[str]:
    """Upper-case alphanumeric words; camelCase boundaries also split words."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w.upper() for w in re.findall(r"[A-Za-z0-9]+", spaced)]


def _letters_of(name: str) -> str:
    return "".join(c for c in name.upper() if c in LETTERS)


def _compose(first: str, second: str, number: int) -> int:
    return (LETTERS.index(first) * 26 + LETTERS.index(second)) * 100 + number % 100


def _pad(letters: str, fallback: str = "XX") -> str:
    """Exactly two letters: pad a short name from ``fallback`` ('X' by default)."""
    return (letters + fallback)[:2]


def _initials(name: str) -> int:
    words = [_letters_of(w) for w in _words(name)]
    words = [w for w in words if w]
    if len(words) >= 2:
        letters = words[0][0] + words[1][0]
    elif words:
        letters = _pad(words[0])
    else:
        letters = "XX"
    return _compose(letters[0], letters[1], len(_letters_of(name)))


def _consonants(name: str) -> int:
    letters = _letters_of(name)
    consonants = [c for c in letters if c not in VOWELS]
    pick = _pad("".join(consonants[:2]) or letters)
    return _compose(pick[0], pick[1], sum(LETTERS.index(c) + 1 for c in letters))


def _edges(name: str) -> int:
    words = [_letters_of(w) for w in _words(name)]
    words = [w for w in words if w]
    if len(words) >= 2:
        letters = words[0][0] + words[-1][0]
    elif words:
        letters = words[0][0] + words[0][-1]
    else:
        letters = "XX"
    checksum = sum((i + 1) * ord(c) for i, c in enumerate(_letters_of(name)))
    return _compose(letters[0], letters[1], checksum)


def _normalised(name: str) -> bytes:
    return " ".join(_words(name)).encode("utf-8")


def _crc32(name: str) -> int:
    return zlib.crc32(_normalised(name)) % SPACE


def _sha256(name: str) -> int:
    digest = hashlib.sha256(_normalised(name)).digest()
    return int.from_bytes(digest[:4], "big") % SPACE


@dataclass(frozen=True)
class IdAlgorithm:
    """A named way to derive a rule id from its name."""
    key: str
    label: str
    description: str
    index: Callable[[str], int]


ALGORITHMS: Mapping[str, IdAlgorithm] = {
    a.key: a
    for a in (
        IdAlgorithm(
            "initials",
            "Initials",
            "First letters of the first two words, then the name's letter count. "
            "Easiest to recognise: tenant-read-isolation becomes TR-19.",
            _initials,
        ),
        IdAlgorithm(
            "consonants",
            "Consonants",
            "The name's first two consonants, then the sum of its letter values. "
            "Keeps the sound of the name.",
            _consonants,
        ),
        IdAlgorithm(
            "edges",
            "First and last word",
            "First letter of the first and of the last word, then a position-weighted "
            "checksum. Tells long, similar names apart.",
            _edges,
        ),
        IdAlgorithm(
            "crc32",
            "CRC-32 hash",
            "Both letters and digits come from a CRC-32 of the name. Evenly spread, so "
            "collisions are rare, but the letters say nothing about the rule.",
            _crc32,
        ),
        IdAlgorithm(
            "sha256",
            "SHA-256 hash",
            "As CRC-32, from a SHA-256 of the name.",
            _sha256,
        ),
    )
}


def render(index: int) -> str:
    """The id for a position in the id space."""
    index %= SPACE
    pair, number = divmod(index, 100)
    first, second = divmod(pair, 26)
    return f"{LETTERS[first]}{LETTERS[second]}-{number:02d}"


def _algorithm(algorithm: str) -> IdAlgorithm:
    try:
        return ALGORITHMS[algorithm]
    except KeyError:
        known = ", ".join(ALGORITHMS)
        raise ValueError(f"unknown id algorithm '{algorithm}' (choose one of: {known})") from None


def candidate(algorithm: str, name: str) -> str:
    """The id ``name`` maps to, ignoring every other rule. Pure."""
    return render(_algorithm(algorithm).index(name))


def assign(algorithm: str, name: str, taken: Collection[str]) -> str:
    """The id for ``name``: its candidate, or - if that is taken - the next free
    id after it (counting up through the digits, then the letters). Deterministic
    for a given ``taken``; raises only if every one of the 67,600 ids is used."""
    start = _algorithm(algorithm).index(name)
    for step in range(SPACE):
        found = render(start + step)
        if found not in taken:
            return found
    raise ValueError("every AA-11 id is already in use")


def assign_all(
    algorithm: str,
    rules: Iterable[tuple[str, str, str]],
    reserved: Collection[str] = (),
) -> dict[str, str]:
    """New ids for a whole set of rules, given as ``(key, name, current_id)``.

    A rule whose current id already is its candidate keeps it, so applying the
    same algorithm twice changes nothing. The rest are assigned in order of name,
    then key, so the result does not depend on the order the rules were given in.
    ``reserved`` ids are never handed out.
    """
    items = sorted(rules, key=lambda r: (r[1].casefold(), r[0]))
    taken: set[str] = set(reserved)
    result: dict[str, str] = {}
    for key, name, current in items:
        wanted = candidate(algorithm, name)
        if current == wanted and wanted not in taken:
            result[key] = wanted
            taken.add(wanted)
    for key, name, _ in items:
        if key not in result:
            result[key] = assign(algorithm, name, taken)
            taken.add(result[key])
    return result


def describe() -> list[dict[str, str]]:
    """The algorithms, for a settings screen, each with an example."""
    example = "tenant-read-isolation"
    return [
        {
            "id": a.key,
            "label": a.label,
            "description": a.description,
            "example": f"{example} -> {render(a.index(example))}",
        }
        for a in ALGORITHMS.values()
    ]


__all__ = [
    "ALGORITHMS",
    "DEFAULT_ALGORITHM",
    "ID_PATTERN",
    "assign",
    "assign_all",
    "candidate",
    "describe",
    "render",
]
