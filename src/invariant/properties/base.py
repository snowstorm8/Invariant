"""Security property definitions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Property:
    id: str
    name: str
    statement: str  # what the software must never allow
