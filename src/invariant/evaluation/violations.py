"""Evaluation outcomes and failure types."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Outcome(StrEnum):
    PASS = "PASS"
    VIOLATION = "VIOLATION"
    INCONCLUSIVE = "INCONCLUSIVE"


_SEVERITY = {Outcome.PASS: 0, Outcome.INCONCLUSIVE: 1, Outcome.VIOLATION: 2}


def worst(outcomes: list[Outcome]) -> Outcome:
    return max(outcomes, key=_SEVERITY.__getitem__, default=Outcome.PASS)


class Evaluation(BaseModel):
    property_id: str
    outcome: Outcome
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
