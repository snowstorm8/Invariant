"""Adapter contract: how Invariant talks to a target application.

Semantics
---------
* ``reset()`` returns the target to an empty, known state or raises
  ``AdapterError``. It must not return until the reset is verified.
* ``execute()`` performs exactly one logical call and never raises for
  application-level failures (4xx/5xx). Failure to obtain any response is
  reported as an ``Observation`` with ``error`` set, so the evaluator can
  classify it as INCONCLUSIVE rather than hiding it.
* An adapter instance is used by one test run at a time.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Action(StrEnum):
    CREATE_ORG = "create_org"
    CREATE_USER = "create_user"
    CREATE_DOCUMENT = "create_document"
    READ_DOCUMENT = "read_document"
    UPDATE_DOCUMENT = "update_document"
    DELETE_DOCUMENT = "delete_document"
    LIST_DOCUMENTS = "list_documents"


class Call(BaseModel):
    """A resolved logical call: real credentials and IDs, no symbolic refs."""

    model_config = ConfigDict(frozen=True)

    action: Action
    credential: str | None = Field(default=None, repr=False)
    org_id: str | None = None
    resource_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class Observation(BaseModel):
    """What the application actually returned (or why nothing was returned)."""

    model_config = ConfigDict(frozen=True)

    status: int | None = None
    body: str = ""
    error: str | None = None
    #: Response headers, names lower-cased. Repeated headers are joined with
    #: ", "; ``Set-Cookie`` is kept apart in ``set_cookies``.
    headers: dict[str, str] = Field(default_factory=dict)
    #: Every ``Set-Cookie`` header, verbatim.
    set_cookies: tuple[str, ...] = ()
    #: The request this answers, when the adapter knows it.
    method: str | None = None
    path: str | None = None

    @property
    def responded(self) -> bool:
        return self.status is not None

    def json_body(self) -> Any | None:
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    def excerpt(self, limit: int = 200) -> str:
        return self.body if len(self.body) <= limit else self.body[:limit] + "..."


class AdapterError(RuntimeError):
    """Infrastructure failure (e.g. reset could not be verified)."""


class Adapter(ABC):
    @abstractmethod
    def reset(self) -> None: ...

    @abstractmethod
    def execute(self, call: Call) -> Observation: ...

    def close(self) -> None:  # noqa: B027 - optional hook
        """Release resources. Default: nothing to release."""
