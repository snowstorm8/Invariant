"""Shared test helpers."""

from __future__ import annotations

import json
from collections.abc import Callable

from invariant.adapters.base import Adapter, Call, Observation
from invariant.core.scenario import Role
from invariant.core.state import DocModel, ModelState, OrgModel, UserModel


class ScriptedAdapter(Adapter):
    """Adapter whose responses come from a function; records everything."""

    def __init__(self, handler: Callable[[Call], Observation]) -> None:
        self.handler = handler
        self.calls: list[Call] = []
        self.resets = 0
        self.closed = False

    def reset(self) -> None:
        self.resets += 1

    def execute(self, call: Call) -> Observation:
        self.calls.append(call)
        return self.handler(call)

    def close(self) -> None:
        self.closed = True


def obs(status: int | None, body: object = "", error: str | None = None) -> Observation:
    text = body if isinstance(body, str) else json.dumps(body)
    return Observation(status=status, body=text, error=error)


def make_state() -> ModelState:
    """org0{user0 admin, user2 viewer, doc0}, org1{user1 member}."""
    s = ModelState()
    s.orgs = {"org0": OrgModel("org0", "org_1"), "org1": OrgModel("org1", "org_2")}
    s.users = {
        "user0": UserModel("user0", "org0", Role.ADMIN, "user_3", "tok0"),
        "user1": UserModel("user1", "org1", Role.MEMBER, "user_4", "tok1"),
        "user2": UserModel("user2", "org0", Role.VIEWER, "user_5", "tok2"),
    }
    s.docs = {
        "doc0": DocModel("doc0", "org0", "doc_6", "secret <<INV:3>>", "<<INV:3>>", version=1),
    }
    return s
