"""Invariant's expected-state model of the target.

This is the *oracle* the evaluator compares the application against. It is only
ever updated from operations the policy authorised, so it records what the
application *should* contain, not what it claims to contain.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .scenario import Role


class UnknownRefError(KeyError):
    """A scenario referenced an entity that was never created."""


@dataclass
class OrgModel:
    ref: str
    external_id: str


@dataclass
class UserModel:
    ref: str
    org: str  # org ref
    role: Role
    external_id: str
    token: str = field(repr=False)


@dataclass
class DocModel:
    ref: str
    org: str  # owning org ref
    external_id: str
    content: str  # exactly what is stored, including the unique marker
    marker: str  # canary embedded in ``content``; its appearance == disclosure
    version: int = 1
    deleted: bool = False


@dataclass
class ModelState:
    orgs: dict[str, OrgModel] = field(default_factory=dict)
    users: dict[str, UserModel] = field(default_factory=dict)
    docs: dict[str, DocModel] = field(default_factory=dict)

    def user(self, ref: str) -> UserModel:
        try:
            return self.users[ref]
        except KeyError:
            raise UnknownRefError(f"unknown user ref {ref!r}") from None

    def doc(self, ref: str) -> DocModel:
        try:
            return self.docs[ref]
        except KeyError:
            raise UnknownRefError(f"unknown doc ref {ref!r}") from None

    def org(self, ref: str) -> OrgModel:
        try:
            return self.orgs[ref]
        except KeyError:
            raise UnknownRefError(f"unknown org ref {ref!r}") from None

    def member_of(self, org_ref: str) -> UserModel | None:
        """Some legitimate user of the org (used to probe the org's real state)."""
        return next((u for u in self.users.values() if u.org == org_ref), None)

    def foreign_docs(self, org_ref: str) -> list[DocModel]:
        """Documents (including deleted ones) that do not belong to ``org_ref``."""
        return [d for d in self.docs.values() if d.org != org_ref]

    def expected_snapshot(self, org_ref: str) -> dict[str, tuple[str, int]]:
        """What a legitimate listing of the org must return: id -> (content, version)."""
        return {
            d.external_id: (d.content, d.version)
            for d in self.docs.values()
            if d.org == org_ref and not d.deleted
        }
