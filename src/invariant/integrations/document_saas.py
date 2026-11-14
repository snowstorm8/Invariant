"""Rule context for the document SaaS model (orgs, users with roles, documents).

This is the integration layer's side of the rule engine: it declares what rules
may refer to when the target is a document SaaS, and builds those values from
Invariant's expected-state model, the reference policy's decision, the response
and the history of the run. The rule language has no knowledge of any of it; a
different application would provide its own ``RuleBinding`` with its own schema.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from invariant.adapters.base import Observation
from invariant.core.scenario import WRITE_OPS, CreateDocument, Role, UpdateDocument
from invariant.core.state import DocModel, ModelState, UserModel
from invariant.evaluation.snapshots import Snapshot
from invariant.properties.authorization import DELETE_ROLES, WRITE_ROLES
from invariant.properties.base import OrgSnapshot, ProbeRequest, Step
from invariant.rules.binding import RuleBinding
from invariant.rules.types import (
    ANY,
    BOOL,
    INT,
    STRING,
    ContextSchema,
    Field,
    ListType,
    MapType,
    ProbeSpec,
    enum,
    record,
)
from invariant.rules.values import LazyContext, Undefined, Value

OPERATION_TYPES = (
    "create_document",
    "read_document",
    "update_document",
    "delete_document",
    "list_documents",
)
PERMISSIONS = ("read", "list", "create", "update", "delete")
_ROLE = enum(*(r.value for r in Role))

# -- schema -----------------------------------------------------------------

_LISTING = MapType(record(content=STRING, version=INT))

_OPERATION = record(
    type=Field(enum(*OPERATION_TYPES), "Kind of operation being performed."),
    is_write=Field(BOOL, "True for create, update and delete."),
    target=Field(STRING, "Symbolic ref of the document acted on (e.g. doc0).", optional=True),
    input=Field(
        record(
            content=Field(STRING, "Content sent with a create or update.", optional=True),
        ),
        "What the actor sent.",
    ),
)
_ACTOR = record(
    ref=Field(STRING, "Symbolic ref of the acting user (e.g. user1)."),
    id=Field(STRING, "The application's id for the user."),
    org=Field(STRING, "Symbolic ref of the user's organization (e.g. org0)."),
    org_id=Field(STRING, "The application's id for that organization.", optional=True),
    role=Field(_ROLE, "The user's role in its organization."),
    permissions=Field(
        ListType(enum(*PERMISSIONS)), "What the reference policy lets this role do in its own org."
    ),
)
_DOCUMENT = record(
    ref=Field(STRING, "Symbolic ref (e.g. doc0)."),
    id=Field(STRING, "The application's id for the document."),
    org=Field(STRING, "Symbolic ref of the owning organization."),
    org_id=Field(STRING, "The application's id for the owning organization.", optional=True),
    content=Field(STRING, "Content the model expects to be stored."),
    marker=Field(STRING, "Unique canary inside the content; seeing it means disclosure."),
    version=Field(INT, "Version the model expects."),
    deleted=Field(BOOL, "True once an authorised delete was verified."),
)
_POLICY = record(
    allowed=Field(BOOL, "Does the reference policy permit this operation?"),
    reason=Field(STRING, "Why it is permitted, or every denial reason."),
    denials=Field(
        MapType(record(reason=STRING)),
        "Policy rules the operation breaks, keyed by policy rule id (TI-1, TI-2, AZ-1).",
    ),
)
_RESPONSE = record(
    status=Field(INT, "HTTP status code."),
    body=Field(STRING, "Raw response body."),
    excerpt=Field(STRING, "The body, truncated for reports."),
    json=Field(ANY, "The body decoded as JSON; undefined if it is not JSON.", optional=True),
)
_EVENT = record(
    index=Field(INT, "Position among the actor operations of this run, from 0."),
    operation=Field(_OPERATION, "The operation performed."),
    actor=Field(_ACTOR, "Who performed it."),
    resource=Field(_DOCUMENT, "The document it targeted, as it was before.", optional=True),
    policy=Field(_POLICY, "The reference policy's ruling."),
    response=Field(
        record(
            status=Field(INT, "HTTP status code.", optional=True),
            body=STRING,
            excerpt=STRING,
            json=Field(ANY, optional=True),
        ),
        "What the application answered.",
    ),
)

SCHEMA = ContextSchema(
    name="document-saas",
    description=(
        "Multi-tenant document service: organizations, users with a role, and documents "
        "owned by an organization."
    ),
    roots={
        "operation": Field(_OPERATION, "The operation being judged."),
        "actor": Field(_ACTOR, "The user performing it."),
        "resource": Field(
            _DOCUMENT,
            "The document the operation targets, as the model expects it before the "
            "operation. Absent for create and list.",
            optional=True,
        ),
        "policy": Field(_POLICY, "The reference policy's ruling on the operation."),
        "state": Field(
            record(
                orgs=Field(ListType(record(ref=STRING, id=STRING)), "Organizations."),
                users=Field(
                    ListType(record(ref=STRING, id=STRING, org=STRING, role=_ROLE)),
                    "Users.",
                ),
                documents=Field(ListType(_DOCUMENT), "Documents, including deleted ones."),
                expected_listing=Field(
                    MapType(_LISTING),
                    "Per organization ref: the documents a legitimate listing must return, "
                    "by application id.",
                ),
            ),
            "Expected application state before the operation (updated only by authorised, "
            "verified writes).",
        ),
        "events": Field(
            ListType(_EVENT),
            "Earlier actor operations of this run, oldest first, with their responses.",
        ),
        "response": Field(_RESPONSE, "What the application answered.", late=True),
    },
    probes={
        "org_documents": ProbeSpec(
            params=(("org", STRING),),
            returns=_LISTING,
            doc=(
                "Documents of an organization (by symbolic ref), listed as one of its own "
                "members after the operation: application id -> {content, version}."
            ),
        ),
    },
)


# -- values -----------------------------------------------------------------


def _permissions(role: Role) -> list[str]:
    granted = ["read", "list"]
    if role in WRITE_ROLES:
        granted += ["create", "update"]
    if role in DELETE_ROLES:
        granted.append("delete")
    return granted


def _org_id(state: ModelState, org_ref: str) -> dict[str, str]:
    org = state.orgs.get(org_ref)
    return {"org_id": org.external_id} if org is not None else {}


def _actor(state: ModelState, user: UserModel) -> dict[str, Value]:
    return {
        "ref": user.ref,
        "id": user.external_id,
        "org": user.org,
        **_org_id(state, user.org),
        "role": user.role.value,
        "permissions": _permissions(user.role),
    }


def _document(state: ModelState, doc: DocModel) -> dict[str, Value]:
    return {
        "ref": doc.ref,
        "id": doc.external_id,
        "org": doc.org,
        **_org_id(state, doc.org),
        "content": doc.content,
        "marker": doc.marker,
        "version": doc.version,
        "deleted": doc.deleted,
    }


def _operation(step: Step) -> dict[str, Value]:
    op = step.op
    out: dict[str, Value] = {"type": op.kind, "is_write": isinstance(op, WRITE_OPS), "input": {}}
    if isinstance(op, (CreateDocument, UpdateDocument)):
        out["input"] = {"content": op.content}
    target = getattr(op, "doc", None)
    if isinstance(target, str):
        out["target"] = target
    return out


def _resource(step: Step) -> Value:
    target = getattr(step.op, "doc", None)
    doc = step.state.docs.get(target) if isinstance(target, str) else None
    if doc is None:
        kind = getattr(step.op, "kind", type(step.op).__name__)
        return Undefined(f"'resource' is not available: {kind} does not target an existing document")
    return _document(step.state, doc)


def _policy(step: Step) -> dict[str, Value]:
    decision = step.decision
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "denials": {d.property_id: {"reason": d.reason} for d in decision.denials},
    }


def _state(state: ModelState) -> dict[str, Value]:
    return {
        "orgs": [{"ref": o.ref, "id": o.external_id} for o in state.orgs.values()],
        "users": [
            {"ref": u.ref, "id": u.external_id, "org": u.org, "role": u.role.value}
            for u in state.users.values()
        ],
        "documents": [_document(state, d) for d in state.docs.values()],
        "expected_listing": {
            ref: _listing(state.expected_snapshot(ref)) for ref in state.orgs
        },
    }


def _listing(snapshot: Snapshot) -> dict[str, Value]:
    return {
        doc_id: {"content": content, "version": version}
        for doc_id, (content, version) in snapshot.items()
    }


def _response(response: Observation) -> dict[str, Value]:
    out: dict[str, Value] = {"body": response.body, "excerpt": response.excerpt()}
    if response.status is not None:
        out["status"] = response.status
    decoded = response.json_body()
    if decoded is not None or response.body.strip() == "null":
        out["json"] = decoded
    return out


class DocumentSaasBinding(RuleBinding):
    """Builds rule contexts from ``Step`` objects of the document SaaS engine."""

    def __init__(self) -> None:
        # One-entry memo: every rule judging the same step shares one context.
        # Held as a single tuple so a reader always sees a consistent pair.
        self._planned: tuple[Step, LazyContext] | None = None
        self._judged: tuple[Step, Observation, LazyContext] | None = None

    @property
    def schema(self) -> ContextSchema:
        return SCHEMA

    def context(self, step: Step, response: Observation | None) -> Mapping[str, Value]:
        planned = self._planned
        if planned is None or planned[0] is not step:
            base = LazyContext(
                {
                    "operation": lambda: _operation(step),
                    "actor": lambda: _actor(step.state, step.actor),
                    "resource": lambda: _resource(step),
                    "policy": lambda: _policy(step),
                    "state": lambda: _state(step.state),
                    "events": lambda: step.history,
                }
            )
            self._planned = planned = (step, base)
        if response is None:
            return planned[1]
        judged = self._judged
        if judged is None or judged[0] is not step or judged[1] is not response:
            full = planned[1].extend({"response": lambda: _response(response)})
            self._judged = judged = (step, response, full)
        return judged[2]

    def event(self, step: Step, response: Observation) -> Mapping[str, Value]:
        """Snapshot of a finished step. Built eagerly: the model changes later."""
        out: dict[str, Value] = {
            "index": len(step.history),
            "operation": _operation(step),
            "actor": _actor(step.state, step.actor),
            "policy": _policy(step),
            "response": _response(response),
        }
        resource = _resource(step)
        if not isinstance(resource, Undefined):
            out["resource"] = resource
        return out

    def probe_request(self, probe: str, args: Sequence[Value]) -> ProbeRequest:
        if probe != "org_documents":
            raise KeyError(f"unknown probe {probe!r}")
        (org,) = args
        return OrgSnapshot(str(org))

    def probe_value(self, probe: str, raw: Any) -> Value:
        return _listing(raw)


#: Shared instance. Bindings hold no run state, only a per-step memo.
DOCUMENT_SAAS = DocumentSaasBinding()

__all__ = ["DOCUMENT_SAAS", "SCHEMA", "DocumentSaasBinding"]
