"""HTTP adapter for REST targets following the demo SaaS contract.

Routes (``Authorization: Bearer <token>`` where a credential is given):

    POST   /_admin/reset                 -> {"orgs": 0, "users": 0, "documents": 0}
    POST   /_admin/orgs                  {"name"}
    POST   /_admin/orgs/{org}/users      {"name", "role"}
    POST   /documents                    {"content"}
    GET    /documents
    GET    /documents/{id}
    PUT    /documents/{id}               {"content"}
    DELETE /documents/{id}
"""

from __future__ import annotations

import httpx

from .base import Action, Adapter, AdapterError, Call, Observation


class HttpAdapter(Adapter):
    def __init__(self, client: httpx.Client) -> None:
        self._client = client

    def reset(self) -> None:
        try:
            response = self._client.post("/_admin/reset")
        except httpx.HTTPError as exc:
            raise AdapterError(f"reset failed: {exc!r}") from exc
        try:
            counts = response.json()
        except ValueError:
            counts = None
        if (
            response.status_code != 200
            or not isinstance(counts, dict)
            or set(counts) != {"orgs", "users", "documents"}
            or any(v != 0 for v in counts.values())
        ):
            raise AdapterError(
                f"reset not verified: status={response.status_code} body={response.text[:200]!r}"
            )

    def execute(self, call: Call) -> Observation:
        method, path, json_body = self._route(call)
        headers = {"Authorization": f"Bearer {call.credential}"} if call.credential else {}
        try:
            response = self._client.request(method, path, json=json_body, headers=headers)
        except httpx.HTTPError as exc:
            return Observation(error=f"{type(exc).__name__}: {exc}")
        return Observation(status=response.status_code, body=response.text)

    def close(self) -> None:
        self._client.close()

    @staticmethod
    def _route(call: Call) -> tuple[str, str, dict[str, object] | None]:
        match call.action:
            case Action.CREATE_ORG:
                return "POST", "/_admin/orgs", dict(call.data)
            case Action.CREATE_USER:
                return "POST", f"/_admin/orgs/{call.org_id}/users", dict(call.data)
            case Action.CREATE_DOCUMENT:
                return "POST", "/documents", dict(call.data)
            case Action.LIST_DOCUMENTS:
                return "GET", "/documents", None
            case Action.READ_DOCUMENT:
                return "GET", f"/documents/{call.resource_id}", None
            case Action.UPDATE_DOCUMENT:
                return "PUT", f"/documents/{call.resource_id}", dict(call.data)
            case Action.DELETE_DOCUMENT:
                return "DELETE", f"/documents/{call.resource_id}", None
