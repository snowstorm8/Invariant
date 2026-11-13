import httpx
import pytest
from fastapi.testclient import TestClient
from vulnerable_saas.app.main import create_app

from invariant.adapters.base import Action, AdapterError, Call
from invariant.adapters.http import HttpAdapter


@pytest.fixture
def adapter():
    a = HttpAdapter(TestClient(create_app(), raise_server_exceptions=False))
    yield a
    a.close()


def provision(adapter):
    org = adapter.execute(Call(action=Action.CREATE_ORG, data={"name": "a"})).json_body()
    user = adapter.execute(
        Call(action=Action.CREATE_USER, org_id=org["id"], data={"name": "u", "role": "admin"})
    ).json_body()
    return org, user


def test_execute_maps_actions_to_routes_and_reports_raw_observation(adapter):
    org, user = provision(adapter)
    created = adapter.execute(
        Call(action=Action.CREATE_DOCUMENT, credential=user["token"], data={"content": "hi"})
    )
    assert created.status == 201 and created.json_body()["content"] == "hi"
    doc_id = created.json_body()["id"]
    read = adapter.execute(
        Call(action=Action.READ_DOCUMENT, credential=user["token"], resource_id=doc_id)
    )
    assert read.status == 200
    upd = adapter.execute(
        Call(action=Action.UPDATE_DOCUMENT, credential=user["token"], resource_id=doc_id,
             data={"content": "v2"})
    )
    assert upd.json_body()["version"] == 2
    listed = adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential=user["token"]))
    assert [d["id"] for d in listed.json_body()] == [doc_id]
    deleted = adapter.execute(
        Call(action=Action.DELETE_DOCUMENT, credential=user["token"], resource_id=doc_id)
    )
    assert deleted.json_body()["deleted"] is True


def test_application_errors_are_observations_not_exceptions(adapter):
    obs = adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential="bad"))
    assert obs.status == 401 and obs.error is None and obs.responded


def test_transport_failure_becomes_error_observation():
    def boom(request):
        raise httpx.ConnectError("refused")

    a = HttpAdapter(httpx.Client(transport=httpx.MockTransport(boom), base_url="http://x"))
    obs = a.execute(Call(action=Action.LIST_DOCUMENTS, credential="t"))
    assert obs.status is None and "ConnectError" in (obs.error or "") and not obs.responded


def test_reset_empties_target_and_is_repeatable(adapter):
    _, user = provision(adapter)
    adapter.execute(Call(action=Action.CREATE_DOCUMENT, credential=user["token"], data={"content": "x"}))
    adapter.reset()
    stats = adapter._client.get("/_admin/stats").json()
    assert stats == {"orgs": 0, "users": 0, "documents": 0}
    adapter.reset()  # idempotent


def test_reset_fails_loudly_when_target_does_not_clear():
    def handler(request):
        return httpx.Response(200, json={"orgs": 1, "users": 0, "documents": 0})

    a = HttpAdapter(httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x"))
    with pytest.raises(AdapterError, match="not verified"):
        a.reset()


@pytest.mark.parametrize("response", [httpx.Response(404), httpx.Response(200, text="nope"),
                                      httpx.Response(200, json={"orgs": 0})])
def test_reset_rejects_unexpected_responses(response):
    a = HttpAdapter(httpx.Client(transport=httpx.MockTransport(lambda r: response), base_url="http://x"))
    with pytest.raises(AdapterError):
        a.reset()


def test_reset_transport_error_raises_adapter_error():
    def boom(request):
        raise httpx.ConnectError("refused")

    a = HttpAdapter(httpx.Client(transport=httpx.MockTransport(boom), base_url="http://x"))
    with pytest.raises(AdapterError, match="reset failed"):
        a.reset()
