"""What the HTTP adapter records about a response, beyond status and body."""

import httpx
from vulnerable_saas.target import adapter_for

from invariant.adapters.base import Action, Call
from invariant.adapters.http import HttpAdapter
from invariant.integrations.document_saas import DOCUMENT_SAAS, _cookie, _response


def adapter_returning(headers):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True}, headers=headers)

    return HttpAdapter(httpx.Client(transport=httpx.MockTransport(handler), base_url="http://t"))


def test_headers_are_recorded_lower_cased_with_repeats_joined():
    adapter = adapter_returning(
        [("X-Thing", "a"), ("x-thing", "b"), ("Content-Security-Policy", "default-src 'none'")]
    )
    seen = adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential="t"))
    assert seen.headers["x-thing"] == "a, b"
    assert seen.headers["content-security-policy"] == "default-src 'none'"
    assert seen.headers["content-type"] == "application/json"
    assert all(name == name.lower() for name in seen.headers)


def test_every_set_cookie_is_kept_apart_and_verbatim():
    adapter = adapter_returning(
        [("Set-Cookie", "a=1; HttpOnly; Secure"), ("set-cookie", "b=2; Path=/; SameSite=Lax")]
    )
    seen = adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential="t"))
    assert seen.set_cookies == ("a=1; HttpOnly; Secure", "b=2; Path=/; SameSite=Lax")
    assert "set-cookie" not in seen.headers


def test_the_request_is_recorded():
    adapter = adapter_returning([])
    seen = adapter.execute(Call(action=Action.READ_DOCUMENT, credential="t", resource_id="doc_1"))
    assert (seen.method, seen.path) == ("GET", "/documents/doc_1")


def test_an_unreachable_target_has_no_headers():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    adapter = HttpAdapter(httpx.Client(transport=httpx.MockTransport(boom), base_url="http://t"))
    seen = adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential="t"))
    assert seen.error and seen.headers == {} and seen.set_cookies == () and seen.method is None


def test_the_demo_app_s_headers_reach_the_observation():
    adapter = adapter_for(frozenset())
    try:
        adapter.reset()
        seen = adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential="nope"))
    finally:
        adapter.close()
    assert seen.status == 401 and seen.headers["x-content-type-options"] == "nosniff"


def test_cookies_are_parsed_case_insensitively_into_attributes():
    cookie = _cookie("SID=abc; Path=/app; Domain=example.com; HttpOnly; secure; SameSite=Strict; Max-Age=60")
    assert cookie == {
        "name": "SID", "secure": True, "http_only": True, "same_site": "strict", "path": "/app",
        "domain": "example.com", "persistent": True,
        "raw": "SID=abc; Path=/app; Domain=example.com; HttpOnly; secure; SameSite=Strict; Max-Age=60",
    }  # fmt: skip
    bare = _cookie("x=1")
    assert (bare["secure"], bare["http_only"], bare["same_site"], bare["persistent"]) == (False, False, "", False)
    assert _cookie("a; HttpOnly")["name"] == "a"


def test_the_rule_context_exposes_headers_cookies_and_the_request():
    adapter = adapter_returning([("Set-Cookie", "a=1; HttpOnly")])
    seen = adapter.execute(Call(action=Action.LIST_DOCUMENTS, credential="t"))
    context = _response(seen)
    assert context["headers"]["content-type"] == "application/json"
    assert context["cookies"][0]["http_only"] is True
    assert context["request"] == {"method": "GET", "path": "/documents"}
    assert "request" not in _response(type(seen)(status=200, body="{}"))
    assert DOCUMENT_SAAS.schema is not None
