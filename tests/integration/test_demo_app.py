"""The demo app itself: correct when fixed, defective only where documented."""

import pytest
from fastapi.testclient import TestClient
from vulnerable_saas.app.main import create_app


def make(defects=frozenset()):
    c = TestClient(create_app(defects), raise_server_exceptions=False)
    org_a = c.post("/_admin/orgs", json={"name": "a"}).json()["id"]
    org_b = c.post("/_admin/orgs", json={"name": "b"}).json()["id"]

    def user(org, role):
        r = c.post(f"/_admin/orgs/{org}/users", json={"name": role, "role": role}).json()
        return {"Authorization": f"Bearer {r['token']}"}

    return c, {
        "a_admin": user(org_a, "admin"),
        "a_member": user(org_a, "member"),
        "a_viewer": user(org_a, "viewer"),
        "b_member": user(org_b, "member"),
    }


def test_unknown_defect_name_is_rejected():
    with pytest.raises(ValueError):
        create_app(frozenset({"typo"}))


def test_authentication_required():
    c, _ = make()
    assert c.get("/documents").status_code == 401
    assert c.get("/documents", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_fixed_app_enforces_tenancy_and_roles():
    c, u = make()
    doc = c.post("/documents", json={"content": "s"}, headers=u["a_member"]).json()
    did = doc["id"]
    assert c.post("/documents", json={"content": "s"}, headers=u["a_viewer"]).status_code == 403
    assert c.get(f"/documents/{did}", headers=u["a_viewer"]).status_code == 200
    assert c.get(f"/documents/{did}", headers=u["b_member"]).status_code == 404
    assert c.put(f"/documents/{did}", json={"content": "x"}, headers=u["b_member"]).status_code == 404
    assert c.put(f"/documents/{did}", json={"content": "x"}, headers=u["a_viewer"]).status_code == 403
    assert c.delete(f"/documents/{did}", headers=u["a_member"]).status_code == 403
    assert c.put(f"/documents/{did}", json={"content": "x"}, headers=u["a_member"]).status_code == 200
    # even after an update (cache path) another tenant sees nothing
    assert c.get(f"/documents/{did}", headers=u["b_member"]).status_code == 404
    assert c.get("/documents", headers=u["b_member"]).json() == []
    assert c.delete(f"/documents/{did}", headers=u["a_admin"]).status_code == 200
    assert c.get(f"/documents/{did}", headers=u["a_admin"]).status_code == 404


def test_stale_cache_defect_needs_an_update_first():
    c, u = make(frozenset({"stale-cache-read"}))
    did = c.post("/documents", json={"content": "s"}, headers=u["a_member"]).json()["id"]
    assert c.get(f"/documents/{did}", headers=u["b_member"]).status_code == 404
    c.put(f"/documents/{did}", json={"content": "x"}, headers=u["a_member"])
    leaked = c.get(f"/documents/{did}", headers=u["b_member"])
    assert leaked.status_code == 200 and leaked.json()["content"] == "x"


def test_update_missing_tenant_check_defect():
    c, u = make(frozenset({"update-missing-tenant-check"}))
    did = c.post("/documents", json={"content": "s"}, headers=u["a_member"]).json()["id"]
    assert c.put(f"/documents/{did}", json={"content": "pwn"}, headers=u["b_member"]).status_code == 200
    assert c.get(f"/documents/{did}", headers=u["a_member"]).json()["content"] == "pwn"


def test_viewer_can_update_defect():
    c, u = make(frozenset({"viewer-can-update"}))
    did = c.post("/documents", json={"content": "s"}, headers=u["a_member"]).json()["id"]
    assert c.put(f"/documents/{did}", json={"content": "v"}, headers=u["a_viewer"]).status_code == 200


def test_reset_clears_everything_and_keeps_defects():
    c, u = make(frozenset({"stale-cache-read"}))
    c.post("/documents", json={"content": "s"}, headers=u["a_member"])
    assert c.get("/_admin/stats").json()["documents"] == 1
    assert c.post("/_admin/reset").json() == {"orgs": 0, "users": 0, "documents": 0}
    assert c.get("/documents", headers=u["a_member"]).status_code == 401  # tokens gone


def test_app_instances_do_not_share_state():
    c1, _ = make()
    c2 = TestClient(create_app())
    assert c2.get("/_admin/stats").json() == {"orgs": 0, "users": 0, "documents": 0}
    assert c1.get("/_admin/stats").json()["orgs"] == 2


# -- browser hardening headers and verbose errors --------------------------------

HARDENING = {
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


def test_the_fixed_app_sends_the_hardening_headers_on_every_answer():
    c, u = make()
    did = c.post("/documents", json={"content": "s"}, headers=u["a_member"]).json()["id"]
    answers = [
        c.get("/documents", headers=u["a_member"]),  # success
        c.get(f"/documents/{did}", headers=u["b_member"]),  # refusal
        c.get("/documents"),  # unauthenticated
        c.get("/nope"),  # no such route
        c.delete(f"/documents/{did}", headers=u["a_viewer"]),
    ]
    for response in answers:
        for name, value in HARDENING.items():
            assert response.headers[name] == value, (response.url, name)
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "server" not in response.headers or "/" not in response.headers["server"]
        assert response.headers["content-type"].startswith("application/json")


def test_missing_security_headers_drops_them_and_announces_the_stack():
    c, u = make({"missing-security-headers"})
    response = c.get("/documents", headers=u["a_member"])
    assert response.status_code == 200
    for name in (*HARDENING, "content-security-policy"):
        assert name not in response.headers
    assert response.headers["server"] == "vulnerable-saas/0.3.1 (uvicorn 0.30.1)"


def test_verbose_errors_confirm_existence_and_name_the_owner_only_when_switched_on():
    c, u = make()
    did = c.post("/documents", json={"content": "s"}, headers=u["a_member"]).json()["id"]
    quiet = c.get(f"/documents/{did}", headers=u["b_member"])
    missing = c.get("/documents/doc_999", headers=u["b_member"])
    assert (quiet.status_code, quiet.json()) == (missing.status_code, missing.json()) == (404, {"detail": "not found"})

    c, u = make({"verbose-errors"})
    did = c.post("/documents", json={"content": "s"}, headers=u["a_member"]).json()["id"]
    org = c.post(f"/documents", json={"content": "t"}, headers=u["a_member"]).json()["org_id"]
    for response in (
        c.get(f"/documents/{did}", headers=u["b_member"]),
        c.put(f"/documents/{did}", json={"content": "x"}, headers=u["b_member"]),
        c.delete(f"/documents/{did}", headers=u["b_member"]),
    ):
        assert response.status_code == 403 and org in response.json()["detail"]
    # Nothing about a document that does not exist, and nothing changed:
    assert c.get("/documents/doc_999", headers=u["b_member"]).status_code == 404
    assert c.get(f"/documents/{did}", headers=u["a_member"]).json()["content"] == "s"


def test_the_new_defects_do_not_disturb_each_other_or_the_old_ones():
    c, u = make({"verbose-errors", "missing-security-headers"})
    did = c.post("/documents", json={"content": "s"}, headers=u["a_member"]).json()["id"]
    assert c.get(f"/documents/{did}", headers=u["a_viewer"]).status_code == 200
    assert c.put(f"/documents/{did}", json={"content": "x"}, headers=u["a_viewer"]).status_code == 403
