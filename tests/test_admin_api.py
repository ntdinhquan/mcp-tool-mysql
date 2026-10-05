from datetime import UTC, datetime, timedelta

import httpx


async def test_requires_admin_key(client):
    assert (await client.get("/admin/v1/tokens")).status_code == 401
    r = await client.get("/admin/v1/tokens", headers={"X-Admin-Key": "wrong"})
    assert r.status_code == 401
    assert r.json()["code"] == "UNAUTHORIZED"


async def test_network_guard_blocks_outside_clients(app, admin_headers):
    transport = httpx.ASGITransport(app=app, client=("8.8.8.8", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as outside:
        r = await outside.get("/admin/v1/tokens", headers=admin_headers)
        assert r.status_code == 403
        assert r.json()["code"] == "FORBIDDEN_NETWORK"
        assert (await outside.get("/admin/v1/docs")).status_code == 403


async def test_openapi_and_docs_available(client):
    spec = (await client.get("/admin/v1/openapi.json")).json()
    assert spec["info"]["title"] == "CPM MCP Admin API"
    assert "/tokens" in spec["paths"]
    assert (await client.get("/admin/v1/docs")).status_code == 200


async def test_list_tables_marks_denylisted(client, admin_headers):
    r = await client.get("/admin/v1/tables", headers=admin_headers)
    assert r.status_code == 200
    by_name = {t["name"]: t for t in r.json()["items"]}
    assert by_name["users"]["grantable"] is True
    assert by_name["sessions"]["grantable"] is False


async def test_create_token_returns_secret_once(client, admin_headers, issue_token):
    created = await issue_token(["users", "orders"])
    assert created["secret"].startswith("cpm_")
    assert created["tables"] == ["orders", "users"]
    assert created["status"] == "active"
    assert created["organization_name"] == "ACME"

    got = (await client.get(f"/admin/v1/tokens/{created['id']}", headers=admin_headers)).json()
    assert "secret" not in got
    listing = (await client.get("/admin/v1/tokens", headers=admin_headers)).text
    assert created["secret"] not in listing


async def test_cannot_grant_denylisted_or_unknown_tables(client, admin_headers):
    body = {"name": "n", "organization_name": "o", "created_by": "a", "tables": ["users", "sessions", "ghost"]}
    r = await client.post("/admin/v1/tokens", json=body, headers=admin_headers)
    assert r.status_code == 422
    assert r.json()["code"] == "TABLE_NOT_FOUND"
    assert r.json()["details"] == {"tables": ["ghost"]}

    body["tables"] = ["users", "sessions"]
    r = await client.post("/admin/v1/tokens", json=body, headers=admin_headers)
    assert r.status_code == 422
    assert r.json()["code"] == "TABLE_NOT_GRANTABLE"


async def test_validation_errors_use_stable_shape(client, admin_headers):
    r = await client.post("/admin/v1/tokens", json={"name": ""}, headers=admin_headers)
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "VALIDATION_ERROR" and isinstance(body["details"], list)


async def test_expiry_must_be_in_future(client, admin_headers):
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    body = {"name": "n", "organization_name": "o", "created_by": "a", "tables": ["users"], "expires_at": past}
    r = await client.post("/admin/v1/tokens", json=body, headers=admin_headers)
    assert r.status_code == 422 and r.json()["code"] == "INVALID_EXPIRY"


async def test_idempotency_key(client, admin_headers):
    body = {"name": "n", "organization_name": "o", "created_by": "a", "tables": ["users"]}
    headers = {**admin_headers, "Idempotency-Key": "abc-123"}
    first = await client.post("/admin/v1/tokens", json=body, headers=headers)
    second = await client.post("/admin/v1/tokens", json=body, headers=headers)
    assert first.status_code == 201 and second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["secret"] and second.json()["secret"] is None
    assert second.json()["replayed"] is True
    assert second.headers["Idempotent-Replay"] == "true"
    total = (await client.get("/admin/v1/tokens", headers=admin_headers)).json()["total"]
    assert total == 1

    other = await client.post("/admin/v1/tokens", json={**body, "name": "different"}, headers=headers)
    assert other.status_code == 409 and other.json()["code"] == "IDEMPOTENCY_KEY_REUSED"


async def test_list_filters_and_pagination(client, admin_headers, issue_token):
    a = await issue_token(["users"], organization_ref="crm-1")
    await issue_token(["users"], organization_ref="crm-2")
    await issue_token(["orders"], organization_ref="crm-2")
    await client.post(f"/admin/v1/tokens/{a['id']}/revoke", headers=admin_headers)

    def get(**params):
        return client.get("/admin/v1/tokens", params=params, headers=admin_headers)

    assert (await get(organization_ref="crm-2")).json()["total"] == 2
    assert (await get(status="revoked")).json()["total"] == 1
    assert (await get(status="active")).json()["total"] == 2
    page = (await get(limit=1, offset=1)).json()
    assert page["total"] == 3 and len(page["items"]) == 1


async def test_patch_tables_and_expiry(client, admin_headers, issue_token):
    created = await issue_token(["users"], expires_at=(datetime.now(UTC) + timedelta(days=1)).isoformat())
    url = f"/admin/v1/tokens/{created['id']}"
    r = await client.patch(url, json={"tables": ["orders", "products"], "note": "hello"}, headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["tables"] == ["orders", "products"] and r.json()["note"] == "hello"
    assert r.json()["expires_at"] is not None  # untouched

    r = await client.patch(url, json={"expires_at": None}, headers=admin_headers)
    assert r.json()["expires_at"] is None  # explicit null clears the expiry

    r = await client.patch(url, json={"tables": ["sessions"]}, headers=admin_headers)
    assert r.json()["code"] == "TABLE_NOT_GRANTABLE"


async def test_revoke_is_idempotent_and_blocks_edits(client, admin_headers, issue_token):
    created = await issue_token(["users"])
    url = f"/admin/v1/tokens/{created['id']}"
    r1 = await client.post(url + "/revoke", headers=admin_headers)
    r2 = await client.post(url + "/revoke", headers=admin_headers)
    assert r1.json()["status"] == "revoked" and r2.json()["revoked_at"] == r1.json()["revoked_at"]
    r = await client.patch(url, json={"note": "x"}, headers=admin_headers)
    assert r.status_code == 409 and r.json()["code"] == "TOKEN_REVOKED"


async def test_unknown_token_is_404(client, admin_headers):
    for method, path in [("GET", ""), ("POST", "/revoke"), ("GET", "/audit")]:
        r = await client.request(method, f"/admin/v1/tokens/nope{path}", headers=admin_headers)
        assert r.status_code == 404 and r.json()["code"] == "TOKEN_NOT_FOUND", path


async def test_table_description(client, admin_headers):
    r = await client.put("/admin/v1/tables/users/description", json={"description": "People"}, headers=admin_headers)
    assert r.status_code == 200 and r.json()["description"] == "People"
    tables = {t["name"]: t for t in (await client.get("/admin/v1/tables", headers=admin_headers)).json()["items"]}
    assert tables["users"]["description"] == "People"
    r = await client.put("/admin/v1/tables/ghost/description", json={"description": "x"}, headers=admin_headers)
    assert r.status_code == 404
