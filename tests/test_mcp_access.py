from datetime import UTC, datetime, timedelta


def names(result):
    return [t["name"] for t in result["structuredContent"]["tables"]]


def error_text(result):
    assert result["isError"] is True
    return result["content"][0]["text"]


async def test_requires_a_valid_bearer_token(mcp):
    r = await mcp.post(None, "tools/list")
    assert r.status_code == 401
    assert "Bearer" in r.headers["www-authenticate"]
    for bad in ["garbage", "cpm_deadbeef_nope", "cpm_"]:
        r = await mcp.post(bad, "tools/list")
        assert r.status_code == 401, bad


async def test_list_tables_only_shows_granted(issue_token, mcp):
    token = (await issue_token(["users", "orders"]))["secret"]
    result = await mcp.tool(token, "list_tables")
    assert names(result) == ["orders", "users"]


async def test_ungranted_table_is_denied_on_every_tool(issue_token, mcp):
    token = (await issue_token(["users"]))["secret"]
    for tool, args in [
        ("describe_table", {"table": "orders"}),
        ("query_table", {"table": "orders"}),
        ("count_rows", {"table": "orders"}),
    ]:
        result = await mcp.tool(token, tool, args)
        assert "not accessible" in error_text(result), tool


async def test_denied_and_missing_tables_are_indistinguishable(issue_token, mcp):
    token = (await issue_token(["users"]))["secret"]
    a = error_text(await mcp.tool(token, "query_table", {"table": "orders"}))
    b = error_text(await mcp.tool(token, "query_table", {"table": "does_not_exist"}))
    assert a.replace("orders", "X") == b.replace("does_not_exist", "X")


async def test_describe_hides_sensitive_columns(issue_token, mcp):
    token = (await issue_token(["users"]))["secret"]
    result = await mcp.tool(token, "describe_table", {"table": "users"})
    cols = [c["name"] for c in result["structuredContent"]["columns"]]
    assert cols == ["id", "name", "email"]
    assert result["structuredContent"]["primary_key"] == ["id"]


async def test_query_never_returns_sensitive_columns(issue_token, mcp):
    token = (await issue_token(["users"]))["secret"]
    result = await mcp.tool(token, "query_table", {"table": "users"})
    rows = result["structuredContent"]["rows"]
    assert rows and all(set(r) == {"id", "name", "email"} for r in rows)
    assert "hash-ann" not in str(result) and "tok-ann" not in str(result)

    for args in [
        {"table": "users", "columns": ["password"]},
        {"table": "users", "filters": [{"column": "password", "op": "like", "value": "h%"}]},
        {"table": "users", "order_by": [{"column": "api_token"}]},
    ]:
        assert "Unknown" in error_text(await mcp.tool(token, "query_table", args))


async def test_denylisted_table_is_blocked_even_if_a_grant_exists(issue_token, mcp, app):
    created = await issue_token(["users"])
    token = created["secret"]
    # Simulate a grant that predates the denylist entry.
    await app.state.services.store.update_token(created["id"], fields={}, tables=["users", "sessions"])
    result = await mcp.tool(token, "query_table", {"table": "sessions"})
    assert "not accessible" in error_text(result)
    assert "sessions" not in names(await mcp.tool(token, "list_tables"))


async def test_filters_ordering_and_columns(issue_token, mcp):
    token = (await issue_token(["orders"]))["secret"]
    result = await mcp.tool(
        token,
        "query_table",
        {
            "table": "orders",
            "columns": ["id", "total"],
            "filters": [{"column": "user_id", "op": "=", "value": 1}],
            "order_by": [{"column": "total", "direction": "desc"}],
        },
    )
    assert result["structuredContent"]["rows"] == [{"id": 2, "total": 20.0}, {"id": 1, "total": 10.5}]

    result = await mcp.tool(
        token, "query_table", {"table": "orders", "filters": [{"column": "note", "op": "is_null"}], "columns": ["id"]}
    )
    assert result["structuredContent"]["rows"] == [{"id": 2}]

    result = await mcp.tool(
        token,
        "query_table",
        {"table": "orders", "filters": [{"column": "id", "op": "in", "value": [1, 3]}], "columns": ["id"]},
    )
    assert [r["id"] for r in result["structuredContent"]["rows"]] == [1, 3]


async def test_sql_injection_attempts_do_not_leak_or_break(issue_token, mcp):
    token = (await issue_token(["users"]))["secret"]
    result = await mcp.tool(
        token, "query_table", {"table": "users", "filters": [{"column": "name", "value": "x' OR '1'='1"}]}
    )
    assert result["structuredContent"]["rows"] == []
    result = await mcp.tool(token, "query_table", {"table": "users; DROP TABLE users"})
    assert "not accessible" in error_text(result)
    # table still intact
    assert (await mcp.tool(token, "count_rows", {"table": "users"}))["structuredContent"]["count"] == 3


async def test_pagination_and_limit_cap(issue_token, mcp):
    token = (await issue_token(["orders"]))["secret"]
    page1 = (await mcp.tool(token, "query_table", {"table": "orders", "limit": 2}))["structuredContent"]
    assert page1["row_count"] == 2 and page1["has_more"] is True
    page2 = (await mcp.tool(token, "query_table", {"table": "orders", "limit": 2, "offset": 2}))["structuredContent"]
    assert page2["row_count"] == 1 and page2["has_more"] is False
    assert [r["id"] for r in page1["rows"] + page2["rows"]] == [1, 2, 3]

    capped = (await mcp.tool(token, "query_table", {"table": "orders", "limit": 1000}))["structuredContent"]
    assert capped["limit"] == 5  # max_rows in the test settings
    default = (await mcp.tool(token, "query_table", {"table": "orders"}))["structuredContent"]
    assert default["limit"] == 3  # default_limit in the test settings


async def test_count_rows_with_filter(issue_token, mcp):
    token = (await issue_token(["orders"]))["secret"]
    result = await mcp.tool(token, "count_rows", {"table": "orders", "filters": [{"column": "user_id", "value": 1}]})
    assert result["structuredContent"]["count"] == 2


async def test_revoking_takes_effect_immediately(issue_token, mcp, client, admin_headers):
    created = await issue_token(["users"])
    assert (await mcp.post(created["secret"], "tools/list")).status_code == 200
    await client.post(f"/admin/v1/tokens/{created['id']}/revoke", headers=admin_headers)
    r = await mcp.post(created["secret"], "tools/list")
    assert r.status_code == 401 and "revoked" in r.headers["www-authenticate"]


async def test_editing_tables_takes_effect_immediately(issue_token, mcp, client, admin_headers):
    created = await issue_token(["users"])
    token = created["secret"]
    url = f"/admin/v1/tokens/{created['id']}"
    assert names(await mcp.tool(token, "list_tables")) == ["users"]
    await client.patch(url, json={"tables": ["users", "products"]}, headers=admin_headers)
    assert names(await mcp.tool(token, "list_tables")) == ["products", "users"]
    await client.patch(url, json={"tables": ["products"]}, headers=admin_headers)
    assert "not accessible" in error_text(await mcp.tool(token, "query_table", {"table": "users"}))


async def test_expired_token_is_rejected(issue_token, mcp, app):
    created = await issue_token(["users"], expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat())
    assert (await mcp.post(created["secret"], "tools/list")).status_code == 200
    # Move the expiry into the past directly in the store (the API refuses past dates).
    past = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
    await app.state.services.store.update_token(created["id"], fields={"expires_at": past}, tables=None)
    r = await mcp.post(created["secret"], "tools/list")
    assert r.status_code == 401 and "expired" in r.headers["www-authenticate"]


async def test_one_token_cannot_use_anothers_grants(issue_token, mcp):
    a = (await issue_token(["users"]))["secret"]
    b = (await issue_token(["orders"]))["secret"]
    assert names(await mcp.tool(a, "list_tables")) == ["users"]
    assert names(await mcp.tool(b, "list_tables")) == ["orders"]


async def test_usage_is_audited(issue_token, mcp, client, admin_headers):
    created = await issue_token(["users"])
    token = created["secret"]
    await mcp.tool(token, "list_tables")
    await mcp.tool(token, "query_table", {"table": "users"})
    await mcp.tool(token, "query_table", {"table": "orders"})
    audit = (await client.get(f"/admin/v1/tokens/{created['id']}/audit", headers=admin_headers)).json()
    assert audit["total"] == 3
    newest = audit["items"][0]
    assert (newest["tool"], newest["table"], newest["status"]) == ("query_table", "orders", "denied")
    ok = [i for i in audit["items"] if i["tool"] == "query_table" and i["status"] == "ok"][0]
    assert ok["row_count"] == 3
    last_used = (await client.get(f"/admin/v1/tokens/{created['id']}", headers=admin_headers)).json()["last_used_at"]
    assert last_used is not None
