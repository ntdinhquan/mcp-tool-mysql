import pytest


@pytest.mark.parametrize("path", ["/", "/docs", "/v1/admin/docs", "/favicon.ico", "/mcpx", "/admin"])
async def test_unknown_paths_are_404_not_401(client, path):
    """A mistyped URL must not look like an authentication failure."""
    r = await client.get(path)
    assert r.status_code == 404, path
    assert r.json() == {"error": "not_found"}


async def test_unknown_paths_stay_404_even_with_a_valid_token(client, issue_token):
    token = (await issue_token(["users"]))["secret"]
    r = await client.get("/docs", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404


async def test_mcp_endpoint_still_requires_a_token(mcp):
    assert (await mcp.post(None, "tools/list")).status_code == 401


async def test_admin_docs_live_under_admin_v1(client):
    assert (await client.get("/admin/v1/docs")).status_code == 200
    assert (await client.get("/healthz")).status_code == 200
