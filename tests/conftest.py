import asyncio
import json
from collections.abc import AsyncIterator

import httpx
import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import StaticPool

from cpm_server.config import Settings
from cpm_server.data.source import ColumnInfo, DataSource, TableInfo
from cpm_server.main import build_services, create_app

ADMIN_KEY = "test-admin-key"


class SqliteDataSource(DataSource):
    """Same code paths as production, but the schema comes from SQLite instead of information_schema."""

    async def _load_tables(self, conn: AsyncConnection) -> dict[str, TableInfo]:
        def inspect(sync_conn):
            insp = sa.inspect(sync_conn)
            tables = {}
            for name in insp.get_table_names():
                pk = set(insp.get_pk_constraint(name)["constrained_columns"])
                columns = tuple(
                    ColumnInfo(
                        name=c["name"],
                        data_type=str(c["type"]),
                        column_type=str(c["type"]),
                        nullable=c["nullable"],
                        key="PRI" if c["name"] in pk else "",
                        comment="",
                    )
                    for c in insp.get_columns(name)
                )
                tables[name] = TableInfo(name=name, kind="BASE TABLE", row_estimate=None, comment="", columns=columns)
            return tables

        return await conn.run_sync(inspect)


SEED = [
    "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, api_token TEXT)",
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, total REAL, note TEXT)",
    "CREATE TABLE products (id INTEGER PRIMARY KEY, title TEXT, price REAL)",
    "CREATE TABLE sessions (id TEXT PRIMARY KEY, payload TEXT)",
    "INSERT INTO users VALUES (1, 'Ann', 'ann@x.com', 'hash-ann', 'tok-ann'), (2, 'Bob', 'bob@x.com', 'hash-bob', 'tok-bob'),"
    " (3, 'Cid', NULL, 'hash-cid', 'tok-cid')",
    "INSERT INTO orders VALUES (1, 1, 10.5, 'first'), (2, 1, 20.0, NULL), (3, 2, 5.25, 'third')",
    "INSERT INTO products VALUES (1, 'Widget', 9.99), (2, 'Gadget', 19.99)",
    "INSERT INTO sessions VALUES ('s1', 'secret-payload')",
]


@pytest.fixture
async def settings(tmp_path) -> Settings:
    return Settings(
        mysql_password="unused",
        token_db_url=f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}",
        admin_api_keys=ADMIN_KEY,
        max_rows=5,
        default_limit=3,
    )


@pytest.fixture
async def app(settings):
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    async with engine.begin() as conn:
        for statement in SEED:
            await conn.execute(sa.text(statement))
    services = build_services(settings, data=SqliteDataSource(settings, engine=engine))
    application = create_app(settings, services)
    application.state.services = services

    # anyio cancel scopes (used by the MCP session manager) must be entered and exited in the same
    # task, which pytest's async fixtures do not guarantee, so the lifespan lives in its own task.
    ready, stop = asyncio.Event(), asyncio.Event()

    async def run_lifespan():
        async with application.router.lifespan_context(application):
            ready.set()
            await stop.wait()

    task = asyncio.create_task(run_lifespan())
    ready_wait = asyncio.create_task(ready.wait())
    await asyncio.wait({task, ready_wait}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():  # startup failed
        task.result()
    yield application
    stop.set()
    await task


@pytest.fixture
async def client(app) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 5000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"X-Admin-Key": ADMIN_KEY}


@pytest.fixture
def issue_token(client, admin_headers):
    async def _issue(tables: list[str], **extra) -> dict:
        body = {
            "name": "test token",
            "organization_name": "ACME",
            "organization_ref": "crm-1",
            "created_by": "admin@crm",
            "tables": tables,
            **extra,
        }
        resp = await client.post("/admin/v1/tokens", json=body, headers=admin_headers)
        assert resp.status_code == 201, resp.text
        return resp.json()

    return _issue


class McpCaller:
    """Minimal JSON-RPC caller for the stateless streamable-HTTP endpoint."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client
        self._id = 0

    async def post(self, token: str | None, method: str, params: dict | None = None) -> httpx.Response:
        self._id += 1
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        return await self._client.post("/mcp", content=json.dumps(payload), headers=headers)

    async def tool(self, token: str, name: str, arguments: dict | None = None) -> dict:
        resp = await self.post(token, "tools/call", {"name": name, "arguments": arguments or {}})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "result" in body, body
        return body["result"]


@pytest.fixture
def mcp(client) -> McpCaller:
    return McpCaller(client)
