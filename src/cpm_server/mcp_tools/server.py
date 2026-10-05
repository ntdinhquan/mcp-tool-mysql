# NOTE: no `from __future__ import annotations` here: the MCP SDK inspects tool signatures
# at registration time to find the Context parameter and to build the JSON schemas.
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field
from sqlalchemy.exc import DBAPIError

from cpm_server.data.query_builder import (
    FilterCondition,
    OrderBy,
    build_count,
    build_select,
    visible_columns,
)
from cpm_server.data.source import to_json_value
from cpm_server.errors import AccessDenied, QueryValidationError
from cpm_server.security.authz import accessible_tables, require_table
from cpm_server.security.middleware import PRINCIPAL_SCOPE_KEY
from cpm_server.security.tokens import Principal
from cpm_server.services import Services

logger = logging.getLogger(__name__)

# MySQL: 3024 = max_execution_time exceeded, 1317 = query interrupted
_TIMEOUT_CODES = {3024, 1317}


class TableSummary(BaseModel):
    name: str
    kind: str = Field(description="'BASE TABLE' or 'VIEW'")
    description: str
    approx_rows: int | None = Field(description="Estimated row count (not exact).")


class TableList(BaseModel):
    tables: list[TableSummary]


class ColumnDescription(BaseModel):
    name: str
    type: str
    nullable: bool
    key: str = Field(description="'PRI' for primary key columns, 'UNI'/'MUL' for indexed ones, else empty.")
    comment: str


class TableDescriptionResult(BaseModel):
    table: str
    kind: str
    description: str
    primary_key: list[str]
    columns: list[ColumnDescription]


class QueryResult(BaseModel):
    table: str
    columns: list[str]
    rows: list[dict[str, Any]]
    row_count: int
    limit: int
    offset: int
    has_more: bool = Field(description="True when more rows exist beyond this page; request the next page with offset.")
    note: str | None = None


class CountResult(BaseModel):
    table: str
    count: int


def current_principal(ctx: Context) -> Principal:
    request = ctx.request_context.request
    scope = getattr(request, "scope", None) or {}
    principal = scope.get(PRINCIPAL_SCOPE_KEY)
    if principal is None:
        raise ToolError("Authentication required.")
    return principal


def build_mcp_server(services: Services) -> MCPServer:
    settings = services.settings
    store = services.store
    data = services.data
    policy = services.policy

    mcp = MCPServer(
        name="cpm-data",
        instructions=(
            "Read-only access to a company database. Call list_tables first to see which tables your token "
            "may read, describe_table to learn a table's columns, then query_table / count_rows to read data. "
            "Queries are structured (filters, columns, order_by); raw SQL is not accepted."
        ),
    )

    async def run_tool(
        ctx: Context,
        tool: str,
        table: str | None,
        work: Callable[[Principal], Awaitable[tuple[Any, int | None]]],
    ) -> Any:
        """Authenticate, run `work`, translate errors for the caller and write the audit record."""
        principal = current_principal(ctx)
        started = time.monotonic()
        status, row_count, detail = "ok", None, None
        try:
            result, row_count = await work(principal)
            return result
        except AccessDenied as exc:
            status, detail = "denied", str(exc)
            raise ToolError(str(exc)) from None
        except QueryValidationError as exc:
            status, detail = "error", str(exc)
            raise ToolError(str(exc)) from None
        except DBAPIError as exc:
            status = "error"
            code = exc.orig.args[0] if exc.orig is not None and exc.orig.args else None
            if code in _TIMEOUT_CODES:
                detail = "query timed out"
                raise ToolError(
                    "The query took too long and was stopped. Add filters, select fewer columns or lower the limit."
                ) from None
            logger.exception("Database error in tool %s", tool)
            detail = "database error"
            raise ToolError("The database could not execute this query.") from None
        except Exception:
            status, detail = "error", "internal error"
            logger.exception("Unexpected error in tool %s", tool)
            raise ToolError("Internal error while executing the request.") from None
        finally:
            try:
                await store.write_audit(
                    token_id=principal.token_id,
                    tool=tool,
                    table_name=table,
                    status=status,
                    row_count=row_count,
                    detail=detail,
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            except Exception:
                logger.exception("Failed to write audit record")

    @mcp.tool(title="List tables")
    async def list_tables(ctx: Context) -> TableList:
        """List the database tables this token is allowed to read, with a short description and approximate row count."""

        async def work(principal: Principal):
            snapshot = await data.schema()
            descriptions = await store.get_descriptions()
            tables = [
                TableSummary(
                    name=info.name,
                    kind=info.kind,
                    description=descriptions.get(info.name) or info.comment,
                    approx_rows=info.row_estimate,
                )
                for info in accessible_tables(principal, snapshot, policy)
            ]
            return TableList(tables=tables), len(tables)

        return await run_tool(ctx, "list_tables", None, work)

    @mcp.tool(title="Describe table")
    async def describe_table(table: str, ctx: Context) -> TableDescriptionResult:
        """Show the columns (name, type, nullability, key, comment) and primary key of a table you are allowed to read."""

        async def work(principal: Principal):
            snapshot = await data.schema()
            info = require_table(principal, snapshot, policy, table)
            descriptions = await store.get_descriptions()
            visible = set(visible_columns(info, policy))
            columns = [
                ColumnDescription(name=c.name, type=c.column_type, nullable=c.nullable, key=c.key, comment=c.comment)
                for c in info.columns
                if c.name in visible
            ]
            result = TableDescriptionResult(
                table=info.name,
                kind=info.kind,
                description=descriptions.get(info.name) or info.comment,
                primary_key=[c for c in info.primary_key if c in visible],
                columns=columns,
            )
            return result, None

        return await run_tool(ctx, "describe_table", table, work)

    @mcp.tool(
        title="Query table",
        description=(
            "Read rows from a table you are allowed to read. Select columns, filter rows, sort and paginate. "
            "filters is a list of {column, op, value} combined with AND; op is one of "
            "=, !=, >, >=, <, <=, like, in, is_null. "
            f"limit defaults to {settings.default_limit} and is capped at {settings.max_rows}; "
            "use offset to page through results (has_more tells you when there is another page)."
        ),
    )
    async def query_table(
        table: str,
        ctx: Context,
        columns: list[str] | None = None,
        filters: list[FilterCondition] | None = None,
        order_by: list[OrderBy] | None = None,
        limit: int = settings.default_limit,
        offset: int = 0,
    ) -> QueryResult:
        async def work(principal: Principal):
            snapshot = await data.schema()
            info = require_table(principal, snapshot, policy, table)
            built = build_select(
                info,
                policy,
                columns=columns,
                filters=filters,
                order_by=order_by,
                limit=limit,
                offset=offset,
                max_rows=settings.max_rows,
            )
            raw_rows = await data.fetch_rows(built.statement)
            has_more = len(raw_rows) > built.limit
            raw_rows = raw_rows[: built.limit]

            rows: list[dict[str, Any]] = []
            size = 0
            note = None
            for raw in raw_rows:
                row = {k: to_json_value(v, settings.max_cell_chars) for k, v in raw.items()}
                size += len(json.dumps(row, ensure_ascii=False, default=str))
                if rows and size > settings.max_response_bytes:
                    has_more = True
                    note = "Response size limit reached; lower the limit or select fewer columns."
                    break
                rows.append(row)

            result = QueryResult(
                table=info.name,
                columns=built.columns,
                rows=rows,
                row_count=len(rows),
                limit=built.limit,
                offset=built.offset,
                has_more=has_more,
                note=note,
            )
            return result, len(rows)

        return await run_tool(ctx, "query_table", table, work)

    @mcp.tool(title="Count rows")
    async def count_rows(
        table: str,
        ctx: Context,
        filters: list[FilterCondition] | None = None,
    ) -> CountResult:
        """Count the rows of a table you are allowed to read, optionally with the same filters as query_table."""

        async def work(principal: Principal):
            snapshot = await data.schema()
            info = require_table(principal, snapshot, policy, table)
            count = int(await data.fetch_scalar(build_count(info, policy, filters=filters)))
            return CountResult(table=info.name, count=count), None

        return await run_tool(ctx, "count_rows", table, work)

    return mcp
