from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass
from datetime import date, datetime, time as dt_time, timedelta
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from cpm_server.config import Settings


@dataclass(frozen=True)
class ColumnInfo:
    name: str
    data_type: str
    column_type: str
    nullable: bool
    key: str
    comment: str


@dataclass(frozen=True)
class TableInfo:
    name: str
    kind: str  # "BASE TABLE" or "VIEW"
    row_estimate: int | None
    comment: str
    columns: tuple[ColumnInfo, ...]

    @property
    def primary_key(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns if c.key == "PRI")


@dataclass(frozen=True)
class SchemaSnapshot:
    tables: dict[str, TableInfo]
    loaded_at: float


_TABLES_SQL = sa.text(
    "SELECT TABLE_NAME AS table_name, TABLE_TYPE AS table_type, TABLE_ROWS AS table_rows, "
    "TABLE_COMMENT AS table_comment FROM information_schema.TABLES WHERE TABLE_SCHEMA = :schema"
)
_COLUMNS_SQL = sa.text(
    "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, DATA_TYPE AS data_type, "
    "COLUMN_TYPE AS column_type, IS_NULLABLE AS is_nullable, COLUMN_KEY AS column_key, "
    "COLUMN_COMMENT AS column_comment FROM information_schema.COLUMNS "
    "WHERE TABLE_SCHEMA = :schema ORDER BY TABLE_NAME, ORDINAL_POSITION"
)


class DataSource:
    """Read-only access to the shared MySQL schema, with a cached view of its structure.

    Table and column names are only ever accepted when they appear in this cached
    snapshot, so user input never reaches the SQL text as an identifier.
    """

    def __init__(self, settings: Settings, engine: AsyncEngine | None = None) -> None:
        self._settings = settings
        self._engine = engine or self._create_engine(settings)
        self._snapshot: SchemaSnapshot | None = None
        self._lock = asyncio.Lock()

    @staticmethod
    def _create_engine(settings: Settings) -> AsyncEngine:
        url = URL.create(
            "mysql+aiomysql",
            username=settings.mysql_user,
            password=settings.mysql_password,
            host=settings.mysql_host,
            port=settings.mysql_port,
            database=settings.mysql_database,
        )
        # Belt and braces on top of the SELECT-only MySQL account: read-only sessions with a statement timeout.
        init_command = (
            f"SET SESSION transaction_read_only = 1, SESSION max_execution_time = {int(settings.query_timeout_ms)}"
        )
        return create_async_engine(
            url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=5,
            pool_recycle=1800,
            connect_args={"init_command": init_command},
        )

    async def dispose(self) -> None:
        await self._engine.dispose()

    # ---- schema ---------------------------------------------------------

    async def schema(self, *, refresh: bool = False) -> SchemaSnapshot:
        snapshot = self._snapshot
        ttl = self._settings.schema_cache_ttl_seconds
        if snapshot is not None and not refresh and time.monotonic() - snapshot.loaded_at < ttl:
            return snapshot
        async with self._lock:
            snapshot = self._snapshot
            if snapshot is not None and not refresh and time.monotonic() - snapshot.loaded_at < ttl:
                return snapshot
            async with self._engine.connect() as conn:
                tables = await self._load_tables(conn)
            self._snapshot = SchemaSnapshot(tables=tables, loaded_at=time.monotonic())
            return self._snapshot

    async def _load_tables(self, conn: AsyncConnection) -> dict[str, TableInfo]:
        schema = self._settings.mysql_database
        table_rows = (await conn.execute(_TABLES_SQL, {"schema": schema})).mappings().all()
        column_rows = (await conn.execute(_COLUMNS_SQL, {"schema": schema})).mappings().all()
        columns: dict[str, list[ColumnInfo]] = {}
        for row in column_rows:
            columns.setdefault(row["table_name"], []).append(
                ColumnInfo(
                    name=row["column_name"],
                    data_type=row["data_type"],
                    column_type=row["column_type"],
                    nullable=row["is_nullable"] == "YES",
                    key=row["column_key"] or "",
                    comment=row["column_comment"] or "",
                )
            )
        return {
            row["table_name"]: TableInfo(
                name=row["table_name"],
                kind=row["table_type"],
                row_estimate=int(row["table_rows"]) if row["table_rows"] is not None else None,
                comment=row["table_comment"] or "",
                columns=tuple(columns.get(row["table_name"], [])),
            )
            for row in table_rows
        }

    # ---- queries --------------------------------------------------------

    async def fetch_rows(self, stmt: sa.Select) -> list[dict[str, Any]]:
        async with self._engine.connect() as conn:
            result = await conn.execute(stmt)
            return [dict(row) for row in result.mappings()]

    async def fetch_scalar(self, stmt: sa.Select) -> Any:
        async with self._engine.connect() as conn:
            return (await conn.execute(stmt)).scalar_one()


def to_json_value(value: Any, max_chars: int) -> Any:
    """Convert a DB value into something JSON-safe, trimming very long strings."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime, date, dt_time)):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) > 64:
            return f"<binary {len(raw)} bytes>"
        return "base64:" + base64.b64encode(raw).decode("ascii")
    text = str(value)
    if len(text) > max_chars:
        return text[:max_chars] + f"... [truncated, {len(text)} chars total]"
    return text
