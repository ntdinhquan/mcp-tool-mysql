from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from cpm_server.store.models import AuditLog, Token
from cpm_server.store.repo import TokenStatus, token_status


class ApiError(Exception):
    """Raised by endpoints; rendered as {"code", "message", "details"} with a stable `code`."""

    def __init__(self, status_code: int, code: str, message: str, details: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


class ErrorBody(BaseModel):
    code: str
    message: str
    details: Any | None = None


def as_utc(value: datetime | None) -> datetime | None:
    """The store keeps naive UTC; the API always speaks timezone-aware UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def to_store_time(value: datetime | None) -> datetime | None:
    """Normalise incoming datetimes to naive UTC (naive input is assumed to already be UTC)."""
    if value is None:
        return None
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo is not None else value


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120, description="Label for this token, e.g. 'ACME reporting'.")
    organization_name: str = Field(min_length=1, max_length=200, description="Business receiving the token.")
    organization_ref: str | None = Field(
        default=None, max_length=100, description="The business' ID in the CRM, used to list tokens per business."
    )
    tables: list[str] = Field(min_length=1, max_length=500, description="Tables the token may read.")
    expires_at: datetime | None = Field(default=None, description="ISO 8601; omit for a token that never expires.")
    created_by: str = Field(min_length=1, max_length=120, description="CRM admin issuing the token (for the audit trail).")
    note: str | None = Field(default=None, max_length=1000)


class TokenUpdate(BaseModel):
    """Partial update. Send only what changes; `expires_at: null` removes the expiry."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    tables: list[str] | None = Field(default=None, min_length=1, max_length=500)
    expires_at: datetime | None = None
    note: str | None = Field(default=None, max_length=1000)


class TokenOut(BaseModel):
    id: str
    prefix: str = Field(description="First characters of the token, safe to display to identify it.")
    name: str
    organization_name: str
    organization_ref: str | None
    created_by: str
    note: str | None
    tables: list[str]
    status: TokenStatus
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None

    @classmethod
    def from_model(cls, token: Token) -> TokenOut:
        return cls(
            id=token.id,
            prefix=token.prefix,
            name=token.name,
            organization_name=token.organization_name,
            organization_ref=token.organization_ref,
            created_by=token.created_by,
            note=token.note,
            tables=token.tables,
            status=token_status(token),
            created_at=as_utc(token.created_at),
            expires_at=as_utc(token.expires_at),
            revoked_at=as_utc(token.revoked_at),
            last_used_at=as_utc(token.last_used_at),
        )


class TokenCreated(TokenOut):
    secret: str | None = Field(
        description=(
            "The full token. Returned ONLY on creation and never again; show it to the admin once. "
            "Null when the request was an idempotent replay (the secret cannot be recovered)."
        )
    )
    replayed: bool = False


class TokenList(BaseModel):
    items: list[TokenOut]
    total: int
    limit: int
    offset: int


class TableOut(BaseModel):
    name: str
    kind: str = Field(description="'BASE TABLE' or 'VIEW'")
    description: str | None
    row_estimate: int | None
    grantable: bool = Field(description="False when the table is on the server-wide denylist and can never be granted.")


class TableDescriptionIn(BaseModel):
    description: str = Field(max_length=500, description="Human readable label shown to CRM admins and to MCP clients.")


class AuditEntry(BaseModel):
    id: int
    tool: str
    table: str | None
    status: str = Field(description="ok | denied | error")
    row_count: int | None
    detail: str | None
    duration_ms: int | None
    created_at: datetime

    @classmethod
    def from_model(cls, row: AuditLog) -> AuditEntry:
        return cls(
            id=row.id,
            tool=row.tool,
            table=row.table_name,
            status=row.status,
            row_count=row.row_count,
            detail=row.detail,
            duration_ms=row.duration_ms,
            created_at=as_utc(row.created_at),
        )


class AuditList(BaseModel):
    items: list[AuditEntry]
    total: int
    limit: int
    offset: int


class TableList(BaseModel):
    items: list[TableOut]
    total: int
