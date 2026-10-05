from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from sqlalchemy import and_, event, func, or_, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from cpm_server.errors import AuthError
from cpm_server.security.tokens import Principal, generate_token, parse_prefix, verify_token
from cpm_server.store.models import (
    AuditLog,
    Base,
    IdempotencyKey,
    TableDescription,
    Token,
    TokenGrant,
    utcnow,
)

TokenStatus = Literal["active", "expired", "revoked"]

# `last_used_at` is only refreshed this often so a busy token does not turn every call into a write.
LAST_USED_REFRESH = timedelta(seconds=60)


class IdempotencyConflict(Exception):
    """The same Idempotency-Key was reused with a different request body."""


class TokenRevoked(Exception):
    """Raised when trying to modify a revoked token."""


def token_status(token: Token, now: datetime | None = None) -> TokenStatus:
    now = now or utcnow()
    if token.revoked_at is not None:
        return "revoked"
    if token.expires_at is not None and token.expires_at <= now:
        return "expired"
    return "active"


class TokenStore:
    def __init__(self, url: str) -> None:
        self._url = url
        self._engine: AsyncEngine = create_async_engine(url)
        if make_url(url).get_backend_name() == "sqlite":
            event.listen(self._engine.sync_engine, "connect", _sqlite_pragmas)
        self._sessions = async_sessionmaker(self._engine, expire_on_commit=False)

    async def init(self) -> None:
        url = make_url(self._url)
        if url.get_backend_name() == "sqlite" and url.database not in (None, "", ":memory:"):
            Path(url.database).parent.mkdir(parents=True, exist_ok=True)
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self._engine.dispose()

    # ---- authentication -------------------------------------------------

    async def authenticate(self, raw_token: str) -> Principal:
        prefix = parse_prefix(raw_token)
        if prefix is None:
            raise AuthError("Malformed token")
        async with self._sessions() as session:
            token = (await session.execute(select(Token).where(Token.prefix == prefix))).scalar_one_or_none()
            if token is None or not verify_token(raw_token, token.token_hash):
                raise AuthError("Invalid token")
            now = utcnow()
            status = token_status(token, now)
            if status == "revoked":
                raise AuthError("Token has been revoked")
            if status == "expired":
                raise AuthError("Token has expired")
            if token.last_used_at is None or now - token.last_used_at > LAST_USED_REFRESH:
                token.last_used_at = now
                await session.commit()
            return Principal(
                token_id=token.id,
                name=token.name,
                organization_name=token.organization_name,
                tables=frozenset(token.tables),
            )

    # ---- token management (admin API) -----------------------------------

    async def create_token(
        self,
        *,
        name: str,
        organization_name: str,
        organization_ref: str | None,
        created_by: str,
        note: str | None,
        expires_at: datetime | None,
        tables: list[str],
        idempotency_key: str | None = None,
        request_hash: str | None = None,
    ) -> tuple[Token, str | None]:
        """Create a token. Returns (token, plaintext); plaintext is None when an idempotent replay hit."""
        async with self._sessions() as session:
            if idempotency_key:
                existing = await session.get(IdempotencyKey, idempotency_key)
                if existing is not None:
                    if existing.request_hash != request_hash:
                        raise IdempotencyConflict(idempotency_key)
                    token = await session.get(Token, existing.token_id)
                    if token is not None:
                        return token, None
            generated = generate_token()
            token = Token(
                id=str(uuid.uuid4()),
                prefix=generated.prefix,
                token_hash=generated.token_hash,
                name=name,
                organization_name=organization_name,
                organization_ref=organization_ref,
                created_by=created_by,
                note=note,
                expires_at=expires_at,
                grants=[TokenGrant(table_name=t) for t in sorted(set(tables))],
            )
            session.add(token)
            if idempotency_key:
                session.add(IdempotencyKey(key=idempotency_key, request_hash=request_hash or "", token_id=token.id))
            await session.commit()
            return token, generated.plaintext

    async def get_token(self, token_id: str) -> Token | None:
        async with self._sessions() as session:
            return await session.get(Token, token_id)

    async def list_tokens(
        self,
        *,
        organization_ref: str | None,
        status: TokenStatus | None,
        limit: int,
        offset: int,
    ) -> tuple[list[Token], int]:
        now = utcnow()
        conditions = []
        if organization_ref is not None:
            conditions.append(Token.organization_ref == organization_ref)
        if status == "revoked":
            conditions.append(Token.revoked_at.is_not(None))
        elif status == "expired":
            conditions.append(and_(Token.revoked_at.is_(None), Token.expires_at.is_not(None), Token.expires_at <= now))
        elif status == "active":
            conditions.append(
                and_(Token.revoked_at.is_(None), or_(Token.expires_at.is_(None), Token.expires_at > now))
            )
        async with self._sessions() as session:
            total = (await session.execute(select(func.count()).select_from(Token).where(*conditions))).scalar_one()
            rows = (
                await session.execute(
                    select(Token).where(*conditions).order_by(Token.created_at.desc()).limit(limit).offset(offset)
                )
            ).scalars()
            return list(rows), total

    async def update_token(
        self,
        token_id: str,
        *,
        fields: dict[str, object],
        tables: list[str] | None,
    ) -> Token | None:
        """Apply a partial update. `fields` may contain name, note and expires_at (None clears it)."""
        async with self._sessions() as session:
            token = await session.get(Token, token_id)
            if token is None:
                return None
            if token.revoked_at is not None:
                raise TokenRevoked(token_id)
            for key, value in fields.items():
                setattr(token, key, value)
            if tables is not None:
                wanted = set(tables)
                for grant in list(token.grants):
                    if grant.table_name not in wanted:
                        token.grants.remove(grant)
                have = {grant.table_name for grant in token.grants}
                for table in sorted(wanted - have):
                    token.grants.append(TokenGrant(table_name=table))
            await session.commit()
            return token

    async def revoke_token(self, token_id: str) -> Token | None:
        async with self._sessions() as session:
            token = await session.get(Token, token_id)
            if token is None:
                return None
            if token.revoked_at is None:
                token.revoked_at = utcnow()
                await session.commit()
            return token

    # ---- audit ----------------------------------------------------------

    async def write_audit(
        self,
        *,
        token_id: str,
        tool: str,
        table_name: str | None,
        status: str,
        row_count: int | None,
        detail: str | None,
        duration_ms: int | None,
    ) -> None:
        async with self._sessions() as session:
            session.add(
                AuditLog(
                    token_id=token_id,
                    tool=tool,
                    table_name=table_name,
                    status=status,
                    row_count=row_count,
                    detail=detail[:1000] if detail else None,
                    duration_ms=duration_ms,
                )
            )
            await session.commit()

    async def list_audit(self, token_id: str, *, limit: int, offset: int) -> tuple[list[AuditLog], int]:
        async with self._sessions() as session:
            total = (
                await session.execute(select(func.count()).select_from(AuditLog).where(AuditLog.token_id == token_id))
            ).scalar_one()
            rows = (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.token_id == token_id)
                    .order_by(AuditLog.id.desc())
                    .limit(limit)
                    .offset(offset)
                )
            ).scalars()
            return list(rows), total

    # ---- table descriptions ---------------------------------------------

    async def get_descriptions(self) -> dict[str, str]:
        async with self._sessions() as session:
            rows = (await session.execute(select(TableDescription))).scalars()
            return {row.table_name: row.description for row in rows}

    async def set_description(self, table_name: str, description: str) -> None:
        async with self._sessions() as session:
            row = await session.get(TableDescription, table_name)
            if row is None:
                session.add(TableDescription(table_name=table_name, description=description))
            else:
                row.description = description
            await session.commit()

    async def delete_description(self, table_name: str) -> None:
        async with self._sessions() as session:
            row = await session.get(TableDescription, table_name)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _sqlite_pragmas(dbapi_connection, _record) -> None:  # noqa: ANN001
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
