from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Naive UTC timestamp. All datetimes in the store are naive UTC; the API layer adds the zone."""
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Token(Base):
    __tablename__ = "tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    prefix: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(120))
    organization_name: Mapped[str] = mapped_column(String(200))
    organization_ref: Mapped[str | None] = mapped_column(String(100), index=True)
    created_by: Mapped[str] = mapped_column(String(120))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)

    grants: Mapped[list[TokenGrant]] = relationship(
        back_populates="token", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def tables(self) -> list[str]:
        return sorted(grant.table_name for grant in self.grants)


class TokenGrant(Base):
    __tablename__ = "token_grants"
    __table_args__ = (UniqueConstraint("token_id", "table_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_id: Mapped[str] = mapped_column(ForeignKey("tokens.id", ondelete="CASCADE"), index=True)
    table_name: Mapped[str] = mapped_column(String(200))

    token: Mapped[Token] = relationship(back_populates="grants")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_id: Mapped[str] = mapped_column(String(36), index=True)
    tool: Mapped[str] = mapped_column(String(64))
    table_name: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16))  # ok | denied | error
    row_count: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class TableDescription(Base):
    __tablename__ = "table_descriptions"

    table_name: Mapped[str] = mapped_column(String(200), primary_key=True)
    description: Mapped[str] = mapped_column(String(500))


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    token_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
