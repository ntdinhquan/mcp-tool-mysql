from __future__ import annotations

import hashlib
import json
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Response

from cpm_server.admin.deps import make_admin_guard
from cpm_server.admin.schemas import (
    ApiError,
    AuditEntry,
    AuditList,
    ErrorBody,
    TableDescriptionIn,
    TableList,
    TableOut,
    TokenCreate,
    TokenCreated,
    TokenList,
    TokenOut,
    TokenUpdate,
    to_store_time,
)
from cpm_server.services import Services
from cpm_server.store.models import utcnow
from cpm_server.store.repo import IdempotencyConflict, TokenRevoked, TokenStatus


def build_router(services: Services) -> APIRouter:
    store, data, policy = services.store, services.data, services.policy

    router = APIRouter(
        dependencies=[Depends(make_admin_guard(services.settings))],
        responses={
            401: {"model": ErrorBody, "description": "Missing or invalid X-Admin-Key"},
            403: {"model": ErrorBody, "description": "Caller network not allowed"},
        },
    )

    async def validate_grantable(tables: list[str]) -> None:
        snapshot = await data.schema()
        unknown = {t for t in tables if t not in snapshot.tables}
        if unknown:  # the cache may simply be stale (table created recently), so retry once with a fresh schema
            snapshot = await data.schema(refresh=True)
            unknown = {t for t in tables if t not in snapshot.tables}
        if unknown:
            raise ApiError(422, "TABLE_NOT_FOUND", "Some tables do not exist.", {"tables": sorted(unknown)})
        denied = sorted(t for t in tables if policy.is_table_denied(t))
        if denied:
            raise ApiError(
                422, "TABLE_NOT_GRANTABLE", "Some tables can never be granted (server-wide denylist).", {"tables": denied}
            )

    def validate_expiry(expires_at) -> None:
        if expires_at is not None and expires_at <= utcnow():
            raise ApiError(422, "INVALID_EXPIRY", "expires_at must be in the future.")

    async def token_or_404(token_id: str):
        token = await store.get_token(token_id)
        if token is None:
            raise ApiError(404, "TOKEN_NOT_FOUND", f"Token '{token_id}' does not exist.")
        return token

    # ---- tables ---------------------------------------------------------

    @router.get("/tables", response_model=TableList, summary="List tables that can be granted")
    async def list_tables(refresh: bool = Query(False, description="Reload the schema from MySQL first.")):
        snapshot = await data.schema(refresh=refresh)
        descriptions = await store.get_descriptions()
        items = [
            TableOut(
                name=info.name,
                kind=info.kind,
                description=descriptions.get(info.name) or info.comment or None,
                row_estimate=info.row_estimate,
                grantable=not policy.is_table_denied(info.name),
            )
            for info in sorted(snapshot.tables.values(), key=lambda t: t.name)
        ]
        return TableList(items=items, total=len(items))

    @router.put(
        "/tables/{name}/description",
        response_model=TableOut,
        summary="Set the friendly label of a table (empty string removes it)",
    )
    async def set_table_description(name: str, body: TableDescriptionIn):
        snapshot = await data.schema()
        info = snapshot.tables.get(name)
        if info is None:
            raise ApiError(404, "TABLE_NOT_FOUND", f"Table '{name}' does not exist.")
        text = body.description.strip()
        if text:
            await store.set_description(name, text)
        else:
            await store.delete_description(name)
        return TableOut(
            name=info.name,
            kind=info.kind,
            description=text or info.comment or None,
            row_estimate=info.row_estimate,
            grantable=not policy.is_table_denied(info.name),
        )

    # ---- tokens ---------------------------------------------------------

    @router.post(
        "/tokens",
        response_model=TokenCreated,
        status_code=201,
        summary="Issue a token",
        description=(
            "Returns the token secret exactly once. Send an `Idempotency-Key` header to make retries safe: "
            "a replay returns the same token without the secret (revoke and re-issue if the secret was lost)."
        ),
        responses={
            409: {"model": ErrorBody, "description": "Idempotency-Key reused with a different body"},
            422: {"model": ErrorBody, "description": "Unknown / non-grantable tables or invalid expiry"},
        },
    )
    async def create_token(
        body: TokenCreate,
        response: Response,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=128)] = None,
    ):
        tables = sorted(set(body.tables))
        await validate_grantable(tables)
        expires_at = to_store_time(body.expires_at)
        validate_expiry(expires_at)

        payload = body.model_dump(mode="json")
        payload["tables"] = tables
        request_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        try:
            token, secret = await store.create_token(
                name=body.name,
                organization_name=body.organization_name,
                organization_ref=body.organization_ref,
                created_by=body.created_by,
                note=body.note,
                expires_at=expires_at,
                tables=tables,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
            )
        except IdempotencyConflict:
            raise ApiError(
                409, "IDEMPOTENCY_KEY_REUSED", "This Idempotency-Key was already used with a different request body."
            ) from None
        replayed = secret is None
        if replayed:
            response.status_code = 200
            response.headers["Idempotent-Replay"] = "true"
        return TokenCreated(**TokenOut.from_model(token).model_dump(), secret=secret, replayed=replayed)

    @router.get("/tokens", response_model=TokenList, summary="List tokens (never includes secrets)")
    async def list_tokens(
        organization_ref: str | None = None,
        status: TokenStatus | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        tokens, total = await store.list_tokens(
            organization_ref=organization_ref, status=status, limit=limit, offset=offset
        )
        return TokenList(items=[TokenOut.from_model(t) for t in tokens], total=total, limit=limit, offset=offset)

    @router.get(
        "/tokens/{token_id}",
        response_model=TokenOut,
        summary="Get one token",
        responses={404: {"model": ErrorBody}},
    )
    async def get_token(token_id: str):
        return TokenOut.from_model(await token_or_404(token_id))

    @router.patch(
        "/tokens/{token_id}",
        response_model=TokenOut,
        summary="Change tables, expiry, name or note (effective immediately)",
        responses={404: {"model": ErrorBody}, 409: {"model": ErrorBody}, 422: {"model": ErrorBody}},
    )
    async def update_token(token_id: str, body: TokenUpdate):
        await token_or_404(token_id)
        sent = body.model_fields_set
        fields: dict[str, object] = {}
        if "name" in sent and body.name is not None:
            fields["name"] = body.name
        if "note" in sent:
            fields["note"] = body.note
        if "expires_at" in sent:
            expires_at = to_store_time(body.expires_at)
            validate_expiry(expires_at)
            fields["expires_at"] = expires_at
        tables = None
        if "tables" in sent and body.tables is not None:
            tables = sorted(set(body.tables))
            await validate_grantable(tables)
        try:
            token = await store.update_token(token_id, fields=fields, tables=tables)
        except TokenRevoked:
            raise ApiError(409, "TOKEN_REVOKED", "A revoked token cannot be modified.") from None
        if token is None:
            raise ApiError(404, "TOKEN_NOT_FOUND", f"Token '{token_id}' does not exist.")
        return TokenOut.from_model(token)

    @router.post(
        "/tokens/{token_id}/revoke",
        response_model=TokenOut,
        summary="Revoke a token (kept for audit; calling it again is harmless)",
        responses={404: {"model": ErrorBody}},
    )
    async def revoke_token(token_id: str):
        token = await store.revoke_token(token_id)
        if token is None:
            raise ApiError(404, "TOKEN_NOT_FOUND", f"Token '{token_id}' does not exist.")
        return TokenOut.from_model(token)

    @router.get(
        "/tokens/{token_id}/audit",
        response_model=AuditList,
        summary="Usage history of a token, newest first",
        responses={404: {"model": ErrorBody}},
    )
    async def token_audit(
        token_id: str,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        await token_or_404(token_id)
        rows, total = await store.list_audit(token_id, limit=limit, offset=offset)
        return AuditList(items=[AuditEntry.from_model(r) for r in rows], total=total, limit=limit, offset=offset)

    return router
