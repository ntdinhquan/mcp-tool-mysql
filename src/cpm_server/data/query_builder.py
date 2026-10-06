from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import sqlalchemy as sa
from pydantic import BaseModel, Field
from sqlalchemy.sql.elements import quoted_name

from cpm_server.data.source import TableInfo
from cpm_server.errors import QueryValidationError
from cpm_server.security.policy import AccessPolicy

Scalar = str | int | float | bool
FilterOp = Literal["=", "!=", ">", ">=", "<", "<=", "like", "in", "is_null"]

MAX_IN_VALUES = 200
MAX_FILTERS = 20
MAX_ORDER_BY = 5
MAX_OFFSET = 1_000_000
MAX_LIKE_LENGTH = 200


class FilterCondition(BaseModel):
    column: str = Field(description="Column name, exactly as returned by describe_table.")
    op: FilterOp = Field(
        default="=",
        description=(
            "Comparison operator. 'like' uses SQL wildcards (% and _). 'in' needs a list value. "
            "'is_null' takes true (IS NULL) or false (IS NOT NULL); omitting the value means true."
        ),
    )
    value: Scalar | list[Scalar] | None = Field(default=None, description="Value to compare against.")


class OrderBy(BaseModel):
    column: str
    direction: Literal["asc", "desc"] = "asc"


@dataclass(frozen=True)
class BuiltQuery:
    statement: sa.Select
    columns: list[str]
    limit: int
    offset: int


def visible_columns(table: TableInfo, policy: AccessPolicy) -> list[str]:
    return [c.name for c in table.columns if not policy.is_column_hidden(c.name)]


def _table(table: TableInfo) -> sa.TableClause:
    return sa.table(quoted_name(table.name, quote=True))


def _column(name: str) -> sa.ColumnClause:
    return sa.column(quoted_name(name, quote=True))


def _require_visible(name: str, allowed: set[str], what: str) -> None:
    # Hidden columns get the same error as unknown ones, so they cannot be probed for.
    if name not in allowed:
        raise QueryValidationError(f"Unknown {what} '{name}'. Use describe_table to see the available columns.")


def _is_scalar(value: object) -> bool:
    return isinstance(value, (str, int, float, bool))


def _condition(col: sa.ColumnClause, flt: FilterCondition) -> sa.ColumnElement[bool]:
    op, value = flt.op, flt.value
    if op == "is_null":
        if value is None or value is True:
            return col.is_(None)
        if value is False:
            return col.is_not(None)
        raise QueryValidationError("is_null expects true, false or no value.")
    if op == "in":
        if not isinstance(value, list) or not value:
            raise QueryValidationError("Operator 'in' needs a non-empty list value.")
        if len(value) > MAX_IN_VALUES:
            raise QueryValidationError(f"Operator 'in' accepts at most {MAX_IN_VALUES} values.")
        return col.in_(value)
    if value is None or isinstance(value, list) or not _is_scalar(value):
        raise QueryValidationError(
            f"Operator '{op}' needs a single value. Use op 'is_null' to test for NULL, or 'in' for several values."
        )
    if op == "like":
        if not isinstance(value, str):
            raise QueryValidationError("Operator 'like' needs a string value.")
        if len(value) > MAX_LIKE_LENGTH:
            raise QueryValidationError(f"Pattern for 'like' is limited to {MAX_LIKE_LENGTH} characters.")
        return col.like(value)
    match op:
        case "=":
            return col == value
        case "!=":
            return col != value
        case ">":
            return col > value
        case ">=":
            return col >= value
        case "<":
            return col < value
        case "<=":
            return col <= value
    raise QueryValidationError(f"Unsupported operator '{op}'.")


def _conditions(filters: list[FilterCondition] | None, allowed: set[str]) -> list[sa.ColumnElement[bool]]:
    filters = filters or []
    if len(filters) > MAX_FILTERS:
        raise QueryValidationError(f"At most {MAX_FILTERS} filters are allowed per query.")
    result = []
    for flt in filters:
        _require_visible(flt.column, allowed, "column")
        result.append(_condition(_column(flt.column), flt))
    return result


def build_select(
    table: TableInfo,
    policy: AccessPolicy,
    *,
    columns: list[str] | None,
    filters: list[FilterCondition] | None,
    order_by: list[OrderBy] | None,
    limit: int,
    offset: int,
    max_rows: int,
) -> BuiltQuery:
    allowed = visible_columns(table, policy)
    allowed_set = set(allowed)
    if not allowed:
        raise QueryValidationError(f"Table '{table.name}' has no columns available through this server.")

    selected = columns or allowed
    if len(set(selected)) != len(selected):
        raise QueryValidationError("Duplicate column names in 'columns'.")
    for name in selected:
        _require_visible(name, allowed_set, "column")

    if offset < 0 or offset > MAX_OFFSET:
        raise QueryValidationError(f"offset must be between 0 and {MAX_OFFSET}.")
    limit = max(1, min(limit, max_rows))

    order_by = order_by or []
    if len(order_by) > MAX_ORDER_BY:
        raise QueryValidationError(f"At most {MAX_ORDER_BY} order_by entries are allowed.")
    ordering = []
    for item in order_by:
        _require_visible(item.column, allowed_set, "order_by column")
        col = _column(item.column)
        ordering.append(col.desc() if item.direction == "desc" else col.asc())
    if not ordering:
        # A stable order is what makes offset-based pagination safe.
        ordering = [_column(name).asc() for name in table.primary_key if name in allowed_set]

    # One extra row tells the caller whether there is more data without a second COUNT query.
    stmt = sa.select(*[_column(name) for name in selected]).select_from(_table(table))
    for condition in _conditions(filters, allowed_set):
        stmt = stmt.where(condition)
    if ordering:
        stmt = stmt.order_by(*ordering)
    stmt = stmt.limit(limit + 1).offset(offset)
    return BuiltQuery(statement=stmt, columns=list(selected), limit=limit, offset=offset)


def build_count(table: TableInfo, policy: AccessPolicy, *, filters: list[FilterCondition] | None) -> sa.Select:
    allowed_set = set(visible_columns(table, policy))
    stmt = sa.select(sa.func.count()).select_from(_table(table))
    for condition in _conditions(filters, allowed_set):
        stmt = stmt.where(condition)
    return stmt
