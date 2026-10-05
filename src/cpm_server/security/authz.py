from cpm_server.data.source import SchemaSnapshot, TableInfo
from cpm_server.errors import AccessDenied
from cpm_server.security.policy import AccessPolicy
from cpm_server.security.tokens import Principal


def require_table(principal: Principal, snapshot: SchemaSnapshot, policy: AccessPolicy, table: str) -> TableInfo:
    """Return the table metadata if this token may read `table`, otherwise raise AccessDenied.

    "Not granted", "denylisted" and "does not exist" all produce the same message, so a token
    holder cannot use the error to discover which other tables exist in the database.
    """
    info = snapshot.tables.get(table)
    if info is None or table not in principal.tables or policy.is_table_denied(table):
        raise AccessDenied(f"Table '{table}' is not accessible with this token. Use list_tables to see what is available.")
    return info


def accessible_tables(principal: Principal, snapshot: SchemaSnapshot, policy: AccessPolicy) -> list[TableInfo]:
    return [
        snapshot.tables[name]
        for name in sorted(principal.tables)
        if name in snapshot.tables and not policy.is_table_denied(name)
    ]
