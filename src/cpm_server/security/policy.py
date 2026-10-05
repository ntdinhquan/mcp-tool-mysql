from fnmatch import fnmatchcase


class AccessPolicy:
    """Server-wide safety nets that apply to every token regardless of its grants.

    Grants are table-level, so granting a table would otherwise expose every column in it
    (e.g. `users.password`). The denylists make sure such data can never leave the server.
    """

    def __init__(self, table_patterns: list[str], column_patterns: list[str]) -> None:
        self._table_patterns = table_patterns
        self._column_patterns = column_patterns

    def is_table_denied(self, table: str) -> bool:
        name = table.lower()
        return any(fnmatchcase(name, pattern) for pattern in self._table_patterns)

    def is_column_hidden(self, column: str) -> bool:
        name = column.lower()
        return any(fnmatchcase(name, pattern) for pattern in self._column_patterns)
