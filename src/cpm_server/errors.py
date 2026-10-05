class CpmError(Exception):
    """Base class for errors that carry a message safe to show to the caller."""


class AuthError(CpmError):
    """Missing, malformed, unknown, expired or revoked token."""


class AccessDenied(CpmError):
    """The token is valid but may not touch the requested table."""


class QueryValidationError(CpmError):
    """The structured query is invalid (unknown column, bad operator, ...)."""
