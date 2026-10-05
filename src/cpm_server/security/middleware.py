from collections.abc import Awaitable, Callable

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from cpm_server.errors import AuthError
from cpm_server.security.tokens import Principal

PRINCIPAL_SCOPE_KEY = "cpm_principal"

Authenticator = Callable[[str], Awaitable[Principal]]


class BearerAuthMiddleware:
    """Rejects any HTTP request without a valid `Authorization: Bearer cpm_...` token.

    On success the resolved Principal is stored in the ASGI scope, where MCP tools read it
    through the request object. Permissions are looked up on every request, so revoking a
    token or editing its tables takes effect immediately.
    """

    def __init__(self, app: ASGIApp, authenticate: Authenticator) -> None:
        self.app = app
        self._authenticate = authenticate

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        scheme, _, credential = Headers(scope=scope).get("authorization", "").partition(" ")
        credential = credential.strip()
        if scheme.lower() != "bearer" or not credential:
            await self._reject(scope, receive, send, "invalid_request", "Missing bearer token")
            return
        try:
            principal = await self._authenticate(credential)
        except AuthError as exc:
            await self._reject(scope, receive, send, "invalid_token", str(exc))
            return

        scope[PRINCIPAL_SCOPE_KEY] = principal
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, error: str, description: str) -> None:
        response = JSONResponse(
            {"error": error, "error_description": description},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer realm="cpm-mcp", error="{error}", error_description="{description}"'},
        )
        await response(scope, receive, send)
