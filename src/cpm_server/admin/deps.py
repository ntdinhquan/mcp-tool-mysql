import hmac
import ipaddress

from fastapi import Request, Security
from fastapi.security import APIKeyHeader
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from cpm_server.admin.schemas import ApiError
from cpm_server.config import Settings

api_key_header = APIKeyHeader(
    name="X-Admin-Key",
    auto_error=False,
    description="Service key held by the CRM backend (one of ADMIN_API_KEYS).",
)


class NetworkGuardMiddleware:
    """Only lets clients from ADMIN_ALLOWED_CIDRS reach the admin API (including its docs).

    This is defence in depth: the reverse proxy must still avoid forwarding /admin to the internet.
    Behind a proxy the peer address is the proxy's, so the proxy rule is the real boundary there.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self._networks = settings.admin_networks

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not self._allowed(scope.get("client")):
            response = JSONResponse(
                {"code": "FORBIDDEN_NETWORK", "message": "Admin API is not reachable from this network."},
                status_code=403,
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _allowed(self, client: tuple[str, int] | None) -> bool:
        if not client:
            return False
        try:
            ip = ipaddress.ip_address(client[0])
        except ValueError:
            return False
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return any(ip in network for network in self._networks)


def make_admin_guard(settings: Settings):
    keys = settings.admin_keys

    async def require_admin(_request: Request, key: str | None = Security(api_key_header)) -> None:
        if not keys:
            raise ApiError(503, "ADMIN_NOT_CONFIGURED", "No ADMIN_API_KEYS are configured on the server.")
        if not key or not any(hmac.compare_digest(key.encode(), configured.encode()) for configured in keys):
            raise ApiError(401, "UNAUTHORIZED", "Missing or invalid X-Admin-Key.")

    return require_admin
