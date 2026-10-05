import logging
from contextlib import asynccontextmanager

from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from cpm_server.admin.app import build_admin_app
from cpm_server.config import Settings, get_settings
from cpm_server.data.source import DataSource
from cpm_server.mcp_tools.server import build_mcp_server
from cpm_server.security.middleware import BearerAuthMiddleware
from cpm_server.security.policy import AccessPolicy
from cpm_server.services import Services
from cpm_server.store.repo import TokenStore

logger = logging.getLogger("cpm_server")


def build_services(settings: Settings, data: DataSource | None = None) -> Services:
    return Services(
        settings=settings,
        store=TokenStore(settings.token_db_url),
        data=data or DataSource(settings),
        policy=AccessPolicy(settings.table_denylist, settings.column_denylist),
    )


def create_app(settings: Settings | None = None, services: Services | None = None) -> Starlette:
    settings = settings or get_settings()
    services = services or build_services(settings)

    mcp_server = build_mcp_server(services)

    # DNS-rebinding protection only matters for unauthenticated localhost servers. Every request here
    # needs a bearer token, so it is opt-in (ALLOWED_HOSTS) rather than forced on.
    allowed_hosts = settings.allowed_host_list
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=bool(allowed_hosts),
        allowed_hosts=allowed_hosts,
        allowed_origins=[f"https://{h}" for h in allowed_hosts],
    )
    # Stateless + JSON responses: each request is self-contained, which suits a query-only server
    # and means a token's permissions are re-checked on every call.
    mcp_app = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=transport_security,
    )
    mcp_app.add_middleware(BearerAuthMiddleware, authenticate=services.store.authenticate)

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    routes: list = [Route("/healthz", healthz)]
    if settings.admin_enabled:
        routes.append(Mount("/admin/v1", app=build_admin_app(services)))
        if not settings.admin_keys:
            logger.warning("ADMIN_ENABLED is true but ADMIN_API_KEYS is empty: every admin call will return 503.")
    routes.append(Mount("/", app=mcp_app))

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        await services.store.init()
        # A mounted sub-app's own lifespan is not run, so the MCP session manager is started here.
        async with mcp_server.session_manager.run():
            yield
        await services.data.dispose()
        await services.store.dispose()

    return Starlette(routes=routes, lifespan=lifespan)
