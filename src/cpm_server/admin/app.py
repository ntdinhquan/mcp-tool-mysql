from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from cpm_server.admin.deps import NetworkGuardMiddleware
from cpm_server.admin.router import build_router
from cpm_server.admin.schemas import ApiError
from cpm_server.services import Services

DESCRIPTION = """
Backend contract for the CRM *Settings* page: list tables, issue / edit / revoke tokens, read usage history.

**Call this API from the CRM backend, never from the browser.** Authenticate with the `X-Admin-Key` header.

Every error has the shape `{"code": "...", "message": "...", "details": ...}`; `code` values are stable.
"""


def _error(status: int, code: str, message: str, details=None) -> JSONResponse:
    return JSONResponse({"code": code, "message": message, "details": details}, status_code=status)


def build_admin_app(services: Services) -> FastAPI:
    settings = services.settings
    app = FastAPI(
        title="CPM MCP Admin API",
        version="1.0.0",
        description=DESCRIPTION,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.include_router(build_router(services))

    @app.exception_handler(ApiError)
    async def api_error_handler(_request: Request, exc: ApiError):
        return _error(exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_request: Request, exc: RequestValidationError):
        details = [{"loc": list(e["loc"]), "message": e["msg"], "type": e["type"]} for e in exc.errors()]
        return _error(422, "VALIDATION_ERROR", "The request is invalid.", details)

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(_request: Request, exc: StarletteHTTPException):
        code = "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"
        return _error(exc.status_code, code, str(exc.detail))

    if settings.admin_cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.admin_cors_origin_list,
            allow_methods=["GET", "POST", "PATCH", "PUT"],
            allow_headers=["X-Admin-Key", "Content-Type", "Idempotency-Key"],
        )
    # Added last so it runs first: nothing is served to clients outside the allowed networks.
    app.add_middleware(NetworkGuardMiddleware, settings=settings)
    return app
