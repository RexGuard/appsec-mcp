"""Read-only local HTTP API and static viewer. Bound to 127.0.0.1 and protected by a token."""

import logging
import secrets
import webbrowser
from collections.abc import Awaitable, Callable
from importlib import resources
from pathlib import Path

from pydantic import BaseModel, ValidationError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from appsec_mcp.context import AppContext
from appsec_mcp.errors import AppSecError, NotFoundError
from appsec_mcp.models.base import SEVERITY_RANK

logger = logging.getLogger(__name__)

LOCALHOST = "127.0.0.1"
TOKEN_HEADER = "X-AppSec-Token"  # noqa: S105 - a header name, not a secret
_TOKEN_BYTES = 24
_MAX_LIMIT = 500
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'"
)

Handler = Callable[[Request], Awaitable[Response]]


def viewer_dir() -> Path:
    """Folder with the built viewer (index.html and assets/)."""
    return Path(str(resources.files("appsec_mcp") / "viewer_dist"))


class _SecurityMiddleware(BaseHTTPMiddleware):
    """Adds security headers everywhere and requires the token on /api/."""

    def __init__(self, app: object, token: str) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._token = token

    async def dispatch(self, request: Request, call_next: Handler) -> Response:  # type: ignore[override]
        """Reject API calls without the right token; set headers on every response."""
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(supplied, self._token):
                response: Response = JSONResponse({"error": "unauthorized"}, status_code=401)
                return _harden(response)
        return _harden(await call_next(request))


def _harden(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def _int_param(request: Request, name: str, default: int, minimum: int, maximum: int) -> int:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    value = int(raw)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _json(model: BaseModel) -> JSONResponse:
    return JSONResponse(model.model_dump(mode="json"))


def _handle(fn: Callable[[Request], BaseModel]) -> Handler:
    async def endpoint(request: Request) -> Response:
        try:
            return _json(fn(request))
        except NotFoundError as exc:
            return JSONResponse({"error": exc.code, "message": exc.message}, status_code=404)
        except AppSecError as exc:
            return JSONResponse({"error": exc.code, "message": exc.message}, status_code=400)
        except (ValueError, ValidationError) as exc:
            return JSONResponse({"error": "INVALID_ARGUMENT", "message": str(exc)}, status_code=422)

    return endpoint


def create_app(ctx: AppContext, token: str, static_dir: Path | None = None) -> Starlette:
    """Build the Starlette app. `static_dir` defaults to the packaged viewer."""
    q = ctx.queries

    def scan_id(request: Request) -> int:
        value = int(request.path_params["scan_id"])
        if value < 1:
            raise ValueError("scan id must be positive")
        return value

    def findings(request: Request) -> BaseModel:
        severity = request.query_params.get("min_severity", "info")
        if severity not in SEVERITY_RANK:
            raise ValueError("min_severity is not a valid severity")
        return q.findings(
            scan_id(request),
            severity,
            _int_param(request, "limit", 100, 1, _MAX_LIMIT),
            _int_param(request, "offset", 0, 0, 10_000_000),
            request.query_params.get("include_fixed") == "true",
        )

    def ledger(request: Request) -> BaseModel:
        section = request.query_params.get("section", "all")
        if section not in ("files", "rules", "all"):
            raise ValueError("section must be files, rules or all")
        return q.ledger(
            scan_id(request),
            section,
            _int_param(request, "limit", 200, 1, _MAX_LIMIT),
            _int_param(request, "offset", 0, 0, 10_000_000),
        )

    routes = [
        Route(
            "/api/scans",
            _handle(lambda r: q.list_scans(None, _int_param(r, "limit", 50, 1, _MAX_LIMIT))),
        ),
        Route("/api/scans/{scan_id:int}", _handle(lambda r: q.scan_summary(scan_id(r)))),
        Route("/api/scans/{scan_id:int}/findings", _handle(findings)),
        Route(
            "/api/findings/{finding_id:int}",
            _handle(lambda r: q.explain(int(r.path_params["finding_id"]))),
        ),
        Route("/api/scans/{scan_id:int}/map", _handle(lambda r: q.graph(scan_id(r)))),
        Route("/api/scans/{scan_id:int}/ledger", _handle(ledger)),
    ]
    static = static_dir or viewer_dir()
    if static.is_dir():
        routes.append(Mount("/", StaticFiles(directory=static, html=True), name="viewer"))
    else:
        logger.warning("Viewer assets not found at %s; only the API is served", static)
    return Starlette(routes=routes, middleware=[Middleware(_SecurityMiddleware, token=token)])


def serve_viewer(ctx: AppContext, port: int = 0, open_browser: bool = True) -> None:
    """Run the viewer on 127.0.0.1 until interrupted, printing its URL with the token."""
    import socket

    import uvicorn

    token = secrets.token_urlsafe(_TOKEN_BYTES)
    app = create_app(ctx, token)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LOCALHOST, port))
    actual_port = sock.getsockname()[1]
    url = f"http://{LOCALHOST}:{actual_port}/#token={token}"
    print(f"AppSec viewer: {url}\nPress Ctrl+C to stop.", flush=True)
    if open_browser:
        webbrowser.open(url)
    config = uvicorn.Config(app, log_level="warning")
    uvicorn.Server(config).run(sockets=[sock])
