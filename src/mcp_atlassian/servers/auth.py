"""Browser-based OAuth endpoints for Central Auth (Phase 1).

Handlers are intentionally thin:

1. Parse and validate HTTP-layer parameters.
2. Delegate business logic to ``CentralAuthService``.
3. Return an appropriate Starlette ``Response`` type.

The base path is configurable (default: ``/auth``) so that reverse-proxies can
mount the application under arbitrary prefixes.

SECURITY NOTE
-------------
• No raw secrets (state, code verifiers, access / refresh tokens, client
  secrets) are ever logged.
• Correlation IDs, if present in ``request.state.correlation_id``, are included
  in INFO logs to aid troubleshooting.

This module is HTTP-only and MUST remain free from heavy business logic.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, RedirectResponse

from mcp_atlassian.central_auth.service import CentralAuthService
from mcp_atlassian.utils.logging import mask_sensitive

if TYPE_CHECKING:  # pragma: no cover
    from mcp_atlassian.servers.main import AtlassianMCP  # circular – only for typing

_LOG = logging.getLogger("mcp-atlassian.auth.routes")


def _html_page(title: str, body: str, status: int = 200) -> HTMLResponse:
    """Return a tiny success / error HTML page."""
    content = (
        "<!doctype html><html lang='en'>"
        "<head><meta charset='utf-8'><title>"
        f"{title}</title></head><body><h1>{title}</h1><p>{body}</p></body></html>"
    )
    return HTMLResponse(content, status_code=status)


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #
def register_auth_routes(app: "AtlassianMCP", *, base_path: str = "/auth") -> None:
    """Attach the OAuth endpoints to *app* under *base_path*."""
    svc = CentralAuthService()

    # ----- GET /auth/link/new --------------------------------------------- #
    @app.custom_route(f"{base_path}/link/new", methods=["GET"])
    async def _new_link(request: Request) -> Response:  # noqa: D401
        link_code = svc.create_link_code()
        _LOG.info(
            "Generated new link_code=%s correlation_id=%s",
            mask_sensitive(link_code, 4),
            getattr(request.state, "correlation_id", "-"),
        )
        return JSONResponse({"link_code": link_code})

    # ----- GET /auth/{jira|confluence}/start ------------------------------ #
    @app.custom_route(f"{base_path}/{{product}}/start", methods=["GET"])
    async def _start_oauth(request: Request) -> Response:  # noqa: D401
        product: Literal["jira", "confluence"] = request.path_params["product"]
        instance = request.query_params.get("instance", "default")
        link_code: str | None = request.query_params.get("link_code")
        redirect_uri = request.query_params.get("redirect_uri")

        if not redirect_uri:
            return JSONResponse({"error": "missing redirect_uri"}, status_code=400)

        try:
            authorize_url = svc.build_authorize_url(
                product=product,
                instance_id=instance,
                redirect_uri=redirect_uri,
                link_code=link_code,
            )
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        _LOG.info(
            "OAuth start product=%s instance=%s correlation_id=%s",
            product,
            instance,
            getattr(request.state, "correlation_id", "-"),
        )

        # ------------------------------------------------------------------
        # Content negotiation + explicit override for browser vs API clients
        # ------------------------------------------------------------------
        fmt_param = request.query_params.get("format")
        accept_header = (request.headers.get("accept") or "").lower()

        def _json_resp() -> JSONResponse:
            return JSONResponse({"authorize_url": authorize_url})

        def _redirect_resp() -> RedirectResponse:
            # Use 303 See Other for GET safety across methods
            return RedirectResponse(authorize_url, status_code=303)

        if fmt_param == "json":
            return _json_resp()
        if fmt_param == "redirect":
            return _redirect_resp()

        if "text/html" in accept_header:
            return _redirect_resp()

        return _json_resp()

    # ----- GET /auth/{jira|confluence}/callback --------------------------- #
    @app.custom_route(
        f"{base_path}/{{product}}/callback", methods=["GET"]
    )
    async def _oauth_callback(request: Request) -> Response:  # noqa: D401
        product: Literal["jira", "confluence"] = request.path_params["product"]
        # Check for provider-side errors first (e.g., invalid_scope, access_denied)
        oauth_error = request.query_params.get("error")
        if oauth_error:
            description = request.query_params.get("error_description", "")
            return _html_page(
                "Authorization error",
                f"{oauth_error}: {description}" if description else oauth_error,
                400,
            )

        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if not code or not state:
            return _html_page("Missing parameters", "code or state missing", 400)

        try:
            svc.exchange_code(product=product, code=code, state=state)
        except Exception as exc:  # broad: mapped to user-visible failure
            _LOG.warning("OAuth callback error: %s", exc, exc_info=True)
            return _html_page("Authorization failed", str(exc), 400)

        _LOG.info(
            "OAuth success product=%s correlation_id=%s",
            product,
            getattr(request.state, "correlation_id", "-"),
        )
        return _html_page("Authorization successful", "You may close this window.")

    # ----- GET /auth/status ---------------------------------------------- #
    @app.custom_route(f"{base_path}/status", methods=["GET"])
    async def _status(request: Request) -> Response:  # noqa: D401
        instance = request.query_params.get("instance", "default")
        status = svc.get_binding_status(instance_id=instance)
        return JSONResponse(status)

    # ----- POST /auth/{jira|confluence}/disconnect ------------------------ #
    @app.custom_route(
        f"{base_path}/{{product}}/disconnect", methods=["POST"]
    )
    async def _disconnect(request: Request) -> Response:  # noqa: D401
        product: Literal["jira", "confluence"] = request.path_params["product"]
        payload: dict[str, Any] = await request.json()
        instance = payload.get("instance", "default")

        svc.disconnect(product=product, instance_id=instance)
        _LOG.info(
            "Disconnected product=%s instance=%s correlation_id=%s",
            product,
            instance,
            getattr(request.state, "correlation_id", "-"),
        )
        return Response(status_code=204)
