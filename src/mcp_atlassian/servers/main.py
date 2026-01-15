"""Main FastMCP server setup for Atlassian integration."""

import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

from cachetools import TTLCache
from fastmcp import FastMCP
from fastmcp.tools import Tool as FastMCPTool
from mcp.types import Tool as MCPTool
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_atlassian.confluence import ConfluenceFetcher
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.environment import get_available_services
from mcp_atlassian.utils.io import is_read_only_mode
from mcp_atlassian.utils.logging import mask_sensitive
from mcp_atlassian.utils.tools import get_enabled_tools, should_include_tool

from .confluence import confluence_mcp
from .context import MainAppContext
from .jira import jira_mcp

logger = logging.getLogger("mcp-atlassian.server.main")


async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@asynccontextmanager
async def main_lifespan(app: FastMCP[MainAppContext]) -> AsyncIterator[dict]:
    logger.info("Main Atlassian MCP server lifespan starting...")
    services = get_available_services()
    read_only = is_read_only_mode()
    enabled_tools = get_enabled_tools()

    # Detect client-auth mode via environment flags
    confluence_client_auth = (
        str(os.getenv("CONFLUENCE_CLIENT_AUTH", "")).strip().lower()
        in ("true", "1", "yes", "y", "on")
    )
    jira_client_auth = (
        str(os.getenv("JIRA_CLIENT_AUTH", "")).strip().lower()
        in ("true", "1", "yes", "y", "on")
    )

    loaded_jira_config: JiraConfig | None = None
    loaded_confluence_config: ConfluenceConfig | None = None
    jira_auth_ok = False
    confluence_auth_ok = False

    if services.get("jira"):
        try:
            jira_config = JiraConfig.from_env()
            jira_auth_ok = jira_config.is_auth_configured()
            if jira_auth_ok or jira_client_auth:
                loaded_jira_config = jira_config
                if jira_auth_ok:
                    logger.info(
                        "Jira configuration loaded and authentication is configured."
                    )
                else:
                    logger.info(
                        "Jira base configuration loaded; expecting auth via X-Jira-Authorization per request"
                    )
            else:
                logger.warning(
                    "Jira URL found, but authentication is not fully configured. Jira tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Jira configuration: {e}", exc_info=True)

    if services.get("confluence"):
        try:
            confluence_config = ConfluenceConfig.from_env()
            confluence_auth_ok = confluence_config.is_auth_configured()
            if confluence_auth_ok or confluence_client_auth:
                loaded_confluence_config = confluence_config
                if confluence_auth_ok:
                    logger.info(
                        "Confluence configuration loaded and authentication is configured."
                    )
                else:
                    logger.info(
                        "Confluence base configuration loaded; expecting auth via X-Confluence-Authorization per request"
                    )
            else:
                logger.warning(
                    "Confluence URL found, but authentication is not fully configured. Confluence tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Confluence configuration: {e}", exc_info=True)

    app_context = MainAppContext(
        full_jira_config=loaded_jira_config,
        full_confluence_config=loaded_confluence_config,
        read_only=read_only,
        enabled_tools=enabled_tools,
        confluence_client_auth=confluence_client_auth,
        jira_client_auth=jira_client_auth,
        confluence_auth_configured=confluence_auth_ok,
        jira_auth_configured=jira_auth_ok,
    )
    logger.info(f"Read-only mode: {'ENABLED' if read_only else 'DISABLED'}")
    logger.info(f"Enabled tools filter: {enabled_tools or 'All tools enabled'}")

    try:
        yield {"app_lifespan_context": app_context}
    except Exception as e:
        logger.error(f"Error during lifespan: {e}", exc_info=True)
        raise
    finally:
        logger.info("Main Atlassian MCP server lifespan shutting down...")
        # Perform any necessary cleanup here
        try:
            # Close any open connections if needed
            if loaded_jira_config:
                logger.debug("Cleaning up Jira resources...")
            if loaded_confluence_config:
                logger.debug("Cleaning up Confluence resources...")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
        logger.info("Main Atlassian MCP server lifespan shutdown complete.")


class AtlassianMCP(FastMCP[MainAppContext]):
    """Custom FastMCP server class for Atlassian integration with tool filtering."""

    async def _list_tools_mcp(self) -> list[MCPTool]:
        # Filter tools based on enabled_tools, read_only mode, and service configuration from the lifespan context.
        req_context = self._mcp_server.request_context
        if req_context is None or req_context.lifespan_context is None:
            logger.warning(
                "Lifespan context not available during _list_tools_mcp call."
            )
            return []

        lifespan_ctx_dict = req_context.lifespan_context
        app_lifespan_state: MainAppContext | None = (
            lifespan_ctx_dict.get("app_lifespan_context")
            if isinstance(lifespan_ctx_dict, dict)
            else None
        )
        read_only = (
            getattr(app_lifespan_state, "read_only", False)
            if app_lifespan_state
            else False
        )
        enabled_tools_filter = (
            getattr(app_lifespan_state, "enabled_tools", None)
            if app_lifespan_state
            else None
        )
        logger.debug(
            f"_list_tools_mcp: read_only={read_only}, enabled_tools_filter={enabled_tools_filter}"
        )

        # Expose tools even when service authentication/configuration is incomplete
        # unless the operator explicitly disables this behaviour.
        skip_auth_filter = (
            str(os.getenv("MCP_EXPOSE_TOOLS_WITHOUT_AUTH", "true"))
            .strip()
            .lower()
            in ("true", "1", "yes", "y", "on")
        )

        all_tools: dict[str, FastMCPTool] = await self.get_tools()
        logger.debug(
            f"Aggregated {len(all_tools)} tools before filtering: {list(all_tools.keys())}"
        )

        filtered_tools: list[MCPTool] = []
        for registered_name, tool_obj in all_tools.items():
            tool_tags = tool_obj.tags

            if not should_include_tool(registered_name, enabled_tools_filter):
                logger.debug(f"Excluding tool '{registered_name}' (not enabled)")
                continue

            if tool_obj and read_only and "write" in tool_tags:
                logger.debug(
                    f"Excluding tool '{registered_name}' due to read-only mode and 'write' tag"
                )
                continue

            # Exclude Jira/Confluence tools if config is not fully authenticated
            is_jira_tool = "jira" in tool_tags
            is_confluence_tool = "confluence" in tool_tags
            service_configured_and_available = True
            if app_lifespan_state:
                if is_jira_tool and not app_lifespan_state.full_jira_config:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}' as Jira configuration/authentication is incomplete."
                    )
                    service_configured_and_available = False
                if is_confluence_tool and not app_lifespan_state.full_confluence_config:
                    logger.debug(
                        f"Excluding Confluence tool '{registered_name}' as Confluence configuration/authentication is incomplete."
                    )
                    service_configured_and_available = False
            elif is_jira_tool or is_confluence_tool:
                logger.warning(
                    f"Excluding tool '{registered_name}' as application context is unavailable to verify service configuration."
                )
                service_configured_and_available = False

            if skip_auth_filter:
                # Override auth-based exclusion – allow schema discovery while
                # logging a debug note to inform operators.
                if not service_configured_and_available:
                    logger.debug(
                        f"Including tool '{registered_name}' despite incomplete "
                        "service configuration (MCP_EXPOSE_TOOLS_WITHOUT_AUTH)."
                    )
                service_configured_and_available = True

            if not service_configured_and_available:
                continue

            filtered_tools.append(tool_obj.to_mcp_tool(name=registered_name))

        logger.debug(
            f"_list_tools_mcp: Total tools after filtering: {len(filtered_tools)}"
        )
        return filtered_tools

    def http_app(
        self,
        path: str | None = None,
        middleware: list[Middleware] | None = None,
        transport: Literal["streamable-http", "sse"] = "streamable-http",
        **kwargs: Any,
    ) -> "Starlette":
        user_token_mw = Middleware(UserTokenMiddleware, mcp_server_ref=self)
        final_middleware_list = [user_token_mw]
        if middleware:
            final_middleware_list.extend(middleware)
        app = super().http_app(
            path=path, middleware=final_middleware_list, transport=transport, **kwargs
        )
        return app


token_validation_cache: TTLCache[
    int, tuple[bool, str | None, JiraFetcher | None, ConfluenceFetcher | None]
] = TTLCache(maxsize=100, ttl=300)


class UserTokenMiddleware:
    """ASGI-compliant middleware to extract Atlassian user tokens/credentials.

    Based on PR #700 by @isaacpalomero - fixes ASGI protocol violations that caused
    server crashes when MCP clients disconnect during HTTP requests.
    """

    def __init__(
        self, app: ASGIApp, mcp_server_ref: Optional["AtlassianMCP"] = None
    ) -> None:
        self.app = app
        self.mcp_server_ref = mcp_server_ref
        if not self.mcp_server_ref:
            logger.warning(
                "UserTokenMiddleware initialized without mcp_server_ref. "
                "Path matching for MCP endpoint might fail if settings are needed."
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Pass through non-HTTP requests directly per ASGI spec
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # According to ASGI spec, middleware should copy scope when modifying it
        scope_copy: Scope = dict(scope)

        # Ensure state exists in scope - this is where Starlette stores request state
        if "state" not in scope_copy:
            scope_copy["state"] = {}

        # Initialize default authentication state (legacy + per-product)
        default_state = {
            "user_atlassian_token": None,
            "user_atlassian_auth_type": None,
            "user_atlassian_email": None,
            "user_atlassian_cloud_id": None,
            # Per-product (new)
            "user_jira_token": None,
            "user_jira_auth_type": None,
            "user_jira_cloud_id": None,
            "user_confluence_token": None,
            "user_confluence_auth_type": None,
            "user_confluence_cloud_id": None,
            # Error holder
            "auth_validation_error": None,
        }
        scope_copy["state"].update(default_state)

        logger.debug(
            f"UserTokenMiddleware: Processing {scope_copy.get('method', 'UNKNOWN')} "
            f"{scope_copy.get('path', 'UNKNOWN')}"
        )

        # Only process authentication for our MCP endpoint
        if self.mcp_server_ref and self._should_process_auth(scope_copy):
            self._process_authentication_headers(scope_copy)

        # Create wrapped send function to handle client disconnections gracefully
        async def safe_send(message: Message) -> None:
            try:
                await send(message)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                # Client disconnected - log but don't propagate to avoid ASGI violations
                logger.debug(
                    f"Client disconnected during response: {type(e).__name__}: {e}"
                )
                # Don't re-raise - this prevents the ASGI protocol violation
                return
            except Exception:
                # Re-raise unexpected errors
                raise

        # Check for auth errors and return 401 before calling app
        auth_error = scope_copy["state"].get("auth_validation_error")
        if auth_error:
            logger.warning(f"Authentication failed: {auth_error}")
            await self._send_json_error_response(safe_send, 401, auth_error)
            return  # Don't call self.app - request is rejected

        # Call the next application with modified scope and safe send wrapper
        await self.app(scope_copy, receive, safe_send)

    async def _send_json_error_response(
        self, send: Send, status_code: int, error_message: str
    ) -> None:
        """Send a JSON error response via ASGI protocol.

        Args:
            send: ASGI send callable (should be safe_send wrapper).
            status_code: HTTP status code (e.g., 401).
            error_message: Error message to include in JSON body.
        """
        body = json.dumps({"error": error_message}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    def _should_process_auth(self, scope: Scope) -> bool:
        """Check if this request should be processed for authentication."""
        if not self.mcp_server_ref or scope.get("method") != "POST":
            return False

        try:
            mcp_path = self.mcp_server_ref.settings.streamable_http_path.rstrip("/")
            request_path = scope.get("path", "").rstrip("/")
            return request_path == mcp_path
        except (AttributeError, ValueError) as e:
            logger.warning(f"Error checking auth path: {e}")
            return False

    def _process_authentication_headers(self, scope: Scope) -> None:
        """Process authentication headers (legacy + per-product) and populate scope state."""
        try:
            headers_bytes = dict(scope.get("headers", []))

            def _h(name: bytes) -> str | None:
                val = headers_bytes.get(name)
                return val.decode("latin-1") if val else None

            # Raw header strings
            legacy_auth = _h(b"authorization")
            legacy_cloud = _h(b"x-atlassian-cloud-id")

            jira_auth = _h(b"x-jira-authorization")
            conf_auth = _h(b"x-confluence-authorization")

            jira_cloud = _h(b"x-jira-cloud-id")
            conf_cloud = _h(b"x-confluence-cloud-id")

            # Optional debug aid (safe, contains no secrets)
            mcp_session_id = _h(b"mcp-session-id")
            if mcp_session_id:
                logger.debug(
                    "UserTokenMiddleware: MCP-Session-ID header found: %s",
                    mcp_session_id,
                )

            logger.debug(
                "UserTokenMiddleware: Auth presence (legacy=%s, jira=%s, confluence=%s), "
                "CloudId presence (legacy=%s, jira=%s, confluence=%s)",
                bool(legacy_auth),
                bool(jira_auth),
                bool(conf_auth),
                bool(legacy_cloud),
                bool(jira_cloud),
                bool(conf_cloud),
            )

            # Helper to parse header value
            def _parse(header_val: str) -> tuple[str | None, str | None, str | None]:
                """Return (token, auth_type, error_msg)."""
                if not header_val.strip():
                    return None, None, "Unauthorized: Empty Authorization header"
                if header_val.startswith("Bearer "):
                    token = header_val[7:].strip()
                    if not token:
                        return None, None, "Unauthorized: Empty Bearer token"
                    return token, "oauth", None
                if header_val.startswith("Token "):
                    token = header_val[6:].strip()
                    if not token:
                        return None, None, "Unauthorized: Empty Token (PAT)"
                    return token, "pat", None
                # Unsupported scheme
                scheme = header_val.split(" ", 1)[0] if header_val.strip() else ""
                if scheme:
                    logger.warning("Unsupported Authorization type: %s", scheme)
                return None, None, (
                    "Unauthorized: Only 'Bearer <OAuthToken>' or "
                    "'Token <PAT>' types are supported."
                )

            # Parse individual auth headers
            legacy_tok, legacy_type, legacy_err = (
                _parse(legacy_auth) if legacy_auth else (None, None, None)
            )
            jira_tok, jira_type, jira_err = (
                _parse(jira_auth) if jira_auth else (None, None, None)
            )
            conf_tok, conf_type, conf_err = (
                _parse(conf_auth) if conf_auth else (None, None, None)
            )

            # Fail fast on first parsing error
            for err in (legacy_err, jira_err, conf_err):
                if err:
                    scope["state"]["auth_validation_error"] = err
                    return

            # Store per-product values
            scope["state"]["user_jira_token"] = jira_tok
            scope["state"]["user_jira_auth_type"] = jira_type
            scope["state"]["user_confluence_token"] = conf_tok
            scope["state"]["user_confluence_auth_type"] = conf_type

            scope["state"]["user_jira_cloud_id"] = jira_cloud.strip() if jira_cloud else None
            scope["state"]["user_confluence_cloud_id"] = (
                conf_cloud.strip() if conf_cloud else None
            )

            # Legacy token mirroring (precedence rules)
            if legacy_tok:
                # Rule 1
                scope["state"]["user_atlassian_token"] = legacy_tok
                scope["state"]["user_atlassian_auth_type"] = legacy_type
            else:
                # Rule 2
                if (
                    jira_tok
                    and conf_tok
                    and jira_tok == conf_tok
                    and jira_type == conf_type
                ):
                    scope["state"]["user_atlassian_token"] = jira_tok
                    scope["state"]["user_atlassian_auth_type"] = jira_type
                elif jira_tok:
                    scope["state"]["user_atlassian_token"] = jira_tok
                    scope["state"]["user_atlassian_auth_type"] = jira_type
                elif conf_tok:
                    scope["state"]["user_atlassian_token"] = conf_tok
                    scope["state"]["user_atlassian_auth_type"] = conf_type

            # Legacy cloudId mirroring (precedence rules)
            if legacy_cloud:
                scope["state"]["user_atlassian_cloud_id"] = legacy_cloud.strip()
            elif jira_cloud:
                scope["state"]["user_atlassian_cloud_id"] = jira_cloud.strip()
            elif conf_cloud:
                scope["state"]["user_atlassian_cloud_id"] = conf_cloud.strip()

            # Fallback per-product with legacy if still missing
            if not jira_tok and legacy_tok:
                scope["state"]["user_jira_token"] = legacy_tok
                scope["state"]["user_jira_auth_type"] = legacy_type
            if not conf_tok and legacy_tok:
                scope["state"]["user_confluence_token"] = legacy_tok
                scope["state"]["user_confluence_auth_type"] = legacy_type

            # Fallback cloud ids
            if not scope["state"]["user_jira_cloud_id"] and legacy_cloud:
                scope["state"]["user_jira_cloud_id"] = legacy_cloud.strip()
            if not scope["state"]["user_confluence_cloud_id"] and legacy_cloud:
                scope["state"]["user_confluence_cloud_id"] = legacy_cloud.strip()

            # Masked debug logs for extracted tokens
            if jira_tok:
                logger.debug(
                    "UserTokenMiddleware: Jira token extracted (masked): ...%s",
                    mask_sensitive(jira_tok, 8),
                )
            if conf_tok and conf_tok != jira_tok:
                logger.debug(
                    "UserTokenMiddleware: Confluence token extracted (masked): ...%s",
                    mask_sensitive(conf_tok, 8),
                )
            if legacy_tok and legacy_tok not in (jira_tok, conf_tok):
                logger.debug(
                    "UserTokenMiddleware: Legacy token extracted (masked): ...%s",
                    mask_sensitive(legacy_tok, 8),
                )

        except Exception as e:
            logger.error(
                "Error processing authentication headers: %s", e, exc_info=True
            )
            scope["state"]["auth_validation_error"] = "Authentication processing error"

    def _parse_auth_header(self, auth_header: str, scope: Scope) -> None:
        """Parse the Authorization header and store credentials in scope state."""
        # Check prefix BEFORE stripping to preserve "Bearer " / "Token " matching
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()  # Remove "Bearer " prefix and strip token
            if not token:
                scope["state"]["auth_validation_error"] = (
                    "Unauthorized: Empty Bearer token"
                )
            else:
                scope["state"]["user_atlassian_token"] = token
                scope["state"]["user_atlassian_auth_type"] = "oauth"
                logger.debug(
                    "UserTokenMiddleware: Bearer token extracted (masked): "
                    f"...{mask_sensitive(token, 8)}"
                )

        elif auth_header.startswith("Token "):
            token = auth_header[6:].strip()  # Remove "Token " prefix and strip token
            if not token:
                scope["state"]["auth_validation_error"] = (
                    "Unauthorized: Empty Token (PAT)"
                )
            else:
                scope["state"]["user_atlassian_token"] = token
                scope["state"]["user_atlassian_auth_type"] = "pat"
                logger.debug(
                    "UserTokenMiddleware: PAT token extracted (masked): "
                    f"...{mask_sensitive(token, 8)}"
                )

        elif auth_header.strip():
            # Non-empty but unsupported auth type
            auth_value = auth_header.strip()
            auth_type = auth_value.split(" ", 1)[0] if " " in auth_value else auth_value
            logger.warning(f"Unsupported Authorization type: {auth_type}")
            scope["state"]["auth_validation_error"] = (
                "Unauthorized: Only 'Bearer <OAuthToken>' or "
                "'Token <PAT>' types are supported."
            )
        else:
            # Empty or whitespace-only
            scope["state"]["auth_validation_error"] = (
                "Unauthorized: Empty Authorization header"
            )


main_mcp = AtlassianMCP(name="Atlassian MCP", lifespan=main_lifespan)
main_mcp.mount(jira_mcp, prefix="jira")
main_mcp.mount(confluence_mcp, prefix="confluence")


@main_mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def _health_check_route(request: Request) -> JSONResponse:
    return await health_check(request)


logger.info("Added /healthz endpoint for Kubernetes probes")
