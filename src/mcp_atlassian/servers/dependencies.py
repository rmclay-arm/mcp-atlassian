"""Dependency providers for JiraFetcher and ConfluenceFetcher with context awareness.

Provides get_jira_fetcher and get_confluence_fetcher for use in tool functions.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import hashlib
from typing import TYPE_CHECKING, Any, Literal

from fastmcp import Context
from fastmcp.server.dependencies import get_http_request
from starlette.requests import Request

from mcp_atlassian.confluence import ConfluenceConfig, ConfluenceFetcher
from mcp_atlassian.jira import JiraConfig, JiraFetcher
from mcp_atlassian.servers.context import MainAppContext
from mcp_atlassian.utils.oauth import OAuthConfig
from mcp_atlassian.central_auth.store import default_store
from mcp_atlassian.central_auth.errors import NeedsReauthError

if TYPE_CHECKING:
    from mcp_atlassian.confluence.config import (
        ConfluenceConfig as UserConfluenceConfigType,
    )
    from mcp_atlassian.jira.config import JiraConfig as UserJiraConfigType

logger = logging.getLogger("mcp-atlassian.servers.dependencies")

# --------------------------------------------------------------------------- #
# Binding header helpers (Phase 1)
# --------------------------------------------------------------------------- #

_BINDING_HEADER_NAME: str = os.getenv("MCP_LINK_CODE_HEADER", "X-MCP-Link-Code")


def _binding_id_from_code(link_code: str) -> str:
    """Derive a stable, filesystem-safe binding_id from the raw link_code."""
    return hashlib.sha256(link_code.encode("utf-8")).hexdigest()[:12]


def _create_user_config_for_fetcher(
    base_config: JiraConfig | ConfluenceConfig,
    auth_type: str,
    credentials: dict[str, Any],
    cloud_id: str | None = None,
) -> JiraConfig | ConfluenceConfig:
    """Create a user-specific configuration for Jira or Confluence fetchers.

    Args:
        base_config: The base JiraConfig or ConfluenceConfig to clone and modify.
        auth_type: The authentication type ('oauth' or 'pat').
        credentials: Dictionary of credentials (token, email, etc).
        cloud_id: Optional cloud ID to override the base config cloud ID.

    Returns:
        JiraConfig or ConfluenceConfig with user-specific credentials.

    Raises:
        ValueError: If required credentials are missing or auth_type is unsupported.
        TypeError: If base_config is not a supported type.
    """
    if auth_type not in ["oauth", "pat"]:
        raise ValueError(
            f"Unsupported auth_type '{auth_type}' for user-specific config creation. Expected 'oauth' or 'pat'."
        )

    username_for_config: str | None = credentials.get("user_email_context")

    logger.debug(
        f"Creating user config for fetcher. Auth type: {auth_type}, Credentials keys: {credentials.keys()}, Cloud ID: {cloud_id}"
    )

    common_args: dict[str, Any] = {
        "url": base_config.url,
        "auth_type": auth_type,
        "ssl_verify": base_config.ssl_verify,
        "http_proxy": base_config.http_proxy,
        "https_proxy": base_config.https_proxy,
        "no_proxy": base_config.no_proxy,
        "socks_proxy": base_config.socks_proxy,
    }

    if auth_type == "oauth":
        user_access_token = credentials.get("oauth_access_token")
        if not user_access_token:
            raise ValueError(
                "OAuth access token missing in credentials for user auth_type 'oauth'"
            )
        if (
            not base_config
            or not hasattr(base_config, "oauth_config")
            or not getattr(base_config, "oauth_config", None)
        ):
            raise ValueError(
                f"Global OAuth config for {type(base_config).__name__} is missing, "
                "but user auth_type is 'oauth'."
            )
        global_oauth_cfg = base_config.oauth_config

        # Use provided cloud_id or fall back to global config cloud_id
        # Determine effective site identification depending on instance type
        if global_oauth_cfg.is_cloud:
            effective_cloud_id = cloud_id if cloud_id else global_oauth_cfg.cloud_id
            if not effective_cloud_id:
                raise ValueError(
                    "Cloud ID is required for Atlassian Cloud OAuth authentication. "
                    "Provide it via X-Atlassian-Cloud-Id header or configure it globally."
                )
        else:  # Data Center – cloud_id not applicable
            effective_cloud_id = None

        # For minimal OAuth config (user-provided tokens), use empty strings for client credentials
        oauth_config_for_user = OAuthConfig(
            client_id=global_oauth_cfg.client_id or "",
            client_secret=global_oauth_cfg.client_secret or "",
            redirect_uri=global_oauth_cfg.redirect_uri or "",
            scope=global_oauth_cfg.scope or "",
            access_token=user_access_token,
            refresh_token=None,
            expires_at=None,
            cloud_id=effective_cloud_id,
            instance_type=global_oauth_cfg.instance_type,
            instance_url=global_oauth_cfg.instance_url,
        )
        common_args.update(
            {
                "username": username_for_config,
                "api_token": None,
                "personal_token": None,
                "oauth_config": oauth_config_for_user,
            }
        )
    elif auth_type == "pat":
        user_pat = credentials.get("personal_access_token")
        if not user_pat:
            raise ValueError("PAT missing in credentials for user auth_type 'pat'")

        # Log warning if cloud_id is provided with PAT auth (not typically needed)
        if cloud_id:
            logger.warning(
                f"Cloud ID '{cloud_id}' provided with PAT authentication. "
                "PAT authentication typically uses the base URL directly and doesn't require cloud_id override."
            )

        common_args.update(
            {
                "personal_token": user_pat,
                "oauth_config": None,
                "username": None,
                "api_token": None,
            }
        )

    if isinstance(base_config, JiraConfig):
        user_jira_config: UserJiraConfigType = dataclasses.replace(
            base_config, **common_args
        )
        user_jira_config.projects_filter = base_config.projects_filter
        return user_jira_config
    elif isinstance(base_config, ConfluenceConfig):
        user_confluence_config: UserConfluenceConfigType = dataclasses.replace(
            base_config, **common_args
        )
        user_confluence_config.spaces_filter = base_config.spaces_filter
        return user_confluence_config
    else:
        raise TypeError(f"Unsupported base_config type: {type(base_config)}")


def _select_request_credentials(
    request: Request, service: Literal["jira", "confluence"]
) -> tuple[str | None, Any, Any, Any]:
    """Select credentials for the requested Atlassian product.

    This helper chooses between per-product request.state keys and the legacy
    generic `user_atlassian_*` keys **without** altering legacy semantics.

    Selection rules:
      • If *any* per-product key is present on request.state, those per-product
        values are returned (even if they are empty strings / None).
      • Otherwise, the legacy generic values are returned.
    The function makes no “truthy” checks – presence of an attribute decides.
    It returns a tuple: (auth_type, token, cloud_id, email).
    """
    if service == "jira":
        per_product_keys = (
            "user_jira_auth_type",
            "user_jira_token",
            "user_jira_cloud_id",
        )
        if any(k in vars(request.state) for k in per_product_keys):
            return (
                getattr(request.state, "user_jira_auth_type", None),
                getattr(request.state, "user_jira_token", None),
                getattr(request.state, "user_jira_cloud_id", None),
                getattr(request.state, "user_jira_email", None),
            )
        return (
            getattr(request.state, "user_atlassian_auth_type", None),
            getattr(request.state, "user_atlassian_token", None),
            getattr(request.state, "user_atlassian_cloud_id", None),
            getattr(request.state, "user_atlassian_email", None),
        )
    elif service == "confluence":
        per_product_keys = (
            "user_confluence_auth_type",
            "user_confluence_token",
            "user_confluence_cloud_id",
        )
        if any(k in vars(request.state) for k in per_product_keys):
            return (
                getattr(request.state, "user_confluence_auth_type", None),
                getattr(request.state, "user_confluence_token", None),
                getattr(request.state, "user_confluence_cloud_id", None),
                getattr(request.state, "user_confluence_email", None),
            )
        return (
            getattr(request.state, "user_atlassian_auth_type", None),
            getattr(request.state, "user_atlassian_token", None),
            getattr(request.state, "user_atlassian_cloud_id", None),
            getattr(request.state, "user_atlassian_email", None),
        )
    else:  # pragma: no cover – Literal guards callers
        raise ValueError(f"Unsupported service '{service}' passed to selector")


async def get_jira_fetcher(ctx: Context) -> JiraFetcher:
    """Returns a JiraFetcher instance appropriate for the current request context.

    Args:
        ctx: The FastMCP context.

    Returns:
        JiraFetcher instance for the current user or global config.

    Raises:
        ValueError: If configuration or credentials are invalid.
    """
    logger.debug(f"get_jira_fetcher: ENTERED. Context ID: {id(ctx)}")
    try:
        request: Request = get_http_request()
        logger.debug(
            f"get_jira_fetcher: In HTTP request context. Request URL: {request.url}. "
            f"State.jira_fetcher exists: {hasattr(request.state, 'jira_fetcher') and request.state.jira_fetcher is not None}. "
            f"State.user_auth_type: {getattr(request.state, 'user_atlassian_auth_type', 'N/A')}. "
            f"State.user_token_present: {hasattr(request.state, 'user_atlassian_token') and request.state.user_atlassian_token is not None}."
        )

        # ------------------------------------------------------------------
        # Phase-1 binding header token resolution
        # ------------------------------------------------------------------
        link_code = request.headers.get(_BINDING_HEADER_NAME)
        if link_code and not getattr(request.state, "user_jira_token", None):
            binding_id = _binding_id_from_code(link_code)
            token_rec = default_store().load_tokens(binding_id, "jira", "default")
            if token_rec:
                request.state.user_jira_token = token_rec.access_token
                request.state.user_jira_auth_type = "oauth"
                request.state.user_jira_cloud_id = token_rec.cloud_id
                # Mirror into legacy generic slots for backward-compat
                request.state.user_atlassian_token = token_rec.access_token
                request.state.user_atlassian_auth_type = "oauth"
                request.state.user_atlassian_cloud_id = token_rec.cloud_id
                logger.info(
                    "Resolved Jira OAuth token via binding header for binding_id=%s",
                    binding_id,
                )
            else:
                logger.info(
                    "No Jira tokens found for binding_id=%s – re-authentication required",
                    binding_id,
                )
                raise NeedsReauthError(
                    auth_txn_id="binding-" + binding_id,
                    product="jira",
                    message="No stored tokens for provided link code",
                )
        # Use fetcher from request.state if already present
        if hasattr(request.state, "jira_fetcher") and request.state.jira_fetcher:
            logger.debug("get_jira_fetcher: Returning JiraFetcher from request.state.")
            return request.state.jira_fetcher
        selected_auth_type, selected_token, selected_cloud_id, selected_email = _select_request_credentials(
            request, "jira"
        )
        user_auth_type = selected_auth_type
        logger.debug(f"get_jira_fetcher: User auth type: {user_auth_type}")
        # Enforce client-provided authentication when configured (no global fallback)
        lifespan_ctx_dict = ctx.request_context.lifespan_context  # type: ignore
        app_lifespan_ctx: MainAppContext | None = (
            lifespan_ctx_dict.get("app_lifespan_context")
            if isinstance(lifespan_ctx_dict, dict)
            else None
        )
        if app_lifespan_ctx and app_lifespan_ctx.jira_client_auth:
            if user_auth_type not in ["oauth", "pat"] or not selected_token:
                raise ValueError(
                    "Jira is configured for client-provided authentication. "
                    "Provide X-Jira-Authorization: Token <PAT> on each request."
                )
        # If OAuth or PAT token is present, create user-specific fetcher
        if user_auth_type in ["oauth", "pat"] and selected_token is not None:
            user_token = selected_token
            user_email = selected_email  # May be None for PAT
            user_cloud_id = selected_cloud_id

            if not user_token:
                raise ValueError("User Atlassian token found in state but is empty.")
            credentials = {"user_email_context": user_email}
            if user_auth_type == "oauth":
                credentials["oauth_access_token"] = user_token
            elif user_auth_type == "pat":
                credentials["personal_access_token"] = user_token
            lifespan_ctx_dict = ctx.request_context.lifespan_context  # type: ignore
            app_lifespan_ctx: MainAppContext | None = (
                lifespan_ctx_dict.get("app_lifespan_context")
                if isinstance(lifespan_ctx_dict, dict)
                else None
            )
            if not app_lifespan_ctx or not app_lifespan_ctx.full_jira_config:
                raise ValueError(
                    "Jira global configuration (URL, SSL) is not available from lifespan context."
                )

            cloud_id_info = f" with cloudId {user_cloud_id}" if user_cloud_id else ""
            logger.info(
                f"Creating user-specific JiraFetcher (type: {user_auth_type}) for user {user_email or 'unknown'} (token ...{str(user_token)[-8:]}){cloud_id_info}"
            )
            user_specific_config = _create_user_config_for_fetcher(
                base_config=app_lifespan_ctx.full_jira_config,
                auth_type=user_auth_type,
                credentials=credentials,
                cloud_id=user_cloud_id,
            )
            try:
                user_jira_fetcher = JiraFetcher(config=user_specific_config)
                current_user_id = user_jira_fetcher.get_current_user_account_id()
                logger.debug(
                    f"get_jira_fetcher: Validated Jira token for user ID: {current_user_id}"
                )
                request.state.jira_fetcher = user_jira_fetcher
                return user_jira_fetcher
            except Exception as e:
                logger.error(
                    f"get_jira_fetcher: Failed to create/validate user-specific JiraFetcher: {e}",
                    exc_info=True,
                )
                raise ValueError(f"Invalid user Jira token or configuration: {e}")
        else:
            logger.debug(
                f"get_jira_fetcher: No user-specific JiraFetcher. Auth type: {user_auth_type}. Token present: {hasattr(request.state, 'user_atlassian_token')}. Will use global fallback."
            )
    except RuntimeError:
        logger.debug(
            "Not in an HTTP request context. Attempting global JiraFetcher for non-HTTP."
        )
    # Fallback to global fetcher if not in HTTP context or no user info
    lifespan_ctx_dict_global = ctx.request_context.lifespan_context  # type: ignore
    app_lifespan_ctx_global: MainAppContext | None = (
        lifespan_ctx_dict_global.get("app_lifespan_context")
        if isinstance(lifespan_ctx_dict_global, dict)
        else None
    )
    if app_lifespan_ctx_global and app_lifespan_ctx_global.full_jira_config:
        logger.debug(
            "get_jira_fetcher: Using global JiraFetcher from lifespan_context. "
            f"Global config auth_type: {app_lifespan_ctx_global.full_jira_config.auth_type}"
        )
        return JiraFetcher(config=app_lifespan_ctx_global.full_jira_config)
    logger.error("Jira configuration could not be resolved.")
    raise ValueError(
        "Jira client (fetcher) not available. Ensure server is configured correctly."
    )


async def get_confluence_fetcher(ctx: Context) -> ConfluenceFetcher:
    """Returns a ConfluenceFetcher instance appropriate for the current request context.

    Args:
        ctx: The FastMCP context.

    Returns:
        ConfluenceFetcher instance for the current user or global config.

    Raises:
        ValueError: If configuration or credentials are invalid.
    """
    logger.debug(f"get_confluence_fetcher: ENTERED. Context ID: {id(ctx)}")
    try:
        request: Request = get_http_request()
        logger.debug(
            f"get_confluence_fetcher: In HTTP request context. Request URL: {request.url}. "
            f"State.confluence_fetcher exists: {hasattr(request.state, 'confluence_fetcher') and request.state.confluence_fetcher is not None}. "
            f"State.user_auth_type: {getattr(request.state, 'user_atlassian_auth_type', 'N/A')}. "
            f"State.user_token_present: {hasattr(request.state, 'user_atlassian_token') and request.state.user_atlassian_token is not None}."
        )

        # ------------------------------------------------------------------
        # Phase-1 binding header token resolution
        # ------------------------------------------------------------------
        link_code = request.headers.get(_BINDING_HEADER_NAME)
        if link_code and not getattr(request.state, "user_confluence_token", None):
            binding_id = _binding_id_from_code(link_code)
            token_rec = default_store().load_tokens(binding_id, "confluence", "default")
            if token_rec:
                request.state.user_confluence_token = token_rec.access_token
                request.state.user_confluence_auth_type = "oauth"
                request.state.user_confluence_cloud_id = token_rec.cloud_id
                # Mirror into legacy generic slots for backward-compat
                request.state.user_atlassian_token = token_rec.access_token
                request.state.user_atlassian_auth_type = "oauth"
                request.state.user_atlassian_cloud_id = token_rec.cloud_id
                logger.info(
                    "Resolved Confluence OAuth token via binding header for binding_id=%s",
                    binding_id,
                )
            else:
                logger.info(
                    "No Confluence tokens found for binding_id=%s – re-authentication required",
                    binding_id,
                )
                raise NeedsReauthError(
                    auth_txn_id="binding-" + binding_id,
                    product="confluence",
                    message="No stored tokens for provided link code",
                )
        if (
            hasattr(request.state, "confluence_fetcher")
            and request.state.confluence_fetcher
        ):
            logger.debug(
                "get_confluence_fetcher: Returning ConfluenceFetcher from request.state."
            )
            return request.state.confluence_fetcher
        selected_auth_type, selected_token, selected_cloud_id, selected_email = _select_request_credentials(
            request, "confluence"
        )
        user_auth_type = selected_auth_type
        logger.debug(f"get_confluence_fetcher: User auth type: {user_auth_type}")
        # Enforce client-provided authentication when configured (no global fallback)
        lifespan_ctx_dict = ctx.request_context.lifespan_context  # type: ignore
        app_lifespan_ctx: MainAppContext | None = (
            lifespan_ctx_dict.get("app_lifespan_context")
            if isinstance(lifespan_ctx_dict, dict)
            else None
        )
        if app_lifespan_ctx and app_lifespan_ctx.confluence_client_auth:
            if user_auth_type not in ["oauth", "pat"] or not selected_token:
                raise ValueError(
                    "Confluence is configured for client-provided authentication. "
                    "Provide X-Confluence-Authorization: Token <PAT> on each request."
                )
        if user_auth_type in ["oauth", "pat"] and selected_token is not None:
            user_token = selected_token
            user_email = selected_email
            user_cloud_id = selected_cloud_id

            if not user_token:
                raise ValueError("User Atlassian token found in state but is empty.")
            credentials = {"user_email_context": user_email}
            if user_auth_type == "oauth":
                credentials["oauth_access_token"] = user_token
            elif user_auth_type == "pat":
                credentials["personal_access_token"] = user_token
            lifespan_ctx_dict = ctx.request_context.lifespan_context  # type: ignore
            app_lifespan_ctx: MainAppContext | None = (
                lifespan_ctx_dict.get("app_lifespan_context")
                if isinstance(lifespan_ctx_dict, dict)
                else None
            )
            if not app_lifespan_ctx or not app_lifespan_ctx.full_confluence_config:
                raise ValueError(
                    "Confluence global configuration (URL, SSL) is not available from lifespan context."
                )

            cloud_id_info = f" with cloudId {user_cloud_id}" if user_cloud_id else ""
            logger.info(
                f"Creating user-specific ConfluenceFetcher (type: {user_auth_type}) for user {user_email or 'unknown'} (token ...{str(user_token)[-8:]}){cloud_id_info}"
            )
            user_specific_config = _create_user_config_for_fetcher(
                base_config=app_lifespan_ctx.full_confluence_config,
                auth_type=user_auth_type,
                credentials=credentials,
                cloud_id=user_cloud_id,
            )
            try:
                user_confluence_fetcher = ConfluenceFetcher(config=user_specific_config)
                current_user_data = user_confluence_fetcher.get_current_user_info()
                # Try to get email from Confluence if not provided (can happen with PAT)
                derived_email = (
                    current_user_data.get("email")
                    if isinstance(current_user_data, dict)
                    else None
                )
                display_name = (
                    current_user_data.get("displayName")
                    if isinstance(current_user_data, dict)
                    else None
                )
                logger.debug(
                    f"get_confluence_fetcher: Validated Confluence token. User context: Email='{user_email or derived_email}', DisplayName='{display_name}'"
                )
                request.state.confluence_fetcher = user_confluence_fetcher
                if (
                    not user_email
                    and derived_email
                    and current_user_data
                    and isinstance(current_user_data, dict)
                    and current_user_data.get("email")
                ):
                    request.state.user_atlassian_email = current_user_data["email"]
                return user_confluence_fetcher
            except Exception as e:
                logger.error(
                    f"get_confluence_fetcher: Failed to create/validate user-specific ConfluenceFetcher: {e}"
                )
                raise ValueError(f"Invalid user Confluence token or configuration: {e}")
        else:
            logger.debug(
                f"get_confluence_fetcher: No user-specific ConfluenceFetcher. Auth type: {user_auth_type}. Token present: {hasattr(request.state, 'user_atlassian_token')}. Will use global fallback."
            )
    except RuntimeError:
        logger.debug(
            "Not in an HTTP request context. Attempting global ConfluenceFetcher for non-HTTP."
        )
    lifespan_ctx_dict_global = ctx.request_context.lifespan_context  # type: ignore
    app_lifespan_ctx_global: MainAppContext | None = (
        lifespan_ctx_dict_global.get("app_lifespan_context")
        if isinstance(lifespan_ctx_dict_global, dict)
        else None
    )
    if app_lifespan_ctx_global and app_lifespan_ctx_global.full_confluence_config:
        logger.debug(
            "get_confluence_fetcher: Using global ConfluenceFetcher from lifespan_context. "
            f"Global config auth_type: {app_lifespan_ctx_global.full_confluence_config.auth_type}"
        )
        return ConfluenceFetcher(config=app_lifespan_ctx_global.full_confluence_config)
    logger.error("Confluence configuration could not be resolved.")
    raise ValueError(
        "Confluence client (fetcher) not available. Ensure server is configured correctly."
    )
