"""Utility functions related to environment checking."""

import logging
import os
from typing import Final, Tuple

from .urls import is_atlassian_cloud_url

logger = logging.getLogger("mcp-atlassian.utils.environment")

_TRUTHY: Final[Tuple[str, ...]] = ("true", "1", "yes", "y", "on")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUTHY


def _client_auth_enabled(service: str) -> bool:
    """
    Return True if ``${SERVICE}_CLIENT_AUTH`` is set to a truthy value.

    This activates *client-provided authentication* mode where callers include
    authentication headers directly and no server-side credentials are required.
    """
    return _truthy(os.getenv(f"{service}_CLIENT_AUTH"))


def _service_oauth_vars_present(service: str) -> bool:
    """
    Return True if *any* service-scoped OAuth variables are present for this service.

    This enforces the resolution order documented in .env.example:
      1) SERVICE-scoped OAuth variables win as a group
      2) Legacy ATLASSIAN_OAUTH_* is used only if no service-scoped vars exist
    """
    prefix = f"{service}_OAUTH_"
    keys = (
        "ENABLE",
        "CLIENT_ID",
        "CLIENT_SECRET",
        "REDIRECT_URI",
        "SCOPE",
        "INSTANCE_TYPE",
        "INSTANCE_URL",
        "CLOUD_ID",
        "ACCESS_TOKEN",
    )
    return any(os.getenv(prefix + k) for k in keys)


def _oauth_get(service: str, key: str) -> str | None:
    """
    Get OAuth env var for the service, using service-scoped vars if present,
    otherwise falling back to legacy ATLASSIAN_OAUTH_*.
    """
    if _service_oauth_vars_present(service):
        return os.getenv(f"{service}_OAUTH_{key}")
    return os.getenv(f"ATLASSIAN_OAUTH_{key}")


def _oauth_enable(service: str) -> bool:
    """
    Determine whether OAuth is enabled for a given service following
    well-defined precedence rules.

    Precedence (highest → lowest):
      1. Service-scoped ``${SERVICE}_OAUTH_ENABLE`` when explicitly set
         • Any truthy value  → enabled
         • Any falsy value   → disabled
      2. Legacy global ``ATLASSIAN_OAUTH_ENABLE``

    This behaviour allows the new *minimal OAuth* mode to be activated via the
    global flag even when other service-scoped OAuth variables (such as
    CLIENT_ID placeholders) are present, unless the operator explicitly sets
    ``${SERVICE}_OAUTH_ENABLE=false`` to opt-out.
    """
    # Read the service-scoped flag **without** requiring that other service-
    # scoped variables are present. If the flag exists it unconditionally wins.
    service_enable_raw = os.getenv(f"{service}_OAUTH_ENABLE")
    if service_enable_raw is not None:
        return _truthy(service_enable_raw)

    # Fall back to the legacy global flag when no service-scoped override.
    return _truthy(os.getenv("ATLASSIAN_OAUTH_ENABLE"))


def _oauth_has_client(service: str) -> bool:
    return all(
        [
            _oauth_get(service, "CLIENT_ID"),
            _oauth_get(service, "CLIENT_SECRET"),
            _oauth_get(service, "REDIRECT_URI"),
            _oauth_get(service, "SCOPE"),
        ]
    )


def _oauth_instance_type(service: str) -> str:
    return (_oauth_get(service, "INSTANCE_TYPE") or "cloud").strip().lower()


def _configured_via_oauth(service: str) -> tuple[bool, str | None]:
    """
    Determine if the service is configured via OAuth based on environment variables.
    Returns (is_configured, log_message_if_configured).
    """
    has_client = _oauth_has_client(service)
    instance_type = _oauth_instance_type(service)

    # Minimal OAuth mode: user-provided tokens via headers (no persisted tokens required)
    # This should enable tool registration even when no client details are provided.
    if _oauth_enable(service) and not has_client:
        return True, f"Using {service.title()} minimal OAuth configuration - expecting user-provided tokens via headers"

    # Bring Your Own Token (Cloud only)
    if _oauth_get(service, "ACCESS_TOKEN") and _oauth_get(service, "CLOUD_ID"):
        return True, (
            f"Using {service.title()} OAuth 2.0 (3LO) authentication (Cloud-only features) "
            f"with provided access token"
        )

    # Full OAuth client config present: decide Cloud vs Data Center
    if has_client:
        if instance_type == "datacenter":
            if _oauth_get(service, "INSTANCE_URL"):
                return True, f"Using {service.title()} OAuth 2.0 authentication (Data Center)"
            return False, None

        # Cloud: require CLOUD_ID (populated after oauth-setup)
        if _oauth_get(service, "CLOUD_ID"):
            return True, f"Using {service.title()} OAuth 2.0 (3LO) authentication (Cloud-only features)"
        return False, None

    return False, None


def get_available_services() -> dict[str, bool | None]:
    """Determine which services are available based on environment variables."""
    # -----------------------------
    # Confluence
    # -----------------------------
    confluence_url = os.getenv("CONFLUENCE_URL")
    confluence_is_setup = False

    if confluence_url:
        is_cloud = is_atlassian_cloud_url(confluence_url)

        # 0) Client-provided auth via headers (no server-side credentials required)
        if _client_auth_enabled("CONFLUENCE"):
            confluence_is_setup = True
            logger.info("Using Confluence client-provided authentication via headers")

        # 1) OAuth (service-scoped first, legacy fallback)
        oauth_ok, oauth_msg = _configured_via_oauth("CONFLUENCE")
        if oauth_ok:
            confluence_is_setup = True
            logger.info(oauth_msg)

        # 2) Cloud non-OAuth (API token)
        elif is_cloud and os.getenv("CONFLUENCE_USERNAME") and os.getenv("CONFLUENCE_API_TOKEN"):
            confluence_is_setup = True
            logger.info("Using Confluence Cloud Basic Authentication (API Token)")

        # 3) Server/Data Center non-OAuth (PAT or Basic)
        elif (os.getenv("CONFLUENCE_PERSONAL_TOKEN")) or (
            os.getenv("CONFLUENCE_USERNAME") and os.getenv("CONFLUENCE_API_TOKEN")
        ):
            confluence_is_setup = True
            logger.info("Using Confluence Server/Data Center authentication (PAT or Basic Auth)")

    else:
        # Preserve prior behavior: minimal OAuth can still “enable” the service even without URL.
        if _oauth_enable("CONFLUENCE"):
            confluence_is_setup = True
            logger.info(
                "Using Confluence minimal OAuth configuration - expecting user-provided tokens via headers"
            )

    # -----------------------------
    # Jira
    # -----------------------------
    jira_url = os.getenv("JIRA_URL")
    jira_is_setup = False

    if jira_url:
        is_cloud = is_atlassian_cloud_url(jira_url)

        # 0) Client-provided auth via headers (no server-side credentials required)
        if _client_auth_enabled("JIRA"):
            jira_is_setup = True
            logger.info("Using Jira client-provided authentication via headers")

        # 1) OAuth (service-scoped first, legacy fallback)
        oauth_ok, oauth_msg = _configured_via_oauth("JIRA")
        if oauth_ok:
            jira_is_setup = True
            logger.info(oauth_msg)

        # 2) Cloud non-OAuth (API token)
        elif is_cloud and os.getenv("JIRA_USERNAME") and os.getenv("JIRA_API_TOKEN"):
            jira_is_setup = True
            logger.info("Using Jira Cloud Basic Authentication (API Token)")

        # 3) Server/Data Center non-OAuth (PAT or Basic)
        elif (os.getenv("JIRA_PERSONAL_TOKEN")) or (os.getenv("JIRA_USERNAME") and os.getenv("JIRA_API_TOKEN")):
            jira_is_setup = True
            logger.info("Using Jira Server/Data Center authentication (PAT or Basic Auth)")

    else:
        # Preserve prior behavior: minimal OAuth can still “enable” the service even without URL.
        if _oauth_enable("JIRA"):
            jira_is_setup = True
            logger.info("Using Jira minimal OAuth configuration - expecting user-provided tokens via headers")

    # -----------------------------
    # Final log messages
    # -----------------------------
    if not confluence_is_setup:
        logger.info("Confluence is not configured or required environment variables are missing.")
    if not jira_is_setup:
        logger.info("Jira is not configured or required environment variables are missing.")

    return {"confluence": confluence_is_setup, "jira": jira_is_setup}
