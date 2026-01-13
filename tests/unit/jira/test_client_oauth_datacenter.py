"""Additional tests for JiraClient OAuth validation specific to Data Center configurations."""

from unittest.mock import patch

import pytest

from mcp_atlassian.jira.client import JiraClient
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.oauth import OAuthConfig


def test_init_with_oauth_datacenter_missing_instance_url() -> None:
    """Ensure an informative error is raised when instance_url is missing for Data Center OAuth."""
    oauth_config = OAuthConfig(
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="https://example.com/callback",
        scope="read:jira-work write:jira-work",
        instance_type="datacenter",
        # instance_url intentionally omitted
        access_token="test-access-token",
    )

    config = JiraConfig(
        url="https://jira.example.com",
        auth_type="oauth",
        oauth_config=oauth_config,
    )

    # Patch Jira to avoid any real initialization/network calls before the error is raised
    with patch("mcp_atlassian.jira.client.Jira"):
        with pytest.raises(
            ValueError,
            match="OAuth authentication for Data Center requires a valid instance_url",
        ):
            JiraClient(config=config)
