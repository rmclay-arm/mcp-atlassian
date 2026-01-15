"""New tests validating minimal OAuth config and Data Center vs Cloud behavior."""

from unittest.mock import patch

import pytest

from mcp_atlassian.utils.oauth import OAuthConfig
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.servers.dependencies import _create_user_config_for_fetcher


def _build_global_oauth_config_cloud(cloud_id: str | None = None) -> OAuthConfig:
    return OAuthConfig(
        client_id="cid",
        client_secret="csec",
        redirect_uri="https://cb",
        scope="scope",
        instance_type="cloud",
        cloud_id=cloud_id,
        access_token="at",
        refresh_token="rt",
    )


def _build_global_oauth_config_dc() -> OAuthConfig:
    return OAuthConfig(
        client_id="cid",
        client_secret="csec",
        redirect_uri="https://cb",
        scope="scope",
        instance_type="datacenter",
        instance_url="https://dc.example.com",
        access_token="at",
        refresh_token="rt",
    )


def test_minimal_oauth_from_env_datacenter(monkeypatch) -> None:
    """Minimal mode should honor INSTANCE_TYPE/URL for Data Center."""
    monkeypatch.setenv("CONFLUENCE_OAUTH_ENABLE", "true")
    monkeypatch.setenv("CONFLUENCE_OAUTH_INSTANCE_TYPE", "datacenter")
    monkeypatch.setenv("CONFLUENCE_OAUTH_INSTANCE_URL", "https://dc.example.com")

    cfg = OAuthConfig.from_env(prefix="CONFLUENCE_OAUTH_")
    assert cfg is not None
    assert cfg.is_datacenter
    assert cfg.instance_url == "https://dc.example.com"
    assert cfg.cloud_id is None


def test_create_user_config_dc_does_not_require_cloud_id() -> None:
    """Data Center user config creation should succeed without cloud_id."""
    base = JiraConfig(url="https://jira", auth_type="oauth", oauth_config=_build_global_oauth_config_dc())

    creds = {"oauth_access_token": "user_tok"}
    user_cfg = _create_user_config_for_fetcher(
        base_config=base, auth_type="oauth", credentials=creds, cloud_id=None
    )
    assert user_cfg.oauth_config is not None
    assert user_cfg.oauth_config.is_datacenter
    assert user_cfg.oauth_config.cloud_id is None
    assert user_cfg.oauth_config.instance_url == "https://dc.example.com"


def test_create_user_config_cloud_requires_cloud_id() -> None:
    """Cloud config must raise when cloud_id missing."""
    base = JiraConfig(url="https://jira", auth_type="oauth", oauth_config=_build_global_oauth_config_cloud())

    creds = {"oauth_access_token": "user_tok"}
    with pytest.raises(ValueError, match="Cloud ID is required"):
        _ = _create_user_config_for_fetcher(
            base_config=base, auth_type="oauth", credentials=creds, cloud_id=None
        )
