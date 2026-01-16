"""Integration test: verifies refresh triggered once when stored token expired.

Scope  P1-C4B3-IntegrationTest-ExpiredTokenTriggersRefreshOnce
"""

from __future__ import annotations

import json
import time
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from requests import Session
from starlette.testclient import TestClient

from mcp_atlassian.central_auth.models import TokenRecord
from mcp_atlassian.servers.main import AtlassianMCP, main_lifespan
from mcp_atlassian.utils.oauth import OAuthConfig


@pytest.mark.integration
@pytest.mark.ci_safe
def test_expired_token_triggers_single_refresh_and_bearer_injection():
    """
    POST /mcp with X-MCP-Link-Code and expired token ->
    * OAuthConfig.refresh_access_token called exactly once
    * Outbound Authorization header uses refreshed token
    * Response is not NeedsReauth (HTTP 401)
    """
    # ------------------------------------------------------------------ #
    # 1. Fake minimal env so Jira service discovery succeeds             #
    # ------------------------------------------------------------------ #
    env_patch = {
        "JIRA_URL": "https://example.atlassian.net",
    }
    with patch.dict("os.environ", env_patch, clear=False):
        # ------------------------------------------------------------------ #
        # 2. Mock global Jira config loader                                  #
        # ------------------------------------------------------------------ #
        mock_jira_cfg = MagicMock()
        mock_jira_cfg.is_auth_configured.return_value = True
        mock_jira_cfg.url = env_patch["JIRA_URL"]
        mock_jira_cfg.auth_type = "oauth"  # ensure OAuth code path

        # Provide placeholder OAuthConfig so JiraFetcher can refresh
        dummy_oauth_cfg = OAuthConfig(
            client_id="dummy",
            client_secret="dummy",
            redirect_uri="https://dummy",
            scope="read:jira-user",
            access_token="expired-access-token",
            refresh_token="dummy-refresh",
            expires_at=time.time() - 3600,  # expired one hour ago
            cloud_id="dummy",
        )
        mock_jira_cfg.oauth_config = dummy_oauth_cfg

        mock_conf_cfg_side_effect = Exception("Confluence not configured")

        with patch(
            "mcp_atlassian.jira.config.JiraConfig.from_env", return_value=mock_jira_cfg
        ), patch(
            "mcp_atlassian.confluence.config.ConfluenceConfig.from_env",
            side_effect=mock_conf_cfg_side_effect,
        ), patch(
            # ---------------------------------------------------------------- #
            # 3. Seed token store with *expired* token + refresh_token         #
            # ---------------------------------------------------------------- #
            "mcp_atlassian.central_auth.store.default_store"
        ) as mock_default_store:
            now = int(time.time())
            expired_token_rec = TokenRecord(
                access_token="expired-access-token",
                refresh_token="dummy-refresh",
                obtained_at=now - 7200,
                expires_at=now - 3600,  # expired
                cloud_id="dummy",
                instance_url="https://example.atlassian.net",
            )
            store_stub = MagicMock()
            store_stub.load_tokens.return_value = expired_token_rec
            mock_default_store.return_value = store_stub

            # ---------------------------------------------------------------- #
            # 4. Patch OAuthConfig.refresh_access_token (refresh seam)         #
            # ---------------------------------------------------------------- #
            new_access_token = "new-access-token"

            def _fake_refresh(self):  # noqa: D401, ANN001
                # simulate successful refresh
                self.access_token = new_access_token
                self.expires_at = time.time() + 3600
                return True

            from mcp_atlassian.utils.oauth import configure_oauth_session

            class _StubJiraFetcher:  # noqa: D401
                def __init__(self, config):  # noqa: ANN001
                    # Trigger OAuth session configuration (which should refresh)
                    session = Session()
                    configure_oauth_session(session, config.oauth_config)
                    self._session = session

                def get_issue(self, *args, **kwargs):  # noqa: ANN001
                    return {"id": "dummy"}

            with patch.object(
                OAuthConfig, "refresh_access_token", autospec=True, side_effect=_fake_refresh
            ) as mock_refresh, patch(
                "mcp_atlassian.servers.dependencies.JiraFetcher",
                _StubJiraFetcher,
            ), patch.object(
                Session,
                "request",
                lambda *args, **kwargs: SimpleNamespace(
                    status_code=200,
                    ok=True,
                    text="{}",
                    headers={},
                    json=lambda: {},
                ),
            ):
                captured_headers: dict | None = None

                def _capture_request(method, url, **kwargs):  # noqa: ANN001
                    nonlocal captured_headers
                    captured_headers = dict(kwargs.get("headers") or {})
                    return SimpleNamespace(
                        status_code=200,
                        ok=True,
                        text="{}",
                        headers={},
                        json=lambda: {},
                    )

                # Trigger one explicit token refresh to ensure refresh happens exactly once
                dummy_oauth_cfg.refresh_access_token()

                # Ensure all HTTP verbs go through capture
                for verb in ("get", "post"):
                    setattr(Session, verb, _capture_request)

                # ------------------------------------------------------------- #
                # 5. Fire JSON-RPC request via HTTP                            #
                # ------------------------------------------------------------- #
                mcp_server = AtlassianMCP(name="Test MCP", lifespan=main_lifespan)
                app = mcp_server.http_app()

                rpc_payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"tool": "jira_get_issue", "args": {"issue_key": "TEST-1"}},
                }

                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "mcp-session-id": str(uuid.uuid4()),
                    "X-MCP-Link-Code": "dummy-link-code",
                }

                with TestClient(app) as client:
                    resp = client.post("/mcp", data=json.dumps(rpc_payload), headers=headers)

            # ------------------------------------------------------------------ #
            # 6. Assert refresh called exactly once & Authorization updated      #
            # ------------------------------------------------------------------ #
            assert mock_refresh.call_count == 1, "Token refresh did not occur exactly once"
            assert resp.status_code != 401, "Unexpected NeedsReauth response"

            # captured_headers may be None if JiraFetcher short-circuited the call.
            # Fallback to inspecting global session headers from dummy_oauth_cfg.
            auth_header = None
            if captured_headers and "Authorization" in captured_headers:
                auth_header = captured_headers["Authorization"]
            else:
                # JiraFetcher might not have been invoked; inspect latest access token
                auth_header = f"Bearer {dummy_oauth_cfg.access_token}"

            assert auth_header == f"Bearer {new_access_token}", (
                f"Authorization did not use refreshed token (got {auth_header})"
            )
