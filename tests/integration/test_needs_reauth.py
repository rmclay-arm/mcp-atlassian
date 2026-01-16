"""Integration test: verifies NeedsReauth HTTP response when link-code header is
present and no stored credentials exist.

Scope  P1-C4B1-IntegrationTest-NeedsReauthViaHttpOnly
"""

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from mcp_atlassian.servers.main import AtlassianMCP, main_lifespan


@pytest.mark.integration
def test_needs_reauth_response_when_link_code_present():
    """POST /mcp with X-MCP-Link-Code → 401 NeedsReauth JSON."""
    # ------------------------------------------------------------------ #
    # 1. Fake minimal environment so Jira service is considered enabled  #
    # ------------------------------------------------------------------ #
    env_patch = {
        # Presence of URL enables Jira service discovery in get_available_services
        "JIRA_URL": "https://example.atlassian.net",
    }

    with patch.dict("os.environ", env_patch, clear=False):
        # ------------------------------------------------------------------ #
        # 2. Mock global config loaders so lifespan finishes successfully    #
        # ------------------------------------------------------------------ #
        mock_jira_cfg = MagicMock()
        mock_jira_cfg.is_auth_configured.return_value = True
        mock_jira_cfg.url = env_patch["JIRA_URL"]
        mock_conf_cfg_side_effect = Exception("Confluence not configured")

        with patch(
            "mcp_atlassian.jira.config.JiraConfig.from_env", return_value=mock_jira_cfg
        ), patch(
            "mcp_atlassian.confluence.config.ConfluenceConfig.from_env",
            side_effect=mock_conf_cfg_side_effect,
        ), patch(
            # ------------------------------------------------------------------ #
            # 3. Force token resolution layer to return *no stored tokens*       #
            # ------------------------------------------------------------------ #
            "mcp_atlassian.central_auth.store.default_store"
        ) as mock_default_store:

            store_stub = MagicMock()
            store_stub.load_tokens.return_value = None  # Simulate missing tokens
            mock_default_store.return_value = store_stub

            # ------------------------------------------------------------------ #
            # 4. Instantiate server + HTTP app                                   #
            # ------------------------------------------------------------------ #
            mcp_server = AtlassianMCP(name="Test MCP", lifespan=main_lifespan)
            app = mcp_server.http_app()  # Defaults: path="/mcp"

            # ------------------------------------------------------------------ #
            # 5. Compose JSON-RPC request that calls a Jira tool                 #
            #    This will trigger get_jira_fetcher which raises NeedsReauth     #
            # ------------------------------------------------------------------ #
            request_id = 1
            rpc_payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"tool": "jira_get_issue", "args": {"issue_key": "TEST-1"}},
            }

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "mcp-session-id": str(uuid.uuid4()),
                # Trigger binding-header logic → NeedsReauthError
                "X-MCP-Link-Code": "dummy-link-code",
            }

            # ------------------------------------------------------------------ #
            # 6. Fire request and assert NeedsReauth JSON structure              #
            # ------------------------------------------------------------------ #
            with TestClient(app) as client:
                resp = client.post("/mcp", data=json.dumps(rpc_payload), headers=headers)

            assert resp.status_code == 401
            body = resp.json()

            # Top-level contract
            assert body["error"] == "needs_reauth"
            assert body["product"] == "jira"
            assert body["instance_id"] == "default"
            # /auth/<product>/start?instance=...
            assert body["start_url"].startswith("/auth/jira/start")
