"""Live smoke tests for Jira tools exposed by an MCP server.

These tests are *opt-in* and will only run when:
1. pytest is invoked with ``-m live``, **and**
2. the environment variable ``MCP_LIVE=1`` is set, **and**
3. ``MCP_LINK_CODE`` is available for authenticated requests.

The tests perform **read-only** operations against the running MCP server.
"""

from __future__ import annotations

import os
import pytest
import httpx

pytestmark = pytest.mark.live


def _mcp_request(method: str, params: dict | None = None) -> dict:
    """Send a JSON-RPC request to the MCP server and return the parsed JSON."""
    url = os.getenv("MCP_URL", "http://localhost:9000/mcp")
    timeout = float(os.getenv("MCP_TIMEOUT_SECONDS", "10"))
    headers: dict[str, str] = {}
    link_code = os.getenv("MCP_LINK_CODE")
    if link_code:
        headers["X-MCP-Link-Code"] = link_code

    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    response = httpx.post(url, json=payload, timeout=timeout, headers=headers)
    response.raise_for_status()
    data = response.json()
    assert "result" in data, f"Unexpected JSON-RPC response: {data}"
    return data


def test_tools_list_and_jira_call() -> None:
    """Verify tools/list works and a simple Jira read-only tool call succeeds."""
    tools_response = _mcp_request("tools/list")
    tools: list[str] = tools_response["result"]
    assert isinstance(tools, list) and tools, "tools/list returned no tools"

    # Prefer a tool that takes no required arguments.
    safe_tool_candidates = ["jira_get_link_types", "jira_get_all_projects"]
    target_tool = next((t for t in safe_tool_candidates if t in tools), None)

    if target_tool is None:
        pytest.skip("No safe read-only Jira tool available for live smoke test")

    call_response = _mcp_request(
        "tools/call",
        {
            "tool_name": target_tool,
            "arguments": {},  # The selected tool requires no mandatory args
        },
    )
    # Basic sanity check on the returned data structure
    assert "result" in call_response, "tools/call did not return a result key"
