"""mcp_call.py

Minimal helper to invoke MCP tools via HTTP with proper JSON escaping and basic
SSE parsing.

Usage example:
    uv run python scripts/mcp_call.py --tool confluence_update_page \\
        --args-file .project-local/runbook_update_args.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, Tuple

import requests

DEFAULT_MCP_URL = os.getenv("MCP_URL", "http://localhost:9000/mcp")
# Environment variables whose names start with these prefixes (case-insensitive)
# are forwarded as HTTP headers. Underscores are replaced with dashes so that
# e.g. `X_CONFLUENCE_AUTHORIZATION` becomes `X-Confluence-Authorization`.
EXTRA_HEADER_PREFIXES: Tuple[str, ...] = ("X_", "X-")

# Default path for local helper env file
DEFAULT_ENV_FILE = Path("scripts/.env.script-helpers")


def _load_env_file(env_path: Path | None) -> None:
    """
    Load KEY=VALUE pairs from a .env style file into os.environ.

    The parser is minimal by design:
    - Lines starting with ``#`` or blank lines are ignored.
    - Leading/trailing whitespace around keys and values is stripped.
    - Values are taken verbatim (no quote unescaping, multiline, etc.)

    Existing environment variables are not overwritten.
    """
    if env_path is None or not env_path.exists():
        return

    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        # Do not overwrite already‐exported env vars
        if key and key not in os.environ:
            os.environ[key] = val


def _iter_extra_headers() -> Iterator[Tuple[str, str]]:
    """Yield additional HTTP headers sourced from env vars (never logged)."""
    for name, value in os.environ.items():
        upper = name.upper()
        if upper.startswith(EXTRA_HEADER_PREFIXES):
            header_name = name.replace("_", "-")
            yield header_name, value


def _first_sse_event(resp: requests.Response) -> Dict[str, Any]:
    """Read the first SSE 'data:' event and return the parsed JSON payload."""
    # Stream must be text-decoded line by line
    buffer = ""
    for line in resp.iter_lines(decode_unicode=True):
        if not line:  # Empty line marks end of an event
            buffer = ""
            continue

        if line.startswith("data:"):
            # Strip "data:" prefix and leading spaces
            payload = line[len("data:") :].lstrip()
            return json.loads(payload)
    raise RuntimeError("No SSE data event received from MCP server.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Call an MCP tool.")
    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL, help="MCP base URL")
    parser.add_argument("--tool", required=True, help="Tool name to invoke")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--args-file", type=Path, help="Path to JSON args file")
    group.add_argument("--args-json", help="Inline JSON args string")
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Path to helper env file (default: scripts/.env.script-helpers)",
    )
    parser.add_argument(
        "--rpc-method",
        default="tools/call",
        help=(
            "Override JSON-RPC method (e.g., tools/list) "
            "instead of the default tools/call"
        ),
    )
    args = parser.parse_args()

    # Load env file first so MCP_URL override is available early
    env_file = args.env_file if args.env_file else (DEFAULT_ENV_FILE if DEFAULT_ENV_FILE.exists() else None)
    _load_env_file(env_file)

    # Load tool args
    if args.args_file:
        try:
            tool_args_raw = args.args_file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            sys.exit(f"Args file not found: {exc.filename}")
    else:
        tool_args_raw = args.args_json

    try:
        tool_args = json.loads(tool_args_raw)
    except json.JSONDecodeError as exc:
        sys.exit(f"Invalid JSON in tool args: {exc}")

    session_id = str(uuid.uuid4())

    # ------------------------------------------------------------------
    # Build JSON-RPC 2.0 envelope expected by the MCP server
    # ------------------------------------------------------------------
    if args.rpc_method and args.rpc_method != "tools/call":
        # Explicit override (e.g. tools/list)
        method = args.rpc_method
        params = {}
    elif args.tool == "tools/list":
        # Legacy convenience: --tool tools/list
        method = "tools/list"
        params = {}
    else:
        # Generic tool invocation
        method = "tools/call"
        params = {"name": args.tool, "arguments": tool_args}

    payload: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": session_id,
        "method": method,
        "params": params,
    }

    # Prefer SSE for streaming but gracefully fall back to JSON if the server
    # responds with a standard application/json payload to avoid 406 errors.
    headers: Dict[str, str] = {
        "Accept": "text/event-stream, application/json;q=0.9",
        "mcp-session-id": session_id,
    }
    headers.update(dict(_iter_extra_headers()))

    # Map specific env vars to headers
    if (val := os.getenv("MCP_CONFLUENCE_AUTH_HEADER")):
        headers["X-Confluence-Authorization"] = val
    if (val := os.getenv("MCP_JIRA_AUTH_HEADER")):
        headers["X-Jira-Authorization"] = val
    if (val := os.getenv("MCP_LINK_CODE")):
        headers["X-MCP-Link-Code"] = val

    # Safe debug: print only header names, never values
    header_names = ", ".join(sorted(headers.keys()))
    print(f"Using headers: {header_names}", file=sys.stderr)

    try:
        resp = requests.post(
            args.mcp_url,
            json=payload,
            headers=headers,
            stream=True,
            timeout=300,  # generous default
        )
    except requests.RequestException as exc:
        sys.exit(f"HTTP error communicating with MCP server: {exc}")

    if not resp.ok:
        # Print server-provided error payload to aid troubleshooting but avoid
        # leaking any auth headers. Prefer JSON decoding, fallback to raw text.
        try:
            err_payload = resp.json()
            err_str = json.dumps(err_payload, ensure_ascii=False)
        except Exception:
            err_str = resp.text.strip()
        sys.exit(
            f"Server returned HTTP {resp.status_code}: {err_str or 'No response body'}"
        )

    content_type = resp.headers.get("content-type", "")
    try:
        if "event-stream" in content_type:
            result_json = _first_sse_event(resp)
        else:
            # Fall back to plain JSON response body
            result_json = resp.json()
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Failed to parse MCP response: {exc}")

    print(json.dumps(result_json, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
