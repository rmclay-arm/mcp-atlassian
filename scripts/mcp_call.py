"""mcp_call.py

Helper to invoke MCP JSON-RPC endpoints with correct Accept headers,
automatic server-minted *mcp-session-id* bootstrapping, and optional
local caching of the minted session ID.

Key features
------------
* Always sends: ``Accept: application/json, text/event-stream``
* Optional user-supplied session id via ``--session-id`` or
  ``MCP_SESSION_ID`` env var
* Transparent bootstrap if the server requires a minted session id
  (handles both JSON and SSE responses)
* Session id cache stored under ``.project-local/mcp-session/`` keyed
  by the MCP base URL (never stores auth tokens)
* Logs **header names only** – values remain hidden

Example
-------
    uv run python scripts/mcp_call.py --rpc-method tools/list
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, MutableMapping, Tuple

import requests

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
DEFAULT_MCP_URL = os.getenv("MCP_URL", "http://localhost:9000/mcp")
DEFAULT_ENV_FILE = Path("scripts/.env.script-helpers")
ACCEPT_HEADER_VALUE = "application/json, text/event-stream"

EXTRA_HEADER_PREFIXES: Tuple[str, ...] = ("X_", "X-")  # forwarded env → header
CACHE_ROOT = Path(".project-local/mcp-session")


# --------------------------------------------------------------------------- #
# Environment helpers
# --------------------------------------------------------------------------- #
def _load_env_file(env_path: Path | None) -> None:
    """Load KEY=VALUE pairs from a .env style file into *os.environ*."""
    if env_path is None or not env_path.exists():
        return

    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if key and key not in os.environ:
            os.environ[key] = val


def _iter_extra_headers() -> Iterator[Tuple[str, str]]:
    """Yield additional HTTP headers sourced from env vars (never log values)."""
    for name, value in os.environ.items():
        if name.upper().startswith(EXTRA_HEADER_PREFIXES):
            yield name.replace("_", "-"), value


# --------------------------------------------------------------------------- #
# Session-ID cache helpers
# --------------------------------------------------------------------------- #
def _safe_url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def _cache_path(mcp_url: str) -> Path:
    return CACHE_ROOT / f"{_safe_url_hash(mcp_url)}.txt"


def _read_cached_session_id(mcp_url: str) -> str | None:
    path = _cache_path(mcp_url)
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except FileNotFoundError:
        return None


def _write_cached_session_id(mcp_url: str, session_id: str) -> None:
    """Atomically write *session_id* to cache (create dirs as needed)."""
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(dir=str(CACHE_ROOT), text=True)
    with os.fdopen(temp_fd, "w", encoding="utf-8") as tmp_file:
        tmp_file.write(session_id)
    Path(temp_path).replace(_cache_path(mcp_url))


# --------------------------------------------------------------------------- #
# Response parsing helpers
# --------------------------------------------------------------------------- #
def _first_sse_event(resp: requests.Response) -> Dict[str, Any]:
    """Return the JSON of the first SSE 'data:' frame."""
    buffer = ""
    for line in resp.iter_lines(decode_unicode=True):
        if not line:
            buffer = ""
            continue
        if line.startswith("data:"):
            payload = line[len("data:") :].lstrip()
            return json.loads(payload)
    raise RuntimeError("No SSE data event received from MCP server.")


# --------------------------------------------------------------------------- #
# Session bootstrap
# --------------------------------------------------------------------------- #
def _bootstrap_session_id(
    mcp_url: str,
    base_headers: Mapping[str, str],
    timeout: int = 30,
) -> str:
    """Bootstrap a new server-minted *mcp-session-id*.

    The handshake consists of:
    1. ``initialize`` (no session header) → server returns session id.
    2. ``notifications/initialized`` using the minted session id.

    Returns
    -------
    str
        The minted session id.
    """
    # ------------------------------------------------------------------ #
    # 1) initialize
    # ------------------------------------------------------------------ #
    init_payload: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "mcp_call.py", "version": "0.2.0"},
            "capabilities": {},
        },
    }

    init_headers: Dict[str, str] = dict(base_headers)
    init_headers.pop("mcp-session-id", None)  # MUST NOT send on bootstrap

    try:
        init_resp = requests.post(
            mcp_url,
            json=init_payload,
            headers=init_headers,
            stream=True,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        sys.exit(f"initialize request failed: {exc}")

    minted = init_resp.headers.get("mcp-session-id")
    if not minted:
        header_names = ", ".join(sorted(init_resp.headers.keys()))
        sys.exit(
            "initialize failed – server did not return an 'mcp-session-id' header. "
            f"Response headers: {header_names}"
        )

    # ------------------------------------------------------------------ #
    # 2) notifications/initialized
    # ------------------------------------------------------------------ #
    notify_payload: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "notifications/initialized",
        "params": {},
    }

    notify_headers: Dict[str, str] = dict(base_headers)
    notify_headers["mcp-session-id"] = minted

    try:
        notify_resp = requests.post(
            mcp_url,
            json=notify_payload,
            headers=notify_headers,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        sys.exit(f"notifications/initialized request failed: {exc}")

    if not notify_resp.ok:
        sys.exit(
            f"notifications/initialized returned HTTP {notify_resp.status_code}: "
            f"{notify_resp.text.strip() or 'No response body'}"
        )

    return minted


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description="Call an MCP tool.")

    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL, help="MCP base URL")
    parser.add_argument("--tool", help="Tool name to invoke")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--args-file", type=Path, help="Path to JSON args file")
    group.add_argument("--args-json", help="Inline JSON args string")
    parser.add_argument(
        "--env-file",
        type=Path,
        help=f"Helper env file (default: {DEFAULT_ENV_FILE})",
    )
    parser.add_argument(
        "--rpc-method",
        default="tools/call",
        help="Override JSON-RPC method (e.g., tools/list)",
    )
    parser.add_argument(
        "--session-id",
        default=os.getenv("MCP_SESSION_ID"),
        help="Use an explicit mcp-session-id value",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable reading/writing the local session id cache",
    )

    args = parser.parse_args()

    # Tool validation – require when using tools/call
    if args.rpc_method == "tools/call" and not args.tool:
        parser.error("--tool is required when rpc-method is tools/call")

    # Load env file early so MCP_URL overrides are respected
    env_file = (
        args.env_file
        if args.env_file
        else (DEFAULT_ENV_FILE if DEFAULT_ENV_FILE.exists() else None)
    )
    _load_env_file(env_file)

    # --------------------------------------------------------------------- #
    # Load tool arguments
    # --------------------------------------------------------------------- #
    if args.args_file:
        try:
            raw = args.args_file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            sys.exit(f"Args file not found: {exc.filename}")
    else:
        raw = args.args_json or "{}"

    try:
        tool_args = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.exit(f"Invalid JSON in tool args: {exc}")

    # --------------------------------------------------------------------- #
    # Build JSON-RPC envelope
    # --------------------------------------------------------------------- #
    call_id = str(uuid.uuid4())
    if args.rpc_method != "tools/call":
        method = args.rpc_method
        params: Dict[str, Any] = {}
    elif args.tool == "tools/list":
        method = "tools/list"
        params = {}
    else:
        method = "tools/call"
        params = {"name": args.tool, "arguments": tool_args}

    payload: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": method,
        "params": params,
    }

    # --------------------------------------------------------------------- #
    # Session handling – cache → flag/env → bootstrap
    # --------------------------------------------------------------------- #
    session_id: str | None = None
    if not args.no_cache:
        session_id = _read_cached_session_id(args.mcp_url)
    if args.session_id:
        session_id = args.session_id

    # Base headers (never log values)
    headers: Dict[str, str] = {
        "Accept": ACCEPT_HEADER_VALUE,
    }
    if session_id:
        headers["mcp-session-id"] = session_id

    # Forward X-* env variables
    headers.update(dict(_iter_extra_headers()))

    # Explicit header mappings
    if (val := os.getenv("MCP_CONFLUENCE_AUTH_HEADER")):
        headers["X-Confluence-Authorization"] = val
    if (val := os.getenv("MCP_JIRA_AUTH_HEADER")):
        headers["X-Jira-Authorization"] = val
    if (val := os.getenv("MCP_LINK_CODE")):
        headers["X-MCP-Link-Code"] = val

    # Safe debug: names only
    print(f"Using headers: {', '.join(sorted(headers.keys()))}", file=sys.stderr)

    # Bootstrap if we still lack a session id
    if "mcp-session-id" not in headers:
        minted = _bootstrap_session_id(args.mcp_url, headers)
        headers["mcp-session-id"] = minted
        if not args.no_cache:
            _write_cached_session_id(args.mcp_url, minted)

    # --------------------------------------------------------------------- #
    # Perform the intended request
    # --------------------------------------------------------------------- #
    def _send_request(hdrs: MutableMapping[str, str]) -> requests.Response:
        try:
            return requests.post(
                args.mcp_url,
                json=payload,
                headers=hdrs,
                stream=True,
                timeout=300,
            )
        except requests.RequestException as exc:
            sys.exit(f"HTTP error communicating with MCP server: {exc}")

    resp = _send_request(headers)

    # Retry once if session id rejected
    if (
        resp.status_code == 400
        and "no valid session id" in resp.text.lower()
        or resp.status_code == 401
        and "invalid session id" in resp.text.lower()
    ):
        print("Session id rejected – bootstrapping a new one.", file=sys.stderr)
        minted = _bootstrap_session_id(args.mcp_url, headers)
        headers["mcp-session-id"] = minted
        if not args.no_cache:
            _write_cached_session_id(args.mcp_url, minted)
        resp = _send_request(headers)

    # --------------------------------------------------------------------- #
    # Handle non-OK responses
    # --------------------------------------------------------------------- #
    if not resp.ok:
        try:
            err_payload = resp.json()
            err_str = json.dumps(err_payload, ensure_ascii=False)
        except Exception:
            err_str = resp.text.strip()
        sys.exit(
            f"Server returned HTTP {resp.status_code}: {err_str or 'No response body'}"
        )

    # --------------------------------------------------------------------- #
    # Parse successful response
    # --------------------------------------------------------------------- #
    content_type = resp.headers.get("content-type", "")
    try:
        if "event-stream" in content_type:
            result_json = _first_sse_event(resp)
        else:
            result_json = resp.json()
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Failed to parse MCP response: {exc}")

    print(json.dumps(result_json, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
