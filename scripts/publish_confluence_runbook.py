"""publish_confluence_runbook.py

Helper that publishes docs/central-oauth/runbook.md to Confluence using the
confluence_update_page MCP tool.  
Avoids fragile JSON-in-JSON agent calls by delegating to scripts/mcp_call.py.

Execution example:
    uv run python scripts/publish_confluence_runbook.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict
import argparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = PROJECT_ROOT / "docs" / "central-oauth" / "runbook.md"
STATE_PATH = PROJECT_ROOT / ".project-local" / "state.json"
MCP_CALL_SCRIPT = PROJECT_ROOT / "scripts" / "mcp_call.py"

PAGE_KEY = "runbook"
ARGS_FILENAME = ".project-local/runbook_update_args.json"
PRE_ARGS_FILENAME = ".project-local/runbook_preflight_args.json"


def load_state() -> Dict[str, Any]:
    if not STATE_PATH.exists():
        sys.exit(
            "State file missing. Run docs-sync task first to resolve Confluence "
            "page IDs (creates .project-local/state.json)."
        )
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.exit(f"Invalid JSON in {STATE_PATH}: {exc}")


def get_page_id(state: Dict[str, Any]) -> str:
    try:
        page_entry = state["confluence"]["pagesByKey"][PAGE_KEY]
    except KeyError:
        sys.exit(
            f"Page key '{PAGE_KEY}' missing in state. "
            "Run docs-sync to persist page IDs."
        )

    if isinstance(page_entry, dict):
        page_id = page_entry.get("pageId") or page_entry.get("id")
    else:
        page_id = page_entry

    if not page_id:
        sys.exit(
            f"Page ID for key '{PAGE_KEY}' is null. "
            "Run docs-sync to resolve and persist the page ID."
        )
    return str(page_id)


def build_args(page_id: str, content: str) -> Dict[str, Any]:
    return {
        "page_id": page_id,
        "title": "Central OAuth – Runbook",
        "content": content,
        "content_format": "markdown",
    }


def run_preflight(page_id: str, env_file: Path | None) -> bool:
    """
    Read-only sanity check: attempt to fetch the Confluence page by ID.

    Returns True if successful, False otherwise.
    """
    pre_args = {
        "page_id": page_id,
        "include_metadata": False,
        "convert_to_markdown": False,
    }
    args_path = PROJECT_ROOT / PRE_ARGS_FILENAME
    args_path.parent.mkdir(parents=True, exist_ok=True)
    args_path.write_text(json.dumps(pre_args), encoding="utf-8")

    cmd = [
        "uv",
        "run",
        "python",
        str(MCP_CALL_SCRIPT),
        "--tool",
        "confluence_get_page",
        "--args-file",
        str(args_path),
    ]
    if env_file:
        cmd.extend(["--env-file", str(env_file)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=os.environ.copy(),
        )
    except subprocess.CalledProcessError as exc:
        print("✖ Preflight FAILED – MCP call error.", file=sys.stderr)
        print(exc.stderr.strip(), file=sys.stderr)
        return False

    # Parse JSON result to detect { "isError": true }
    try:
        result_json = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("✖ Preflight FAILED – invalid JSON response.", file=sys.stderr)
        return False

    if result_json.get("isError"):
        print("✖ Preflight FAILED – server reported error.", file=sys.stderr)
        return False

    print("✔ Preflight succeeded – page is accessible.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Publish Central OAuth runbook to Confluence."
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Path to helper env file (default: scripts/.env.script-helpers)",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Run read-only preflight check and exit without publishing.",
    )
    args = parser.parse_args()

    # Resolve env file: explicit flag wins, otherwise use default if it exists
    default_env = PROJECT_ROOT / "scripts" / ".env.script-helpers"
    env_file = (
        args.env_file
        if args.env_file
        else (default_env if default_env.exists() else None)
    )

    # Load environment helpers (.env) without importing scripts.mcp_call
    if env_file and env_file.exists():
        for raw in env_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if key and key not in os.environ:
                os.environ[key] = val
    # Read runbook content
    if not DOC_PATH.exists():
        sys.exit(f"Runbook not found at {DOC_PATH}")
    runbook_md = DOC_PATH.read_text(encoding="utf-8")

    # Load project-local state and extract page_id
    state = load_state()
    page_id = get_page_id(state)

    # ------------------------------------------------------------------
    # Preflight check
    # ------------------------------------------------------------------
    ok = run_preflight(page_id, env_file)
    if args.preflight_only:
        sys.exit(0 if ok else 1)
    if not ok:
        sys.exit(1)

    tool_args = build_args(page_id, runbook_md)

    # Write tool args to temp file in .project-local
    args_path = PROJECT_ROOT / ARGS_FILENAME
    args_path.parent.mkdir(parents=True, exist_ok=True)
    args_path.write_text(json.dumps(tool_args), encoding="utf-8")

    # First attempt: update existing page
    cmd = [
        "uv",
        "run",
        "python",
        str(MCP_CALL_SCRIPT),
        "--tool",
        "confluence_update_page",
        "--args-file",
        str(args_path),
    ]
    # Forward the same env-file to mcp_call.py so headers are applied consistently
    if env_file:
        cmd.extend(["--env-file", str(env_file)])

    # Propagate current env (contains auth headers), but ensure we do not print them.
    try:
        proc = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        out = proc.stdout.strip() or proc.stderr.strip()
        if '"isError": true' in out:
            print(
                "✖ Confluence runbook update FAILED (key:",
                PAGE_KEY,
                ").",
                file=sys.stderr,
            )
            print(
                "Run the docs-sync task to ensure page IDs are resolved "
                "and persisted before retrying."
            )
            sys.exit(1)
        print("✔ Confluence runbook update succeeded (key:", PAGE_KEY, ")")
    except subprocess.CalledProcessError as exc:
        print(
            "✖ Confluence runbook update FAILED (key:",
            PAGE_KEY,
            "). Exit code:",
            exc.returncode,
            file=sys.stderr,
        )
        print(
            "Run the docs-sync task to ensure page IDs are resolved "
            "and persisted before retrying."
        )
        sys.exit(exc.returncode)


if __name__ == "__main__":
    main()
