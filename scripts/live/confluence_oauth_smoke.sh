#!/usr/bin/env bash
# Opt-in smoke script for Confluence Phase 1 browser OAuth + read-only tool call
# Safe for public repos: no secrets printed; exits non-zero on config errors.

set -euo pipefail

###############################################################################
# Helpers
###############################################################################
abort() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

need_var() {
  local name="$1"
  [[ -n "${!name-}" ]] || abort "Missing required env var: $name"
}

generate_link_code() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    python - <<'PY'
import uuid, sys; sys.stdout.write(str(uuid.uuid4()))
PY
  fi
}

run_mcp_call() {
  local args=("$@")
  if [[ -f scripts/.env.script-helpers ]]; then
    python scripts/mcp_call.py "${args[@]}" --env-file scripts/.env.script-helpers
  else
    python scripts/mcp_call.py "${args[@]}"
  fi
}

###############################################################################
# Required configuration
###############################################################################
need_var MCP_PUBLIC_BASE_URL
need_var MCP_URL

: "${MCP_LINK_CODE:=$(generate_link_code)}"
export MCP_LINK_CODE  # ensure helper picks it up

printf 'Using link code: %s\n\n' "${MCP_LINK_CODE}"

start_url="${MCP_PUBLIC_BASE_URL}/auth/confluence/start?code=${MCP_LINK_CODE}"
printf 'Open this URL in your browser and complete OAuth:\n%s\n\n' "${start_url}"
read -rp 'Press Enter after completing authentication... '

###############################################################################
# List available tools (read-only expected)
###############################################################################
printf '\n=== tools/list ===\n'
run_mcp_call --rpc-method tools/list

###############################################################################
# Prompt for a safe read-only Confluence tool
###############################################################################
default_tool='confluence_search'
read -rp "Enter read-only Confluence tool to invoke [${default_tool}]: " tool_name
tool_name="${tool_name:-$default_tool}"

default_args='{"query":"type=page ORDER BY created DESC","limit":3}'
read -rp "Enter JSON args (leave blank for ${default_args}): " args_json
args_json="${args_json:-$default_args}"

printf '\n=== Invoking %s ===\n' "${tool_name}"
run_mcp_call --tool "${tool_name}" --args-json "${args_json}"
