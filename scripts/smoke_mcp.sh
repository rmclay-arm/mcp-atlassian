#!/usr/bin/env bash
# Lightweight smoke-test for a running MCP Atlassian streamable-HTTP server.
#
# Required env vars:
#   MCP_URL                # https://central.example.com/mcp
#   JIRA_AUTH_HEADER       # "Bearer abc123" | "Token abc123"
#   CONFLUENCE_AUTH_HEADER # "Bearer def456" | "Token def456"
#
# Optional env vars:
#   JIRA_CLOUD_ID          # uuid-like
#   CONFLUENCE_CLOUD_ID    # uuid-like
#   HANDSHAKE_ONLY=1       # run initialize → tools/list then exit
#
# Exit code 0 on success, non-zero on any failure.
set -euo pipefail

fail() { echo "❌ $1" >&2; exit 1; }
pass() { echo "✅ $1"; }

# Basic env checks
[[ -z "${MCP_URL:-}" ]] && fail "MCP_URL is required"

# Determine which services are enabled (at least one required)
JIRA_ENABLED=0
CONF_ENABLED=0
[[ -n "${JIRA_AUTH_HEADER:-}" ]]       && JIRA_ENABLED=1
[[ -n "${CONFLUENCE_AUTH_HEADER:-}" ]] && CONF_ENABLED=1
(( JIRA_ENABLED || CONF_ENABLED )) || fail "At least one of JIRA_AUTH_HEADER or CONFLUENCE_AUTH_HEADER must be set"

# Ensure jq is available for JSON parsing (required for schema-driven smoke test)
command -v jq >/dev/null 2>&1 || fail "jq is required but not installed"

########################################
# Helper utilities
########################################

# Extract the first JSON payload from a SSE response.
# Takes stdin, prints JSON on stdout.
extract_sse_json() {
  grep -m1 '^data:' | sed 's/^data: //'
}

# Abort if the JSON payload contains "isError": true
ensure_no_is_error() {
  local json="$1"
  if echo "${json}" | grep -q '"isError":[[:space:]]*true'; then
    fail "Server reported isError=true → ${json}"
  fi
}

normalize_auth_header() {
  local v="$1"
  if [[ "${v}" =~ ^(Token|Bearer)[[:space:]]+.+$ ]]; then
    printf '%s' "${v}"
  else
    # Assume raw PAT; do not print it, just prefix it.
    printf 'Token %s' "${v}"
  fi
}

########################################
# Common headers
########################################
BASE_HEADERS=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
)

########################################
# Normalize headers (only for services in use)
########################################
if (( JIRA_ENABLED )); then
  JIRA_AUTH_HEADER="$(normalize_auth_header "${JIRA_AUTH_HEADER}")"
fi
if (( CONF_ENABLED )); then
  CONFLUENCE_AUTH_HEADER="$(normalize_auth_header "${CONFLUENCE_AUTH_HEADER}")"
fi

########################################
# 0. initialize → obtain session id
########################################
echo "⏳ Initializing MCP session …"
TMP_HEADERS="$(mktemp)"

INIT_PAYLOAD='{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "clientInfo": { "name": "smoke-script", "version": "0.1.0" },
    "capabilities": {}
  }
}'

INIT_HEADERS=(
  "${BASE_HEADERS[@]}"
)
if (( JIRA_ENABLED )); then
  INIT_HEADERS+=( -H "X-Jira-Authorization: ${JIRA_AUTH_HEADER}" )
  [[ -n "${JIRA_CLOUD_ID:-}" ]] && INIT_HEADERS+=( -H "X-Jira-Cloud-Id: ${JIRA_CLOUD_ID}" )
fi
if (( CONF_ENABLED )); then
  INIT_HEADERS+=( -H "X-Confluence-Authorization: ${CONFLUENCE_AUTH_HEADER}" )
  [[ -n "${CONFLUENCE_CLOUD_ID:-}" ]] && INIT_HEADERS+=( -H "X-Confluence-Cloud-Id: ${CONFLUENCE_CLOUD_ID}" )
fi

INIT_RESP_AND_CODE=$(
  curl -sS -D "${TMP_HEADERS}" -w '\n%{http_code}' \
    -X POST "${MCP_URL}" \
    "${INIT_HEADERS[@]}" \
    -d "${INIT_PAYLOAD}"
)

INIT_HTTP_CODE="$(echo "${INIT_RESP_AND_CODE}" | tail -n1)"
INIT_RESP="$(echo "${INIT_RESP_AND_CODE}" | head -n -1)"

[[ "${INIT_HTTP_CODE}" == "200" ]] || { rm -f "${TMP_HEADERS}"; fail "initialize returned HTTP ${INIT_HTTP_CODE}"; }
echo "${INIT_RESP}" | grep -q '"error"' && { rm -f "${TMP_HEADERS}"; fail "initialize response contains error"; }

# Extract session id header (case-insensitive, strip CR)
SESSION_ID="$(
  grep -i '^mcp-session-id:' "${TMP_HEADERS}" | tr -d '\r' | awk '{print $2}'
)"
rm -f "${TMP_HEADERS}"
[[ -n "${SESSION_ID}" ]] || fail "initialize did not return mcp-session-id header"
pass "Session id obtained"
# Optionally print the session id so callers can re-use it
if [[ "${PRINT_SESSION_ID:-}" == "1" ]]; then
  echo "export SESSION_ID=${SESSION_ID}"
fi

########################################
# 0b. notifications/initialized
########################################
echo "⏳ Sending notifications/initialized …"
NOTIFY_HEADERS=(
  "${BASE_HEADERS[@]}"
  -H "mcp-session-id: ${SESSION_ID}"
)
if (( JIRA_ENABLED )); then
  NOTIFY_HEADERS+=( -H "X-Jira-Authorization: ${JIRA_AUTH_HEADER}" )
  [[ -n "${JIRA_CLOUD_ID:-}" ]] && NOTIFY_HEADERS+=( -H "X-Jira-Cloud-Id: ${JIRA_CLOUD_ID}" )
fi
if (( CONF_ENABLED )); then
  NOTIFY_HEADERS+=( -H "X-Confluence-Authorization: ${CONFLUENCE_AUTH_HEADER}" )
  [[ -n "${CONFLUENCE_CLOUD_ID:-}" ]] && NOTIFY_HEADERS+=( -H "X-Confluence-Cloud-Id: ${CONFLUENCE_CLOUD_ID}" )
fi

NOTIFY_HTTP_CODE=$(
  curl -sS -o /dev/null -w "%{http_code}" \
    -X POST "${MCP_URL}" \
    "${NOTIFY_HEADERS[@]}" \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
)
[[ "${NOTIFY_HTTP_CODE}" =~ ^2[0-9]{2}$ ]] || fail "notifications/initialized returned HTTP ${NOTIFY_HTTP_CODE}"
pass "notifications/initialized OK"

########################################
# 1. tools/list
########################################
echo "⏳ Listing tools …"
LIST_HEADERS=(
  "${BASE_HEADERS[@]}"
  -H "mcp-session-id: ${SESSION_ID}"
)
if (( JIRA_ENABLED )); then
  LIST_HEADERS+=( -H "X-Jira-Authorization: ${JIRA_AUTH_HEADER}" )
  [[ -n "${JIRA_CLOUD_ID:-}" ]] && LIST_HEADERS+=( -H "X-Jira-Cloud-Id: ${JIRA_CLOUD_ID}" )
fi
if (( CONF_ENABLED )); then
  LIST_HEADERS+=( -H "X-Confluence-Authorization: ${CONFLUENCE_AUTH_HEADER}" )
  [[ -n "${CONFLUENCE_CLOUD_ID:-}" ]] && LIST_HEADERS+=( -H "X-Confluence-Cloud-Id: ${CONFLUENCE_CLOUD_ID}" )
fi

LIST_RESP=$(
  curl -sS -N \
    -X POST "${MCP_URL}" \
    "${LIST_HEADERS[@]}" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
)
LIST_JSON="$(echo "${LIST_RESP}" | extract_sse_json)"
ensure_no_is_error "${LIST_JSON}"
pass "tools/list isError=false"

# ------------------------------------------------------------------------------
# DEBUG_SCHEMA support → dump tools/list + show searchable schemas
# ------------------------------------------------------------------------------
if [[ "${DEBUG_SCHEMA:-}" == "1" ]]; then
  echo "${LIST_JSON}" > /tmp/mcp-tools-list.json
  echo "📝 tools/list JSON persisted to /tmp/mcp-tools-list.json"
  TOOL_COUNT=$(echo "${LIST_JSON}" | jq '.result.tools | length')
  echo "ℹ️ Tool count: ${TOOL_COUNT}"
  if [[ "${TOOL_COUNT}" -eq 0 ]]; then
    echo "⚠️ tools/list returned an empty tools array – auth/config filtering?"
  fi
  for TOOL_NAME in jira_search confluence_search; do
    TOOL_JSON=$(echo "${LIST_JSON}" | jq -c --arg n "${TOOL_NAME}" '.result.tools[]? | select(.name==$n)')
    if [[ -n "${TOOL_JSON}" ]]; then
      echo "🔧 ${TOOL_NAME} schema:"
      echo "${TOOL_JSON}" | jq -r '
        "  required: \(.inputSchema.required // [])\n  properties: \(.inputSchema.properties | keys // [])"'
      echo "${TOOL_JSON}" | jq '.inputSchema'
    else
      echo "⚠️ Tool ${TOOL_NAME} not found"
    fi
  done
fi

# Helper: pick first matching property key from a list of candidates
choose_key() {
  local props_json="$1"; shift
  for cand in "$@"; do
    if echo "${props_json}" | jq -e --arg k "${cand}" 'has($k)' >/dev/null; then
      echo "${cand}"
      return 0
    fi
  done
  return 1
}

# Exit early if only the handshake is required
[[ "${HANDSHAKE_ONLY:-}" == "1" ]] && { echo "🎉 Handshake-only mode complete"; exit 0; }

########################################
# 2. jira_search (read-only, schema-driven)
########################################
if (( JIRA_ENABLED )); then
echo "⏳ Jira search …"

# Locate jira_search schema and determine correct argument keys
JIRA_SCHEMA=$(echo "${LIST_JSON}" | jq -c '.result.tools[]? | select(.name=="jira_search")')
[[ -n "${JIRA_SCHEMA}" ]] || fail "jira_search definition not found in tools/list – check service configuration or MCP_EXPOSE_TOOLS_WITHOUT_AUTH"

JIRA_PROPS=$(echo "${JIRA_SCHEMA}" | jq '.inputSchema.properties')
JIRA_QUERY_KEY=$(choose_key "${JIRA_PROPS}" jql query q) \
  || fail "Could not find query key for jira_search"
JIRA_LIMIT_KEY=$(choose_key "${JIRA_PROPS}" max_results maxResults limit max top) \
  || fail "Could not find limit key for jira_search"

JIRA_ARGS=$(jq -n \
  --arg qk  "${JIRA_QUERY_KEY}" \
  --arg qry "ORDER BY created DESC" \
  --arg lk  "${JIRA_LIMIT_KEY}" \
  --argjson lim 1 \
  '{($qk): $qry, ($lk): $lim}')

JIRA_HEADERS=(
  "${BASE_HEADERS[@]}"
  -H "mcp-session-id: ${SESSION_ID}"
  -H "X-Jira-Authorization: ${JIRA_AUTH_HEADER}"
)
[[ -n "${JIRA_CLOUD_ID:-}" ]] && JIRA_HEADERS+=( -H "X-Jira-Cloud-Id: ${JIRA_CLOUD_ID}" )

JIRA_PAYLOAD=$(jq -n --argjson a "${JIRA_ARGS}" '{
  jsonrpc:"2.0",
  id:3,
  method:"tools/call",
  params:{name:"jira_search",arguments:$a}
}')

JIRA_RESP=$(
  curl -sS -N \
    -X POST "${MCP_URL}" \
    "${JIRA_HEADERS[@]}" \
    -d "${JIRA_PAYLOAD}"
)
JIRA_JSON="$(echo "${JIRA_RESP}" | extract_sse_json)"
ensure_no_is_error "${JIRA_JSON}"
pass "jira_search isError=false"
fi

########################################
# 3. confluence_search (read-only, schema-driven)
########################################
if (( CONF_ENABLED )); then
echo "⏳ Confluence search …"

CONF_SCHEMA=$(echo "${LIST_JSON}" | jq -c '.result.tools[]? | select(.name=="confluence_search")')
[[ -n "${CONF_SCHEMA}" ]] || fail "confluence_search definition not found in tools/list – check service configuration or MCP_EXPOSE_TOOLS_WITHOUT_AUTH"

CONF_PROPS=$(echo "${CONF_SCHEMA}" | jq '.inputSchema.properties')
CONF_QUERY_KEY=$(choose_key "${CONF_PROPS}" cql query) \
  || fail "Could not find query key for confluence_search"
CONF_LIMIT_KEY=$(choose_key "${CONF_PROPS}" max_results maxResults limit max top) \
  || fail "Could not find limit key for confluence_search"

CONF_ARGS=$(jq -n \
  --arg qk  "${CONF_QUERY_KEY}" \
  --arg qry "type = page ORDER BY created DESC" \
  --arg lk  "${CONF_LIMIT_KEY}" \
  --argjson lim 1 \
  '{($qk): $qry, ($lk): $lim}')

CONF_HEADERS=(
  "${BASE_HEADERS[@]}"
  -H "mcp-session-id: ${SESSION_ID}"
  -H "X-Confluence-Authorization: ${CONFLUENCE_AUTH_HEADER}"
)
[[ -n "${CONFLUENCE_CLOUD_ID:-}" ]] && CONF_HEADERS+=( -H "X-Confluence-Cloud-Id: ${CONFLUENCE_CLOUD_ID}" )

CONF_PAYLOAD=$(jq -n --argjson a "${CONF_ARGS}" '{
  jsonrpc:"2.0",
  id:4,
  method:"tools/call",
  params:{name:"confluence_search",arguments:$a}
}')

CONF_RESP=$(
  curl -sS -N \
    -X POST "${MCP_URL}" \
    "${CONF_HEADERS[@]}" \
    -d "${CONF_PAYLOAD}"
)
CONF_JSON="$(echo "${CONF_RESP}" | extract_sse_json)"
ensure_no_is_error "${CONF_JSON}"
pass "confluence_search isError=false"
fi

echo "🎉 Smoke test PASSED"
