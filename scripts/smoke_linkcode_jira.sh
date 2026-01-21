#!/usr/bin/env bash
# Deterministic link-code smoke test (Jira only).
#
# Behaviour changes (2026-01-20):
#   • Always mints a **new** link code – no MCP_LINK_CODE env required.
#   • Persists run artefacts under .project-local/smoke/
#   • Detects needs_reauth and prints browser URL, exits non-zero.
#   • Asserts issue summary when SMOKE_EXPECT_SUMMARY is set.
#
# Required env vars:
#   MCP_URL                  # e.g. http://localhost:9010/mcp
#
# Optional env vars:
#   MCP_PUBLIC_BASE_URL      # Public base URL if MCP_URL is private
#   JIRA_SMOKE_ISSUE_KEY     # PROJ-123 etc. Defaults to EXPL-777
#   SMOKE_EXPECT_SUMMARY     # Exact expected summary for assertion
#   SMOKE_EXPECT_DESCRIPTION_SUBSTR  # Description must contain substring
#
# Exit code 0 on success, non-zero on any failure.

set -euo pipefail

fail() { echo "❌ $1" >&2; exit 1; }
pass() { echo "✅ $1"; }

# ----------------------- Pre-flight -----------------------
[[ -z "${MCP_URL:-}" ]] && fail "MCP_URL is required"

ISSUE_KEY="${JIRA_SMOKE_ISSUE_KEY:-EXPL-777}"
# Set default expectations for well-known smoke issue
if [[ "${ISSUE_KEY}" == "EXPL-777" ]]; then
  : "${SMOKE_EXPECT_SUMMARY:=DS5 PCE??????}"
  : "${SMOKE_EXPECT_DESCRIPTION_SUBSTR:=Here is a test description.}"
fi
BASE_URL="${MCP_PUBLIC_BASE_URL:-${MCP_URL%/mcp}}"
SMOKE_DIR=".project-local/smoke"
mkdir -p "${SMOKE_DIR}"

command -v jq >/dev/null 2>&1 || fail "jq is required but not installed"

# ----------------------- Mint link code -------------------
echo "⏳ Minting new link code …"
LINK_JSON="$(curl -sSf "${BASE_URL}/auth/link/new")" || fail "Failed to call /auth/link/new"
MCP_LINK_CODE="$(echo "${LINK_JSON}" | jq -r '.link_code')"
[[ -n "${MCP_LINK_CODE}" && "${MCP_LINK_CODE}" != "null" ]] || fail "Invalid link_code in response"
echo "${MCP_LINK_CODE}" > "${SMOKE_DIR}/link_code.txt"
pass "link_code minted $(echo "${MCP_LINK_CODE}" | sed 's/.\{8\}$/********/')"

# ----------------------- tools/list -----------------------
echo "⏳ tools/list (link-code) …"
LIST_JSON="$(
  MCP_LINK_CODE="${MCP_LINK_CODE}" \
  uv run python scripts/mcp_call.py --rpc-method tools/list --args-json '{}' --no-cache
)"
echo "${LIST_JSON}" | jq -e '(.isError // false) == false' >/dev/null || {
  # Reauth could trigger here as well
  if echo "${LIST_JSON}" | jq -e '.error?.error?=="needs_reauth"' >/dev/null 2>&1; then
    echo "🔑 Re-auth required – open in browser:"
    echo "   ${BASE_URL}/auth/jira/start?link_code=${MCP_LINK_CODE}"
    if [[ "${SMOKE_INTERACTIVE:-0}" == "1" ]]; then
      read -rp "➡️  Complete auth then press Enter to retry…"
      # Retry once
      ISSUE_RESP="$(
        MCP_LINK_CODE="${MCP_LINK_CODE}" \
        uv run python scripts/mcp_call.py \
          --tool jira_get_issue \
          --args-json "${ARGS_JSON}" \
          --no-cache
      )"
      echo "${ISSUE_RESP}" > "${SMOKE_DIR}/jira_get_issue.json"
      echo "${ISSUE_RESP}" | jq -e '(.isError // false) == false' >/dev/null || \
        fail "jira_get_issue still failing after retry"
    else
      exit 1
    fi
  fi
  fail "tools/list responded with isError=true"
}
echo "${LIST_JSON}" > "${SMOKE_DIR}/tools_list.json"
pass "tools/list isError=false"

# ----------------------- jira_get_issue -------------------
echo "⏳ jira_get_issue ${ISSUE_KEY} …"
ARGS_JSON="$(jq -nc --arg k "${ISSUE_KEY}" '{issue_key:$k,"fields":"summary,description"}')"
ISSUE_RESP="$(
  MCP_LINK_CODE="${MCP_LINK_CODE}" \
  uv run python scripts/mcp_call.py \
    --tool jira_get_issue \
    --args-json "${ARGS_JSON}" \
    --no-cache
)"

# Save raw response before any parsing
echo "${ISSUE_RESP}" > "${SMOKE_DIR}/jira_get_issue.json"

# ----------------------- Reauth detection -----------------
if echo "${ISSUE_RESP}" | jq -e '(.isError // false) == true' >/dev/null 2>&1; then
  if echo "${ISSUE_RESP}" | jq -e '.error?.error?=="needs_reauth"' >/dev/null 2>&1; then
    echo "🔑 Re-auth required – open in browser:"
    echo "   ${BASE_URL}/auth/jira/start?link_code=${MCP_LINK_CODE}"
    if [[ "${SMOKE_INTERACTIVE:-0}" == "1" ]]; then
      read -rp "➡️  Complete auth then press Enter to retry…"
      ISSUE_RESP="$(
        MCP_LINK_CODE="${MCP_LINK_CODE}" \
        uv run python scripts/mcp_call.py \
          --tool jira_get_issue \
          --args-json "${ARGS_JSON}" \
          --no-cache
      )"
      echo "${ISSUE_RESP}" > "${SMOKE_DIR}/jira_get_issue.json"
      echo "${ISSUE_RESP}" | jq -e '(.isError // false) == false' >/dev/null || \
        fail "jira_get_issue still failing after retry"
    else
      exit 1
    fi
  fi
  fail "jira_get_issue responded with isError=true"
fi
pass "jira_get_issue isError=false"

# ----------------------- Extract payload ------------------
# Handle both content-shape variants
extract_payload() {
  jq -c '
    if .result? then .result
    elif (.result.content? and (.result.content | type=="array")) then
      (
        (.result.content[]? | select(.type=="json") | .json?) //
        ((.result.content[]? | select(.type=="text") | .text?) | fromjson?)
      )
    else empty end
  '
}

PAYLOAD="$(echo "${ISSUE_RESP}" | extract_payload)"
[[ -n "${PAYLOAD}" ]] || fail "Unable to extract issue payload"

SUMMARY=$(echo "${PAYLOAD}" | jq -r '.summary // .fields.summary // empty')
DESCRIPTION=$(echo "${PAYLOAD}" | jq -r '.description // .fields.description // empty')
# Empty summary indicates bad fetch – treat as failure
[[ -z "${SUMMARY}" ]] && fail "Summary is empty – fetch failed? (see ${SMOKE_DIR}/jira_get_issue.json)"

# ----------------------- Assertions ----------------
fail_with_artifacts() {
  local reason="$1"
  echo "❌ ${reason}" >&2
  echo "   summary: ${SUMMARY:-<empty>}" >&2
  if [[ -n "${SMOKE_EXPECT_DESCRIPTION_SUBSTR:-}" ]]; then
    echo "   description matched: ${2:-no}" >&2
  fi
  echo "   artefact: ${SMOKE_DIR}/jira_get_issue.json" >&2
  exit 1
}

# Assert summary
if [[ -n "${SMOKE_EXPECT_SUMMARY:-}" ]]; then
  [[ "${SUMMARY}" == "${SMOKE_EXPECT_SUMMARY}" ]] || \
    fail_with_artifacts "Summary mismatch (expected '${SMOKE_EXPECT_SUMMARY}', got '${SUMMARY}')"
fi

# Assert description substring
if [[ -n "${SMOKE_EXPECT_DESCRIPTION_SUBSTR:-}" ]]; then
  if grep -Fq "${SMOKE_EXPECT_DESCRIPTION_SUBSTR}" <<<"${DESCRIPTION}"; then
    : # match ok
  else
    fail_with_artifacts "Description does not contain expected substring" "no"
  fi
fi

# ----------------------- Human-readable output -------------
echo "${ISSUE_KEY}: ${SUMMARY}"
echo "🔎 Description (first 10 lines):"
echo "${DESCRIPTION}" | head -n 10

echo "🎉 Link-code smoke test PASSED"
