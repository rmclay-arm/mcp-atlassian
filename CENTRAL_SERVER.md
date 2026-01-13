# Central Deployment Guide

Run **MCP Atlassian** as a **stateless, multi-tenant HTTP service**.  
User credentials are **never stored** on the server – every request carries the
caller’s Jira / Confluence token(s) in HTTP headers.

---

## 1. Header Contract

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Jira-Authorization` | `Bearer <OAuthToken>` &#124; `Token <PAT>` | Jira OAuth 2.0 access-token **or** Personal Access Token |
| `X-Confluence-Authorization` | `Bearer <OAuthToken>` &#124; `Token <PAT>` | Confluence OAuth 2.0 access-token **or** PAT |
| `X-Jira-Cloud-Id` | *uuid-like* | **Optional** – Cloud-ID for the Jira site |
| `X-Confluence-Cloud-Id` | *uuid-like* | **Optional** – Cloud-ID for the Confluence site |

Backward-compatibility:

* If the product-specific auth headers are omitted the legacy  
  `Authorization` header is used for **both** Jira *and* Confluence.
* If the product-specific cloud-ID headers are omitted the legacy  
  `X-Atlassian-Cloud-Id` header is used.

---

## 2. Required Environment Variables on the Server

Even in central mode the server still needs base URLs in order to build
API routes, perform SSL verification, etc.

| Variable | Example | Notes |
|----------|---------|-------|
| `JIRA_URL` | `https://your-company.atlassian.net` | Base URL (no trailing slash) |
| `CONFLUENCE_URL` | `https://your-company.atlassian.net/wiki` | Base URL (no trailing slash) |
| TLS | `REQUESTS_CA_BUNDLE=/etc/ssl/certs/custom-ca.pem` | **Optional** – custom CA / mTLS |
| Proxy | `HTTPS_PROXY=https://proxy.local:3128` | **Optional** – corporate proxy |

> The server **never** needs user-specific usernames, API tokens or OAuth
> secrets in this model.

---

## 3. Example `curl` Session

```bash
# List available tools (JSON-RPC)
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-Jira-Authorization:  Bearer ${JIRA_TOKEN}" \
  -H "X-Confluence-Authorization: Token  ${CONFLUENCE_PAT}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Invoke a Jira READ tool (safe):
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-Jira-Authorization:  Bearer ${JIRA_TOKEN}" \
  -d '{"tool":"jira_search","arguments":{"jql":"assignee = currentUser()"}}'

# Invoke a Confluence READ tool (safe):
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-Confluence-Authorization: Token ${CONFLUENCE_PAT}" \
  -d '{"tool":"confluence_search","arguments":{"cql":"type = page ORDER BY created DESC"}}'
```

---

## 4. Running the Server Centrally

```bash
# 1) Install (one-off)
uvx mcp-atlassian --python=3.12 -- --version   # prints version

# 2) Start the service (stateless HTTP, port 9000)
JIRA_URL="https://your-domain.atlassian.net" \
CONFLUENCE_URL="https://your-domain.atlassian.net/wiki" \
uvx mcp-atlassian \
  --transport streamable-http \
  --stateless \
  --port 9000 \
  -vv
```

* The server exposes `/mcp` (streamable-HTTP) and `/healthz` (readiness probe).
* Deploy behind an HTTPS reverse proxy (nginx / Ingress) for TLS termination.

---

## 5. Smoke Test

A ready-made script lives at `scripts/smoke_mcp.sh`.  
Set the environment variables and run:

```bash
export MCP_URL="https://central.example.com/mcp"
export JIRA_AUTH_HEADER="Bearer <user-oauth-token>"
export CONFLUENCE_AUTH_HEADER="Token <user-pat>"
./scripts/smoke_mcp.sh
```

The script performs:

1. `tools/list`
2. `jira_search` (read-only)
3. `confluence_search` (read-only)

and prints a concise **SUCCESS/FAIL** report without leaking tokens.

---
