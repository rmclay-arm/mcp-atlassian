# Live OAuth Smoke Scripts

These **opt-in** scripts exercise Phase 1 **browser OAuth** flow against a running
MCP-Atlassian server and then perform **read-only** tool calls using an
`X-MCP-Link-Code` header.

The scripts are **safe** for public repositories:
- **No tokens, secrets or internal URLs are committed.**
- All authentication details are supplied via **environment variables** at
  runtime.
- Only **read-only** MCP tools are invoked.

---

## Prerequisites

1. A running MCP-Atlassian server that has OAuth configured  
   (e.g. `uv run mcp-atlassian`).
2. A shell with `bash`, `curl`, `python` (via `uv`) and, ideally, `uuidgen`.
3. The helper env file copied once:

```bash
cp scripts/.env.script-helpers.example scripts/.env.script-helpers
# edit the copy if you want to pre-declare extra headers
```

---

## Required environment variables

| Variable                    | Example value                 | Purpose                                           |
|-----------------------------|-------------------------------|---------------------------------------------------|
| `MCP_PUBLIC_BASE_URL`       | `http://localhost:9000`       | Base URL the browser will hit                     |
| `MCP_URL`                   | `http://localhost:9000/mcp`   | JSON-RPC endpoint consumed by `mcp_call.py`       |
| `MCP_LINK_CODE` *(optional)*| `123e4567-e89b-12d3-a456...`  | Pre-generated link code. Script autogenerates one if unset |

**Never** commit real values—use placeholders only.

---

## How the flow works

1. **Link code generation**  
   The script will **generate** a random UUID (unless `MCP_LINK_CODE` is
   pre-exported) and **print** it for your reference.  
   The MCP server must accept this value when the browser completes OAuth.

2. **Start URL**  
   Open the printed URL in your browser:

```
${MCP_PUBLIC_BASE_URL}/auth/<service>/start?code=${MCP_LINK_CODE}
```

   Replace `<service>` with `jira` or `confluence`.

3. **Complete OAuth**  
   Sign in with your Atlassian account and grant access.  
   When the browser shows “Success” you may return to the terminal.

4. **Smoke calls**  
   The script first runs:

```bash
python scripts/mcp_call.py --rpc-method tools/list
```

   to list available tools, then prompts you to choose a **read-only** tool and
   (optionally) its JSON args. A convenience default is provided.

---

## Quickstart

```bash
# 1) Export required vars
export MCP_PUBLIC_BASE_URL="http://localhost:9000"
export MCP_URL="http://localhost:9000/mcp"

# 2) Run Jira smoke script (uses bash)
bash scripts/live/jira_oauth_smoke.sh
```

Follow the on-screen instructions. A similar script exists for Confluence:

```bash
bash scripts/live/confluence_oauth_smoke.sh
```

---

## Troubleshooting

| Symptom                              | Likely cause & fix                            |
|--------------------------------------|-----------------------------------------------|
| “Missing MCP_PUBLIC_BASE_URL”        | Export the env var before running the script. |
| Browser shows error after OAuth      | Check server logs; ensure link code matches.  |
| `tools/list` returns auth error      | OAuth not completed or wrong link code header.|
| Validation error calling a tool      | Re-run script and choose another read-only tool.|

---

## Safety notes

- Scripts **exit non-zero** with a helpful message if required env vars are
  missing.
- Auth header **values are never echoed**—only header names are displayed.
- All read-only calls use `scripts/mcp_call.py`, which enforces JSON-RPC
  envelope handling and basic SSE parsing without leaking secrets.

Enjoy your smoke-testing! 🎉
