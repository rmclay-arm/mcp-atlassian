# Central OAuth – Runbook

This runbook provides **day-2 operational guidance** for the Central OAuth Service (Phase 1).  
All instructions are generic and free of internal URLs or secrets.

> **Publishing note:** Update this runbook in Confluence via  
> `scripts/publish_confluence_runbook.py` to avoid JSON-in-JSON escaping issues.

---

## Browser-based OAuth Flow (Phase 1)

The Central OAuth Service exposes a **browser-based device flow** under a configurable
base path (default `/auth`).  
If you run the MCP server behind a reverse-proxy you may remap the path at
application bootstrap:

```python
from mcp_atlassian.servers.main import main_mcp
from mcp_atlassian.servers.auth import register_auth_routes

register_auth_routes(main_mcp, base_path="/custom/auth")   # override example
```

### Endpoints

Method | Path | Purpose
-------|------|--------
`GET` | `{base}/link/new` | Generate a one-time **link code** that binds a headless client to a browser session.
`GET` | `{base}/{jira&#124;confluence}/start?instance=<id>&redirect_uri=<url>` | Build the provider **authorize_url** that the browser should visit.
`GET` | `{base}/{jira&#124;confluence}/callback?code=…&state=…` | OAuth redirect target. Returns a minimal success/failure HTML page (no secrets).
`GET` | `{base}/status?instance=<id>` | Poll binding / token status for an instance.
`POST` | `{base}/{jira&#124;confluence}/disconnect` (JSON `{"instance": "<id>"}`) | Revoke and delete stored tokens.

### Binding Header (Link Code)

All subsequent **tool calls** must include a binding header that links the
request to the authorised account:

```
Header: X-MCP-Link-Code: <link_code>
```

The header name is configurable via the environment variable
`MCP_LINK_HEADER_NAME` (default `X-MCP-Link-Code`).  
The server resolves the link code to an OAuth access token and injects it
automatically. The header value never leaves the server.

> **Note:** The **effective identity** for any tool call is determined by which authentication header path is used—either the link-code header or direct product-specific auth headers. Permissions are evaluated against that effective identity.

### Flow sequence

1. **Client** requests `GET {base}/link/new` → receives `link_code`.
2. **Client** opens browser to  
   `{base}/{product}/start?instance=<id>&redirect_uri=<callback>`  
   and follows the returned `authorize_url`.
3. Atlassian completes OAuth and redirects to  
   `{base}/{product}/callback` which shows *Authorization successful/failed*.
4. **Client** polls `GET {base}/status?instance=<id>` until tokens are **READY**.
5. Subsequent **tool calls** include  
   `X-MCP-Link-Code: <link_code>` and succeed automatically.  
   Tokens are refreshed transparently by the server.
6. If a call returns **NeedsReauth** (see below), repeat the browser flow.
7. Optional: `POST {base}/{product}/disconnect` removes stored credentials.

### NeedsReauth Response

When an access token has expired or been revoked **and** cannot be refreshed,
the server responds to tool calls with HTTP `412 Precondition Failed` and a JSON
body like:

```json
{
  "error": "NeedsReauth",
  "instance": "<id>",
  "product": "jira",
  "auth_url": "/auth/jira/start?instance=<id>&redirect_uri=<callback>"
}
```

Clients should open `auth_url` in a browser, complete the OAuth flow, and then
resume polling `/status` until the instance reports **READY**.

### Correlation IDs

Every HTTP request is tagged with an `X-Correlation-ID` header (random UUID4 if
absent). The value is echoed in the response and injected into structured logs,
allowing end-to-end tracing without exposing secrets.

### Storage

Tokens and transient state are stored on disk by **DiskAuthStore**.  
Directory is controlled by env `MCP_AUTH_STORAGE_DIR` (default
`~/.mcp-atlassian/auth`). When containerised, mount this path as a **persistent
volume**.

## 1. Service Lifecycle

| Action | Command (container example) | Notes |
|--------|-----------------------------|-------|
| **Start** | `docker compose up -d` | Compose file should mount persistent volume at `/data` |
| **Stop** | `docker compose down` | Graceful shutdown; background refresh tasks exit cleanly |
| **Restart** | `docker compose restart central-oauth` | Uses built-in health check to confirm readiness |
| **Upgrade** | Pull new image, then `docker compose up -d --pull=always` | Schema migrations run automatically |

---

## 2. Health & Monitoring

Endpoint | Purpose | Expected HTTP
---------|---------|-------------
`GET /v1/healthz` | Liveness probe | `200 OK`
`GET /v1/metrics` *(optional)* | Prometheus metrics | `200 OK`

Integrate these endpoints with your platform’s health monitoring (e.g. Kubernetes `livenessProbe`).

---

## 3. Common Operational Tasks

### 3.1 Rotate Encryption Key

1. **Set** new `CENTRAL_OAUTH_SECRET_KEY` value (32-byte hex).  
2. Start service with both **old** and **new** keys in `CENTRAL_OAUTH_KEY_RING` (comma-separated).  
3. Run `POST /v1/admin/re-encrypt` to rewrite token rows with the newest key.  
4. Remove old key from configuration.

### 3.2 Backup Database

```bash
# Offline backup (service stopped)
cp /data/db.sqlite3 /backups/central-oauth-$(date -I).sqlite3
```

For live backups, use `sqlite3 .backup` API or file-system snapshots.

### 3.3 Restore Database

1. Stop the service.  
2. Replace `/data/db.sqlite3` with desired backup file.  
3. Start the service and watch logs for automatic migrations.

### 3.4 Revoke a Compromised Account

```bash
curl -X DELETE https://oauth.example.com/v1/tokens/{account_id}
```

Tokens are deleted atomically; subsequent requests will require re-authorisation.

---

## 4. Incident Response

| Scenario | Immediate Steps |
|----------|-----------------|
| **Service Down** | Check container logs (`docker logs central-oauth`). Verify volume mount and DB path. |
| **DB Corruption** | Restore last known-good backup, then re-run migrations. |
| **Token Leak** | Revoke affected accounts, rotate encryption key, audit access logs. |
| **High Latency** | Validate SQLite journal mode (`WAL` recommended). Review host IO performance. |

---

## 5. Configuration Reference (Env Vars)

Variable | Default | Description
---------|---------|------------
`CENTRAL_OAUTH_DB_PATH` | `/var/lib/central-oauth/db.sqlite3` | Location of SQLite file
`CENTRAL_OAUTH_SECRET_KEY` | *none* | 32-byte hex used for AES-GCM
`CENTRAL_OAUTH_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`
`CENTRAL_OAUTH_KEY_RING` | *same as SECRET* | Comma list of active keys (newest first)  
`MCP_AUTH_STORAGE_DIR` | `~/.mcp-atlassian/auth` | Base directory for on-disk token store (`DiskAuthStore`)

---

## 6. Disaster Recovery Checklist

- [ ] Confirm backups run daily and are tested monthly.  
- [ ] Store encryption keys in a secure secret manager.  
- [ ] Document manual token re-authorisation steps for critical services.  
- [ ] Periodically test restore procedure in a staging environment.

---

_End of Runbook_
