# Central OAuth – Overview

This documentation set describes the **Central OAuth Service** used by Model Context Protocol (MCP) integrations.  
It is intentionally product-agnostic and contains **no internal or environment-specific URLs or secrets**.  
Replace any placeholders (e.g. `https://jira.example.com`) with values appropriate to your deployment **outside the repository**.

---

## Purpose

The Central OAuth Service provides a single place to manage OAuth credentials for Atlassian-based tools (Jira, Confluence, etc.).  
Clients obtain short-lived access tokens from this service instead of handling OAuth flows independently.

---

## Phase 1 Constraints

| Area | Constraint |
|------|------------|
| Identity provider | **No Entra ID / generic OIDC yet** (planned for Phase 2) |
| Storage | Local filesystem path – single **SQLite 3** database file |
| Deployment | **Single replica** only (stateless options postponed) |
| High availability | None (handled at platform layer if required) |
| Secrets | Managed via environment variables or container secrets – *never* hard-coded |

These constraints simplify the initial rollout and allow rapid iteration.

---

## Planned REST Endpoints (Phase 1)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/link-code` | Start device-code flow; returns numeric **link-code** and verification URL |
| `GET`  | `/v1/poll/:link_code` | Client polls until code exchange completes; returns access token payload |
| `DELETE` | `/v1/tokens/:account_id` | Revoke all stored tokens for an account |
| `GET`  | `/v1/healthz` | Liveness probe |

The **link-code binding model** decouples headless CLI clients from browser-based authorization.  
Tokens are stored encrypted (SQLite, AES-GCM) and can be refreshed transparently.

---

## Deployment at a Glance

```text
+-------------+          +----------------------+          +------------------------+
| MCP Client  | <—HTTP—> | Central OAuth Service | <—OAuth—> | Atlassian Cloud (Jira) |
+-------------+          +----------------------+          +------------------------+
       ^                                                             
       | Device-code & tokens                                        
       |                                                             
       +——— CLI / CI pipelines                                        
```

---

## Operational Notes

* **Storage path**: Define `CENTRAL_OAUTH_DB_PATH` to override the default (`/var/lib/central-oauth/db.sqlite3`).  
  In containerized deployments, mount a Docker volume to this location to persist tokens.

* **Configuration** is exclusively via environment variables to simplify twelve-factor compliance.

* **Logging** follows JSON lines to `stdout`; adjust log level with `CENTRAL_OAUTH_LOG_LEVEL`.

* **Upgrading**: Schema migrations are handled automatically on startup using `PRAGMA user_version`.

---

### Next Steps

See additional documents in this folder for architecture details, runbook procedures, security checklists, and the implementation changelog for Phase 1.
