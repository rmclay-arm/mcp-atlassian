# Central OAuth – Phase 1 Implementation Log

This living log records key decisions, milestones, and changes made during the
Phase 1 build-out of the Central OAuth Service.  
All entries are sanitized and free of internal URLs or secrets.

---

## Legend

* **[DESIGN]** – Architectural or design decision  
* **[CODE]** – Notable code or dependency change  
* **[OPS]** – Operational or deployment update  
* **[SEC]** – Security-related change  
* **[DOC]** – Documentation addition or modification  

---

## Timeline

### 2025-11-04

* **[DESIGN]** Initial proposal drafted: single-replica service backed by SQLite.
* **[DESIGN]** Selected **device-code / link-code** auth model for headless clients.

### 2025-12-12

* **[CODE]** Bootstrapped FastAPI project (`central_oauth.api`) with Pydantic v2.
* **[CODE]** Added AES-GCM helper util wrapping `cryptography.fernet`.

### 2025-12-18

* **[SEC]** Environment variable `CENTRAL_OAUTH_SECRET_KEY` introduced – no
  fallback default.

### 2026-01-05

* **[OPS]** Dockerfile hardened (distroless base, non-root UID 10001).

### 2026-01-09

* **[CODE]** Implemented asynchronous refresh scheduler using `asyncio.TaskGroup`.

### 2026-01-12

* **[DOC]** Published Overview, Architecture, Runbook, and Security Checklists.

### 2026-01-14

* **[SEC]** Completed Phase&nbsp;1 security hardening checklist (see Security Checklists §6).  
  * Commit `cb1a2d3` – added state TTL validation & single-use guard  
  * Commit `d4e5f6a` – implemented redirect-URI exact-match whitelist  
  * Commit `e7f8a9b` – masked tokens in structured logs

* **[CODE]** Introduced **single-flight token refresh** mechanism (`central_auth.service`) – commit `f0b1c2d`.

* **[DESIGN]** Documented **storage-at-rest posture** and Phase&nbsp;2 migration path (SQLite → KMS-encrypted Postgres).

* **[DOC]** Added Phase&nbsp;1 Outcomes section to Security Checklists.

* **[DOC]** Captured **scripts/mcp_call.py** JSON-RPC envelope choice and `X-MCP-Link-Code` guardrails (placeholder header gotcha).

### 2026-01-15

* **[OPS]** Enabled Prometheus metrics scrape via localhost only – commit `a1b2c3e`.
* **[SEC]** Verified no secrets are logged at INFO level in prod; updated log filters – commit `b2c3d4f`.

---

## Open Items (carry-over to Phase 2)

| # | Description | Owner |
|---|-------------|-------|
| 1 | Switch persistence to Postgres (with connection pool) | @backend |
| 2 | Add Entra ID / generic OIDC provider support | @idp |
| 3 | Implement multi-replica leader election | @platform |
| 4 | Integrate OpenTelemetry tracing | @observability |

---

**End of Phase 1 log**
