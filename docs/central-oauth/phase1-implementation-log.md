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
