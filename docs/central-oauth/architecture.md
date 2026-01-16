# Central OAuth – Architecture

This document describes the **internal architecture** of the Central OAuth Service
as delivered in **Phase 1**.  
It is intentionally vendor-neutral and free of environment-specific details.

---

## High-Level Component Diagram

```text
┌──────────────────────────────────────────────────────────┐
│                   Central OAuth Service                 │
│ ┌──────────────┐  ┌───────────────────────────────────┐ │
│ │  API Layer   │  │      Token Management Core       │ │
│ │ (FastAPI)    │  │  • Device-code coordinator       │ │
│ │              │  │  • Refresh scheduler (async)     │ │
│ └──────────────┘  │  • AES-GCM encryption helpers    │ │
│        │          └───────────────────────────────────┘ │
│        ▼                  ▲                              │
│ ┌──────────────┐          │                              │
│ │ Persistence  │──────────┘                              │
│ │  (SQLite 3)  │                                         │
│ └──────────────┘                                         │
└──────────────────────────────────────────────────────────┘
```

* **API Layer** – Exposes REST endpoints; validates input/output with
  Pydantic models.

* **Token Management Core** – Implements device-code flow, link-code binding,
  secure storage, automatic refresh, and revocation logic.

* **Persistence** – Single SQLite database file; path configured by
  `CENTRAL_OAUTH_DB_PATH`.

---

## Database Schema (Phase 1)

| Table | Purpose |
|-------|---------|
| `accounts` | Stores remote account metadata (`account_id`, `display_name`, etc.) |
| `tokens` | Encrypted access / refresh tokens linked to `account_id` |
| `device_codes` | Active link-codes awaiting user verification |

Primary keys are integer autoincrement.  
All sensitive columns (`access_token`, `refresh_token`) are encrypted at rest
using AES-GCM with a key supplied via `CENTRAL_OAUTH_SECRET_KEY`.

---

## Link-Code Binding Model

1. **Client** requests `POST /v1/link-code`.  
   The service generates:  
   • `link_code` (numeric, short lived)  
   • `verification_url` (e.g. `https://auth.example.com/device`)  
2. **User** opens the `verification_url`, enters the `link_code`, and completes
   OAuth consent in the browser.  
3. **Service** exchanges the device code for tokens and persists them.  
4. **Client** polls `GET /v1/poll/:link_code` until success or timeout.

This model decouples non-interactive clients (CLI/CI) from browser authentication
while avoiding inbound callbacks.

---

## Deployment Topology

Phase 1 is limited to **one replica**. Horizontal scaling is postponed until
state sharing (e.g. Postgres or KMS) is added.

Typical container run command:

```bash
docker run -d \
  -e CENTRAL_OAUTH_DB_PATH=/data/db.sqlite3 \
  -e CENTRAL_OAUTH_SECRET_KEY=<32-byte-hex> \
  -v central-oauth-data:/data \
  -p 8080:8080 \
  ghcr.io/your-org/central-oauth:latest
```

* The volume `central-oauth-data` retains the SQLite file across restarts.  
* Health probe endpoint: `GET /v1/healthz`.

---

## Future (Phase 2+) Preview

| Capability | Status |
|------------|--------|
| Entra / OIDC provider support | Planned |
| Postgres + connection pool | Planned |
| Multi-replica / leader-election | Planned |
| Metrics & tracing (OpenTelemetry) | Planned |
