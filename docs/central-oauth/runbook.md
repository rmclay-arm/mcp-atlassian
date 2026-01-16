# Central OAuth – Runbook

This runbook provides **day-2 operational guidance** for the Central OAuth Service (Phase 1).  
All instructions are generic and free of internal URLs or secrets.

---

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

---

## 6. Disaster Recovery Checklist

- [ ] Confirm backups run daily and are tested monthly.  
- [ ] Store encryption keys in a secure secret manager.  
- [ ] Document manual token re-authorisation steps for critical services.  
- [ ] Periodically test restore procedure in a staging environment.

---

_End of Runbook_
