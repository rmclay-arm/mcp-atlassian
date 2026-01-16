# Central OAuth – Security Checklists

This document provides **actionable security checklists** for deploying and
operating the Central OAuth Service (Phase 1).  
It avoids any environment-specific secrets or URLs.

---

## 1. Pre-Deployment Checklist

| # | Item | Status |
|---|------|--------|
| 1 | Review code for hard-coded credentials or keys | ☐ |
| 2 | Set **`CENTRAL_OAUTH_SECRET_KEY`** (32-byte hex) via secret manager | ☐ |
| 3 | Enable container image signing / provenance (e.g. Sigstore) | ☐ |
| 4 | Configure read-only root filesystem except `/data` volume | ☐ |
| 5 | Limit container UID/GID (non-root) | ☐ |
| 6 | Define NetworkPolicy / firewall rules – allow **HTTPS outbound only** | ☐ |
| 7 | Enable TLS termination (Ingress or sidecar) using trusted CA | ☐ |
| 8 | Scan container image with vulnerability scanner (Trivy/Grype) | ☐ |

---

## 2. Runtime Hardening Checklist

| # | Item | Status |
|---|------|--------|
| 1 | Mount `/data` volume with `noexec`, `nosuid`, `nodev` where possible | ☐ |
| 2 | Run SQLite in **WAL** mode to reduce file corruption risk | ☐ |
| 3 | Set **`CENTRAL_OAUTH_LOG_LEVEL=INFO`** (avoid DEBUG in prod) | ☐ |
| 4 | Rotate encryption key annually or after incident | ☐ |
| 5 | Backup database daily to encrypted storage | ☐ |
| 6 | Retain audit logs for 90 days minimum | ☐ |
| 7 | Enable Prometheus metrics scrape over **localhost** only | ☐ |

---

## 3. Post-Incident Checklist

| # | Item | Status |
|---|------|--------|
| 1 | Revoke affected tokens via `DELETE /v1/tokens/:account_id` | ☐ |
| 2 | Rotate `CENTRAL_OAUTH_SECRET_KEY` and re-encrypt DB | ☐ |
| 3 | Audit access logs for anomaly timeframe | ☐ |
| 4 | Perform forensics on container image / host | ☐ |
| 5 | Update threat model & runbook based on findings | ☐ |

---

## 4. Compliance Alignment Matrix

Requirement | Coverage Notes
----------- | --------------
Encryption at rest | Tokens encrypted with AES-GCM; DB file stored on encrypted volume
Encryption in transit | HTTPS enforced (TLS 1.2+)
Secrets management | Environment variables injected from secret manager; never committed to VCS
Access control | Service exposes no UI; API protected by network boundaries
Audit logging | JSON lines include `request_id`, `account_id`, `ip`
Backup & DR | Daily snapshot to secure bucket; restore procedure tested quarterly

---

## 5. Static Analysis & Dependency Hygiene

* **SCA**: Dependabot / Renovate configured for upstream patching  
* **Ruff**: Linting enforces secure coding patterns (no `subprocess`, no
  wildcard TLS verify disable)  
* **Bandit** *(optional)*: Additional static analysis stage in CI

---

_End of Security Checklists_
