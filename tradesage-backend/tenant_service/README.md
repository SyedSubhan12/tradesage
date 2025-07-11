# Tenant Service – Architectural Overview & Assessment

> **Version:** 2025-07-08  |  **Author:** AI Architecture Review

---

## 1. Purpose
The **Tenant Service** is responsible for life-cycle management of tenants in the TradeSage platform.  It provisions isolated Postgres schemas per tenant, monitors health / utilisation, and performs scheduled backups.

---

## 2. High-Level Architecture
```
┌────────────┐      Async HTTP      ┌───────────┐
│  Client /  │ ───────────────────▶ │ API Router│
│ API GW     │                      └───────────┘
     ▲                                   │          (FastAPI)
     │                                   ▼
     │                          Business Logic
     │                          (Routers / Services)
     │                                   │
     │        SQLAlchemy Async ORM       ▼
     │──────────────────────────────▶  Postgres
     │                                   ▲
     │         redis-py (async/sync)      │
     └──────────────────────────────▶  Redis
```
The entry-point is `tenant_service/main.py` which bootstraps a FastAPI application, registers routers, and starts two background tasks:
* **Monitoring task** – gathers metrics via `TenantMonitoringService` every 5 minutes.
* **Backup task** – creates daily backups via `TenantBackupService` (S3) **or** `MA130BackupService` (on-prem SCP) depending on env flags.

Prometheus middleware exports metrics at `/metrics`; a rich health-check endpoint at `/health` verifies Postgres, Redis, and dependency connectivity.

---

## 3. File & Module Breakdown
| Path | Purpose |
|------|---------|
| `main.py` | Service entry. Sets up logging, DB/Redis clients, lifespan context, background tasks, routers, health-check, global error handler & request logging middleware. |
| `app/routers/v1/tenants.py` | CRUD & admin actions for tenants (provision, status, list, activate/deactivate, delete). Depends on `SchemaProvisioner`, `TenantMonitoringService`, and authentication helpers. |
| `app/routers/v1/schemas.py` | Endpoints to manage individual schemas (create, migrate, list, etc.). |
| `app/routers/v1/monitoring.py` | Exposes metrics & health data per tenant. |
| `app/models/tenant.py` | SQLAlchemy models – `TenantSchema`, `TenantBackup`, etc. |
| `app/schemas/tenant_schemas.py` | Pydantic request/response models ensuring API contract validation. |
| `app/services/schema_provisioner.py` | Wraps asyncpg to create Postgres schemas, run migrations & bootstrap templates. |
| `app/services/monitoring_service.py` | Collects DB/Redis metrics, cache ratio, connection counts and stores them (likely in Redis). Also exposes helper methods for routers. |
| `app/services/backup_service.py` | Generic S3 backup implementation using boto3. |
| `app/services/backup_service_ma130.py` | Alternative backup via SSH/SCP to MA130 NAS. |
| `app/utils/` | Shared helpers (not inspected in detail). |
| `config/*.yaml`, `scripts/` | Deployment & infra bootstrapping helpers. |

### Notable Methods
* **`lifespan`** (`main.py`) – orchestrates startup/shutdown, executes connectivity tests, spins background tasks.
* **`periodic_monitoring / periodic_backup`** – infinite loops with `asyncio.sleep`, performing collection / backup.
* **`TenantMonitoringService.collect_tenant_metrics`** – executes SQL & Redis queries to compute CPU/memory, cache-hit ratio, connections.
* **`SchemaProvisioner.provision_tenant_schema`** – creates schema, installs extensions, copies template tables, applies RLS policies.

---

## 4. Strengths 👍
1. **Comprehensive Observability** – Prometheus metrics, structured logging (`structlog`), and detailed health checks provide good insight.
2. **Isolation** – Per-tenant Postgres schemas help enforce data isolation without running separate DBs.
3. **Async IO** – Use of `httpx`, `asyncpg`, and SQLAlchemy async engine allows high concurrency.
4. **Background Processing** – Monitoring & backup tasks run outside request path preventing latency impact.
5. **Security Hooks** – JWT auth decorators (`require_admin`, `get_current_user`) guard sensitive endpoints.
6. **Pluggable Backup Strategy** – Env-driven toggle between S3 and on-prem SCP increases deployment flexibility.

---

## 5. Identified Flaws / Risks ⚠️
| Category | Issue |
|----------|-------|
| **Scalability** | Background tasks run **inside** each service instance; with >1 replica they duplicate work & contend for resources. Use a distributed scheduler (e.g., Celery beat, APScheduler w/ DB lock) or dedicate a worker. |
| **Backup Blocking** | Large daily backups executed synchronously may block event loop (network I/O via paramiko/S3). Offload to thread-pool or external job queue. |
| **Error Handling** | Many `except Exception as e` blocks log but continue; failed backups/metrics aren’t retried or alerted; missing circuit-breaker patterns. |
| **Redis Client Mixing** | `redis_manager` is async but code occasionally uses sync `redis.from_url` (see startup) – inconsistent API surfaces and potential blocking calls inside async loop. |
| **Configuration Duplication** | URLs & secrets are read directly from `settings`, but some hard-coded defaults exist (e.g., MA130_HOST). Centralise in one settings module & validate at start-up. |
| **Schema Limits Hard-coded** | Health check caps schemas at `100`; should come from config/env. |
| **Security** | No rate-limiting or brute-force protection on admin endpoints; backups may contain plaintext PII if not encrypted. |
| **Testing** | Little evidence of unit / integration tests; migration safety & rollback are unclear. |
| **Migration Management** | Comments mention Alembic migrations, but SchemaProvisioner may run raw SQL; ensure both paths stay in sync. |
| **Observation Lag** | Monitoring interval fixed at 5 min; consider push-based metrics or configurable cron. |

---

## 6. Recommendations for Production Readiness 🚀
1. **External Scheduler & Workers**
   * Extract monitoring & backup loops into Celery/Arq/Temporal workers; maintain singleton scheduling via Redis locks or specialised schedulers (e.g., APScheduler + Postgres).  
   * Keep API container stateless.
2. **Connection Management**
   * Use **Async Redis** (`redis.asyncio`) consistently; avoid synchronous `ping()` inside async context.
   * Configure SQLAlchemy pool sizes via env, monitor with PoolMetrics.
3. **Resilience & Retry**
   * Implement exponential back-off retries for DB/Redis failures and backup uploads.
   * Add circuit-breaker around external dependencies.
4. **Observability Enhancements**
   * Emit structured events to OpenTelemetry; instrument background tasks with custom Prometheus metrics (success/fail counts, duration).
   * Push logs to ELK/Loki with correlation IDs.
5. **Security Hardening**
   * Enforce RBAC scopes per endpoint; add rate-limiting middleware.
   * Encrypt backup files at rest; rotate SSH keys & S3 credentials via secrets manager.
6. **Operational Automation**
   * Use Helm charts or Terraform to deploy Postgres, Redis, and service with health probes & HPA autoscaling.
   * Add **readiness/liveness** probes for Kubernetes.
7. **Testing & CI/CD**
   * Add pytest suite with testcontainers-postgres; run migrations & provisioner paths.
   * Perform load testing with Locust/Gatling; include backup/monitoring under stress.
8. **Configuration & Secrets**
   * Adopt [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) for type-safe env management.
   * Store secrets in AWS Secrets Manager / Vault; avoid embedding defaults in code.
9. **Data Management**
   * Implement tenant off-boarding (archival & GDPR erase) workflows.
   * Monitor schema bloat, index usage, and vacuum stats; auto-tune per schema.
10. **High Availability**
    * Run ≥2 replicas behind a load-balancer; externalise stateful tasks; use Postgres streaming replicas and Redis cluster.

---

## 7. Conclusion
The Tenant Service has a solid foundation with asynchronous FastAPI, modular routers, and comprehensive logging.  Addressing the highlighted risks—especially background task duplication, consistent async I/O, and stronger operational automation—will greatly improve reliability and scalability in a production environment.

---

*Generated automatically · please adapt recommendations to your organisation’s standards.*