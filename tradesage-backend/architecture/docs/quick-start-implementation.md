# TradeSage Backend - Quick Start Implementation Guide

## 🚨 CRITICAL: What Needs to Be Done NOW

### 1. Tenant Service - START IMMEDIATELY
The tenant service is completely missing and is blocking multi-tenant functionality.

**Location**: `tradesage-backend/tenant-service/`
**Priority**: CRITICAL
**Time Estimate**: 3-4 days

```bash
# Create the service structure
cd tradesage-backend/tenant-service
mkdir -p app/{models,schemas,services,routers/v1,utils}
touch app/main.py app/__init__.py
```

**Key Implementation Points**:
- Automated PostgreSQL schema creation
- Schema templates for different tenant types
- Resource monitoring per tenant
- Health check endpoints
- Must complete schema creation in <10 seconds

### 2. User Service - HIGH PRIORITY
The user service is completely missing and is required for user management.

**Location**: `tradesage-backend/user-service/`
**Priority**: HIGH
**Time Estimate**: 2-3 days

```bash
# Create the service structure
cd tradesage-backend/user-service
mkdir -p app/{models,schemas,services,routers/v1,utils}
touch app/main.py app/__init__.py
```

**Key Implementation Points**:
- User profile management
- Preference storage
- Activity tracking
- Session management integration
- Permission calculation

### 3. Auth Service Security Enhancements
The auth service exists but needs security hardening.

**Location**: `tradesage-backend/auth_service/`
**Priority**: HIGH
**Current Gaps**:
- No OAuth 2.0 PKCE flow
- No comprehensive audit logging
- No JWT encryption for tenant IDs
- Missing progressive login delays

### 4. PostgreSQL Infrastructure
Currently using a single database instance.

**Required Setup**:
```bash
# Install TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb;

# Set up replication (primary + 2 replicas)
# Configure PgBouncer for connection pooling
# Set up automated backups
```

### 5. Security Infrastructure
No security infrastructure exists.

**Required Components**:
- HashiCorp Vault for secrets management
- mTLS certificates for inter-service communication
- Wazuh/OSSEC for intrusion detection
- Security scanning automation

## 📋 Day 1 Action Items

### Morning (First 4 Hours)
1. **Set up Tenant Service skeleton**
   - Create project structure
   - Set up basic FastAPI app
   - Create database models
   - Implement health check endpoint

2. **Create tenant database schema**
   ```sql
   -- Add to migrations
   CREATE TABLE tenant_schemas (
       tenant_id UUID REFERENCES tenants(id),
       schema_name VARCHAR(100) UNIQUE NOT NULL,
       created_at TIMESTAMPTZ DEFAULT NOW(),
       is_active BOOLEAN DEFAULT true
   );
   ```

### Afternoon (Next 4 Hours)
1. **Implement core tenant endpoints**
   - POST /tenants - Create tenant
   - GET /tenants/{id} - Get tenant
   - POST /tenants/{id}/schema - Create schema

2. **Test schema creation performance**
   - Must complete in <10 seconds
   - Test concurrent schema creation

## 🏗️ Service Implementation Templates

### FastAPI Service Template
```python
# app/main.py
from fastapi import FastAPI
from contextlib import asynccontextmanager
import structlog
from common.config import settings
from common.database import db_manager
from common.redis_client import redis_manager

logger = structlog.get_logger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    db_manager.initialize(settings.database_url)
    await redis_manager.connect()
    logger.info(f"{SERVICE_NAME} started")
    yield
    # Shutdown
    await redis_manager.disconnect()
    await db_manager.close()
    logger.info(f"{SERVICE_NAME} stopped")

app = FastAPI(
    title=f"TradeSage {SERVICE_NAME}",
    lifespan=lifespan
)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
```

### Database Model Template
```python
# app/models/tenant.py
from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
import uuid
from common.database import Base

class TenantSchema(Base):
    __tablename__ = "tenant_schemas"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False)
    schema_name = Column(String(100), unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
```

## 🔧 Development Environment Setup

```bash
# Install dependencies
cd tradesage-backend
pip install -r requirements.txt

# Set up environment variables
export DATABASE_URL="postgresql://user:pass@localhost/tradesage"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET_KEY="your-secret-key"

# Run database migrations
alembic upgrade head

# Start services
python auth_service/app/main.py &
python api_gateway/main.py &
# Add tenant and user services once created
```

## 📊 Progress Tracking

Use this to track daily progress:

**Day 1**:
- [ ] Tenant service structure created
- [ ] Basic tenant CRUD endpoints
- [ ] Schema creation working
- [ ] Performance <10s verified

**Day 2**:
- [ ] User service structure created
- [ ] Basic user endpoints
- [ ] Permission system design
- [ ] Integration with auth service

**Day 3**:
- [ ] PostgreSQL replication setup
- [ ] TimescaleDB installed
- [ ] Connection pooling configured
- [ ] Backup strategy implemented

**Day 4**:
- [ ] HashiCorp Vault deployed
- [ ] Service authentication configured
- [ ] Secrets migrated to Vault
- [ ] mTLS certificates generated

**Day 5**:
- [ ] Integration testing complete
- [ ] Load testing passed
- [ ] Security scan clean
- [ ] Documentation updated

## ⚡ Quick Commands

```bash
# Check service health
curl http://localhost:8000/health

# Create a tenant (after implementation)
curl -X POST http://localhost:8000/api/v1/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Corp", "domain": "test.com"}'

# Monitor PostgreSQL connections
SELECT datname, count(*) 
FROM pg_stat_activity 
GROUP BY datname;

# Check schema size
SELECT schema_name, 
       pg_size_pretty(sum(pg_total_relation_size(schemaname||'.'||tablename))::bigint) as size
FROM pg_tables 
WHERE schemaname LIKE 'tenant_%'
GROUP BY schema_name;
```

## 🆘 Getting Help

1. Check existing implementation in `auth_service/` for patterns
2. Use `common/` modules for shared functionality
3. Follow FastAPI best practices
4. Ensure all endpoints have proper authentication
5. Add comprehensive logging for debugging

Remember: The goal is to have a secure, multi-tenant foundation by the end of Month 1! 