# Tenant Service Implementation Guide

## Overview
The Tenant Service is critical for TradeSage's multi-tenant architecture. It manages tenant lifecycle, PostgreSQL schema isolation, and resource monitoring.

## Service Architecture

### Directory Structure
```
tenant-service/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── dependencies.py      # Dependency injection
│   ├── config.py           # Service-specific config
│   ├── models/
│   │   ├── __init__.py
│   │   ├── tenant.py       # Tenant-specific models
│   │   └── schema.py       # Schema management models
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── tenant.py       # Pydantic schemas
│   │   └── requests.py     # Request/response models
│   ├── services/
│   │   ├── __init__.py
│   │   ├── tenant_service.py     # Core business logic
│   │   ├── schema_service.py     # Schema management
│   │   ├── monitoring_service.py # Resource monitoring
│   │   └── template_service.py   # Schema templates
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── tenants.py       # Tenant endpoints
│   │   │   ├── schemas.py       # Schema endpoints
│   │   │   └── monitoring.py    # Monitoring endpoints
│   └── utils/
│       ├── __init__.py
│       ├── database.py          # DB utilities
│       └── validators.py        # Input validation
├── tests/
├── Dockerfile
├── requirements.txt
└── README.md
```

## Core Implementation

### 1. Main Application (app/main.py)
```python
from fastapi import FastAPI
from contextlib import asynccontextmanager
import structlog
from common.config import settings
from common.database import db_manager
from common.redis_client import redis_manager
from common.logging_config import setup_logging
from app.routers.v1 import tenants, schemas, monitoring

setup_logging()
logger = structlog.get_logger("tradesage.tenant")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        db_manager.initialize(settings.database_url)
        await redis_manager.connect()
        logger.info("Tenant Service Started")
        yield
    finally:
        # Shutdown
        await redis_manager.disconnect()
        await db_manager.close()
        logger.info("Tenant Service Shutdown")

app = FastAPI(
    title="TradeSage Tenant Service",
    description="Multi-tenant management service",
    version="1.0.0",
    lifespan=lifespan
)

# Include routers
app.include_router(tenants.router, prefix="/api/v1/tenants", tags=["tenants"])
app.include_router(schemas.router, prefix="/api/v1/schemas", tags=["schemas"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["monitoring"])
```

### 2. Tenant Service Core (app/services/tenant_service.py)
```python
import asyncio
from datetime import datetime
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import structlog
from app.models.tenant import TenantModel
from app.schemas.tenant import TenantCreate, TenantUpdate, TenantStatus
from app.services.schema_service import SchemaService
from common.exceptions import TenantNotFoundError, TenantCreationError

logger = structlog.get_logger(__name__)

class TenantService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.schema_service = SchemaService(db)
    
    async def create_tenant(self, tenant_data: TenantCreate) -> TenantModel:
        """Create a new tenant with isolated schema."""
        start_time = datetime.utcnow()
        
        try:
            # Create tenant record
            tenant = TenantModel(
                name=tenant_data.name,
                domain=tenant_data.domain,
                status=TenantStatus.PENDING,
                settings=tenant_data.settings or {}
            )
            self.db.add(tenant)
            await self.db.flush()
            
            # Generate schema name
            schema_name = f"tenant_{str(tenant.id).replace('-', '_')}"
            tenant.schema_name = schema_name
            
            # Create isolated schema
            await self.schema_service.create_schema(schema_name)
            
            # Apply schema template
            await self.schema_service.apply_template(
                schema_name, 
                template_name=tenant_data.template or "default"
            )
            
            # Update status
            tenant.status = TenantStatus.ACTIVE
            await self.db.commit()
            
            # Log creation time
            creation_time = (datetime.utcnow() - start_time).total_seconds()
            logger.info(
                "Tenant created",
                tenant_id=str(tenant.id),
                creation_time=creation_time
            )
            
            # Verify < 10 second requirement
            if creation_time > 10:
                logger.warning(
                    "Tenant creation exceeded 10s threshold",
                    actual_time=creation_time
                )
            
            return tenant
            
        except Exception as e:
            await self.db.rollback()
            logger.error("Tenant creation failed", error=str(e))
            raise TenantCreationError(f"Failed to create tenant: {str(e)}")
    
    async def get_tenant(self, tenant_id: str) -> Optional[TenantModel]:
        """Get tenant by ID."""
        result = await self.db.execute(
            select(TenantModel).where(TenantModel.id == tenant_id)
        )
        return result.scalar_one_or_none()
    
    async def update_tenant(
        self, 
        tenant_id: str, 
        update_data: TenantUpdate
    ) -> Optional[TenantModel]:
        """Update tenant configuration."""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            raise TenantNotFoundError(f"Tenant {tenant_id} not found")
        
        # Update fields
        for field, value in update_data.dict(exclude_unset=True).items():
            setattr(tenant, field, value)
        
        tenant.updated_at = datetime.utcnow()
        await self.db.commit()
        await self.db.refresh(tenant)
        
        return tenant
    
    async def deactivate_tenant(self, tenant_id: str) -> bool:
        """Soft delete/deactivate tenant."""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            raise TenantNotFoundError(f"Tenant {tenant_id} not found")
        
        tenant.status = TenantStatus.SUSPENDED
        tenant.updated_at = datetime.utcnow()
        await self.db.commit()
        
        logger.info("Tenant deactivated", tenant_id=tenant_id)
        return True
```

### 3. Schema Management Service (app/services/schema_service.py)
```python
import asyncio
from typing import Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import structlog
from app.services.template_service import TemplateService

logger = structlog.get_logger(__name__)

class SchemaService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.template_service = TemplateService()
    
    async def create_schema(self, schema_name: str):
        """Create isolated PostgreSQL schema."""
        try:
            # Create schema
            await self.db.execute(
                text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}")
            )
            
            # Set search path for isolation
            await self.db.execute(
                text(f"SET search_path TO {schema_name}, public")
            )
            
            logger.info("Schema created", schema_name=schema_name)
            
        except Exception as e:
            logger.error("Schema creation failed", schema_name=schema_name, error=str(e))
            raise
    
    async def apply_template(self, schema_name: str, template_name: str):
        """Apply schema template with tables and indexes."""
        template = self.template_service.get_template(template_name)
        
        # Set schema context
        await self.db.execute(
            text(f"SET search_path TO {schema_name}, public")
        )
        
        # Create tables from template
        for table_sql in template.get("tables", []):
            await self.db.execute(text(table_sql))
        
        # Create indexes
        for index_sql in template.get("indexes", []):
            await self.db.execute(text(index_sql))
        
        # Create TimescaleDB hypertables if needed
        if template.get("timescale_tables"):
            await self._create_hypertables(
                schema_name, 
                template["timescale_tables"]
            )
        
        logger.info(
            "Template applied", 
            schema_name=schema_name, 
            template=template_name
        )
    
    async def _create_hypertables(
        self, 
        schema_name: str, 
        tables: List[Dict]
    ):
        """Create TimescaleDB hypertables for time-series data."""
        for table in tables:
            await self.db.execute(text(f"""
                SELECT create_hypertable(
                    '{schema_name}.{table["name"]}',
                    '{table["time_column"]}',
                    chunk_time_interval => INTERVAL '{table.get("chunk_interval", "1 day")}'
                )
            """))
    
    async def validate_schema(self, schema_name: str) -> Dict:
        """Validate schema structure and health."""
        # Check table existence
        tables_query = text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = :schema_name
        """)
        
        result = await self.db.execute(
            tables_query, 
            {"schema_name": schema_name}
        )
        tables = [row[0] for row in result]
        
        # Check indexes
        indexes_query = text("""
            SELECT indexname 
            FROM pg_indexes 
            WHERE schemaname = :schema_name
        """)
        
        result = await self.db.execute(
            indexes_query, 
            {"schema_name": schema_name}
        )
        indexes = [row[0] for row in result]
        
        return {
            "schema_name": schema_name,
            "tables": tables,
            "indexes": indexes,
            "is_valid": len(tables) > 0
        }
```

### 4. Monitoring Service (app/services/monitoring_service.py)
```python
from typing import Dict, List
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import structlog

logger = structlog.get_logger(__name__)

class MonitoringService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def get_tenant_health(self, tenant_id: str, schema_name: str) -> Dict:
        """Get comprehensive tenant health metrics."""
        metrics = {
            "tenant_id": tenant_id,
            "timestamp": datetime.utcnow().isoformat(),
            "database": await self._get_database_metrics(schema_name),
            "resource_usage": await self._get_resource_usage(schema_name),
            "activity": await self._get_activity_metrics(schema_name)
        }
        
        # Calculate overall health score
        metrics["health_score"] = self._calculate_health_score(metrics)
        
        return metrics
    
    async def _get_database_metrics(self, schema_name: str) -> Dict:
        """Get database-level metrics for tenant schema."""
        # Schema size
        size_query = text("""
            SELECT 
                pg_size_pretty(sum(pg_total_relation_size(schemaname||'.'||tablename))::bigint) as total_size,
                count(*) as table_count
            FROM pg_tables 
            WHERE schemaname = :schema_name
        """)
        
        result = await self.db.execute(size_query, {"schema_name": schema_name})
        row = result.first()
        
        # Connection count
        conn_query = text("""
            SELECT count(*) as connection_count
            FROM pg_stat_activity
            WHERE datname = current_database()
            AND query LIKE :pattern
        """)
        
        conn_result = await self.db.execute(
            conn_query, 
            {"pattern": f"%{schema_name}%"}
        )
        conn_count = conn_result.scalar() or 0
        
        return {
            "schema_size": row[0] if row else "0 bytes",
            "table_count": row[1] if row else 0,
            "connection_count": conn_count
        }
    
    async def _get_resource_usage(self, schema_name: str) -> Dict:
        """Get resource usage metrics."""
        # Query performance
        query_stats = text("""
            SELECT 
                count(*) as total_queries,
                avg(total_exec_time) as avg_query_time,
                max(total_exec_time) as max_query_time
            FROM pg_stat_statements
            WHERE query LIKE :pattern
            AND calls > 0
        """)
        
        try:
            result = await self.db.execute(
                query_stats, 
                {"pattern": f"%{schema_name}%"}
            )
            row = result.first()
            
            return {
                "total_queries": row[0] if row else 0,
                "avg_query_time_ms": round(row[1], 2) if row and row[1] else 0,
                "max_query_time_ms": round(row[2], 2) if row and row[2] else 0
            }
        except:
            # pg_stat_statements might not be enabled
            return {
                "total_queries": 0,
                "avg_query_time_ms": 0,
                "max_query_time_ms": 0
            }
    
    async def _get_activity_metrics(self, schema_name: str) -> Dict:
        """Get tenant activity metrics."""
        # This would typically query tenant-specific activity tables
        # For now, return placeholder metrics
        return {
            "active_users": 0,
            "api_calls_today": 0,
            "trades_today": 0,
            "last_activity": datetime.utcnow().isoformat()
        }
    
    def _calculate_health_score(self, metrics: Dict) -> float:
        """Calculate overall health score (0-100)."""
        score = 100.0
        
        # Deduct points for issues
        db_metrics = metrics.get("database", {})
        
        # High connection count
        if db_metrics.get("connection_count", 0) > 50:
            score -= 10
        
        # Slow queries
        resource_metrics = metrics.get("resource_usage", {})
        if resource_metrics.get("avg_query_time_ms", 0) > 1000:
            score -= 20
        
        # No recent activity
        activity = metrics.get("activity", {})
        if activity.get("api_calls_today", 0) == 0:
            score -= 5
        
        return max(0, min(100, score))
    
    async def get_all_tenants_usage(self) -> List[Dict]:
        """Get resource usage for all tenants."""
        # Query all tenant schemas
        schemas_query = text("""
            SELECT schema_name, tenant_id
            FROM tenants
            WHERE status = 'active'
        """)
        
        result = await self.db.execute(schemas_query)
        tenants = result.all()
        
        usage_reports = []
        for schema_name, tenant_id in tenants:
            usage = await self._get_resource_usage(schema_name)
            usage["tenant_id"] = str(tenant_id)
            usage["schema_name"] = schema_name
            usage_reports.append(usage)
        
        return usage_reports
```

### 5. API Endpoints (app/routers/v1/tenants.py)
```python
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from common.database import get_db
from common.auth import get_current_user, require_admin
from app.schemas.tenant import (
    TenantCreate, TenantResponse, TenantUpdate, TenantHealth
)
from app.services.tenant_service import TenantService
from app.services.monitoring_service import MonitoringService

router = APIRouter()

@router.post("/", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    tenant_data: TenantCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Create a new tenant with isolated schema."""
    service = TenantService(db)
    tenant = await service.create_tenant(tenant_data)
    return tenant

@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get tenant details."""
    service = TenantService(db)
    tenant = await service.get_tenant(tenant_id)
    
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )
    
    # Check access rights
    if current_user.role != "admin" and current_user.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return tenant

@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: str,
    update_data: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Update tenant configuration."""
    service = TenantService(db)
    tenant = await service.update_tenant(tenant_id, update_data)
    return tenant

@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Deactivate a tenant."""
    service = TenantService(db)
    await service.deactivate_tenant(tenant_id)

@router.get("/{tenant_id}/health", response_model=TenantHealth)
async def get_tenant_health(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get tenant health metrics."""
    # Verify access
    if current_user.role != "admin" and current_user.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Get tenant
    tenant_service = TenantService(db)
    tenant = await tenant_service.get_tenant(tenant_id)
    
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )
    
    # Get health metrics
    monitoring_service = MonitoringService(db)
    health = await monitoring_service.get_tenant_health(
        tenant_id, 
        tenant.schema_name
    )
    
    return health
```

## Database Schema Templates

### Default Template (app/services/templates/default.json)
```json
{
    "name": "default",
    "description": "Default trading platform schema",
    "tables": [
        "CREATE TABLE IF NOT EXISTS portfolios (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL, name VARCHAR(255), description TEXT, is_active BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS positions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), portfolio_id UUID REFERENCES portfolios(id), symbol VARCHAR(20) NOT NULL, quantity DECIMAL(20,8), avg_price DECIMAL(20,8), current_price DECIMAL(20,8), created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS trades (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), portfolio_id UUID REFERENCES portfolios(id), symbol VARCHAR(20) NOT NULL, side VARCHAR(10), quantity DECIMAL(20,8), price DECIMAL(20,8), timestamp TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS market_data (symbol VARCHAR(20), timestamp TIMESTAMPTZ, open DECIMAL(20,8), high DECIMAL(20,8), low DECIMAL(20,8), close DECIMAL(20,8), volume BIGINT, PRIMARY KEY (symbol, timestamp))"
    ],
    "indexes": [
        "CREATE INDEX idx_portfolios_user_id ON portfolios(user_id)",
        "CREATE INDEX idx_positions_portfolio_id ON positions(portfolio_id)",
        "CREATE INDEX idx_trades_portfolio_id_timestamp ON trades(portfolio_id, timestamp DESC)",
        "CREATE INDEX idx_market_data_symbol_timestamp ON market_data(symbol, timestamp DESC)"
    ],
    "timescale_tables": [
        {
            "name": "trades",
            "time_column": "timestamp",
            "chunk_interval": "1 day"
        },
        {
            "name": "market_data",
            "time_column": "timestamp",
            "chunk_interval": "1 day"
        }
    ]
}
```

## Testing Strategy

### Unit Tests
```python
# tests/test_tenant_service.py
import pytest
from datetime import datetime
from app.services.tenant_service import TenantService
from app.schemas.tenant import TenantCreate

@pytest.mark.asyncio
async def test_create_tenant_under_10_seconds(db_session):
    """Test tenant creation completes in under 10 seconds."""
    service = TenantService(db_session)
    
    start = datetime.utcnow()
    tenant = await service.create_tenant(
        TenantCreate(
            name="Test Tenant",
            domain="test.tradesage.io"
        )
    )
    duration = (datetime.utcnow() - start).total_seconds()
    
    assert tenant.id is not None
    assert tenant.schema_name is not None
    assert tenant.status == "active"
    assert duration < 10  # Must complete in under 10 seconds

@pytest.mark.asyncio
async def test_tenant_isolation(db_session):
    """Test that tenant schemas are completely isolated."""
    service = TenantService(db_session)
    
    # Create two tenants
    tenant1 = await service.create_tenant(
        TenantCreate(name="Tenant 1", domain="tenant1.com")
    )
    tenant2 = await service.create_tenant(
        TenantCreate(name="Tenant 2", domain="tenant2.com")
    )
    
    # Verify schemas are different
    assert tenant1.schema_name != tenant2.schema_name
    
    # Test cross-schema access (should fail)
    # Implementation depends on your isolation strategy
```

### Load Tests
```python
# tests/load/test_concurrent_schemas.py
import asyncio
from datetime import datetime

async def create_tenant_load_test(num_tenants=100):
    """Test creating multiple tenants concurrently."""
    tasks = []
    
    for i in range(num_tenants):
        task = create_tenant(f"LoadTest{i}", f"test{i}.com")
        tasks.append(task)
    
    start = datetime.utcnow()
    results = await asyncio.gather(*tasks)
    duration = (datetime.utcnow() - start).total_seconds()
    
    print(f"Created {num_tenants} tenants in {duration} seconds")
    print(f"Average time per tenant: {duration/num_tenants} seconds")
    
    assert all(r.status == "active" for r in results)
```

## Deployment

### Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@postgres:5432/tradesage
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://redis:6379/0

# Service Config
SERVICE_NAME=tenant-service
LOG_LEVEL=INFO
SCHEMA_CREATION_TIMEOUT=10

# TimescaleDB
ENABLE_TIMESCALEDB=true
```

## Performance Optimizations

1. **Connection Pooling**: Use dedicated connection pools per tenant
2. **Schema Caching**: Cache schema metadata in Redis
3. **Async Operations**: Use asyncio for all I/O operations
4. **Batch Operations**: Support bulk tenant operations
5. **Resource Limits**: Implement per-tenant resource quotas

## Security Considerations

1. **Schema Isolation**: Use PostgreSQL schemas for complete isolation
2. **Access Control**: Validate tenant access on every request
3. **Audit Logging**: Log all tenant operations
4. **Resource Limits**: Prevent resource exhaustion attacks
5. **Data Encryption**: Encrypt sensitive tenant configuration

## Monitoring & Alerts

1. **Metrics to Track**:
   - Schema creation time
   - Active tenant count
   - Resource usage per tenant
   - Failed operations
   - API response times

2. **Alerts**:
   - Schema creation > 10 seconds
   - Tenant resource usage > threshold
   - Failed tenant operations
   - Database connection issues

## Next Steps

1. Implement comprehensive integration tests
2. Add support for tenant data migration
3. Create tenant backup/restore functionality
4. Build admin UI for tenant management
5. Add billing integration for resource usage 