# Multi-Tenant PostgreSQL Database Architecture

## Executive Summary

This document defines the multi-tenant database architecture for TradeSage, implementing PostgreSQL schema-based isolation with absolute data separation, sub-10-second provisioning, and enterprise-grade security.

## Architecture Overview

### Tenant Isolation Strategy

We implement **Schema-Based Isolation** where each tenant has a dedicated PostgreSQL schema:

```
Database: tradesage_production
├── public (system tables only)
├── tenant_abc123def456 (Tenant 1)
├── tenant_ghi789jkl012 (Tenant 2)
└── tenant_mno345pqr678 (Tenant 3)
```

### Key Design Principles

1. **Absolute Isolation**: Zero cross-tenant data access
2. **Rapid Provisioning**: <10 second schema creation
3. **Scalability**: Support 100+ concurrent schemas
4. **Security First**: Defense in depth approach
5. **Performance**: Optimized for high-throughput trading

## Database Infrastructure

### PostgreSQL Cluster Configuration

```yaml
# PostgreSQL 15+ Cluster Setup
Primary Server:
  - CPU: 32 cores
  - Memory: 128GB
  - Storage: NVMe SSD 2TB
  - Location: us-east-1a

Read Replica 1:
  - Specs: Same as primary
  - Location: us-east-1b
  - Lag: <100ms

Read Replica 2:
  - Specs: Same as primary  
  - Location: us-east-1c
  - Lag: <100ms

Configuration:
  - max_connections: 1000
  - shared_buffers: 32GB
  - effective_cache_size: 96GB
  - work_mem: 256MB
  - maintenance_work_mem: 2GB
  - checkpoint_segments: 32
  - wal_buffers: 16MB
```

### Connection Pooling Strategy

```python
# PgBouncer Configuration
[databases]
tradesage_production = host=primary.db.internal port=5432 dbname=tradesage

[pgbouncer]
pool_mode = session
max_client_conn = 5000
default_pool_size = 25
reserve_pool_size = 5
reserve_pool_timeout = 3
server_lifetime = 3600
server_idle_timeout = 600

# Per-tenant connection limits
max_db_connections = 100
```

## Schema Provisioning System

### Template-Based Schema Creation

```sql
-- Master template stored in system
CREATE SCHEMA template_trading;

-- Core trading tables
CREATE TABLE template_trading.portfolios (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    base_currency CHAR(3) DEFAULT 'USD',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE template_trading.positions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID REFERENCES portfolios(id) ON DELETE CASCADE,
    symbol VARCHAR(20) NOT NULL,
    quantity DECIMAL(20,8) NOT NULL,
    avg_price DECIMAL(20,8) NOT NULL,
    current_price DECIMAL(20,8),
    realized_pnl DECIMAL(20,8) DEFAULT 0,
    unrealized_pnl DECIMAL(20,8) DEFAULT 0,
    opened_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE template_trading.trades (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID REFERENCES portfolios(id) ON DELETE CASCADE,
    symbol VARCHAR(20) NOT NULL,
    side VARCHAR(4) CHECK (side IN ('BUY', 'SELL')),
    quantity DECIMAL(20,8) NOT NULL,
    price DECIMAL(20,8) NOT NULL,
    commission DECIMAL(20,8) DEFAULT 0,
    executed_at TIMESTAMPTZ NOT NULL,
    order_id VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE template_trading.market_data (
    symbol VARCHAR(20),
    timestamp TIMESTAMPTZ,
    open DECIMAL(20,8),
    high DECIMAL(20,8),
    low DECIMAL(20,8),
    close DECIMAL(20,8),
    volume BIGINT,
    PRIMARY KEY (symbol, timestamp)
);

-- Indexes for performance
CREATE INDEX idx_portfolios_user_id ON template_trading.portfolios(user_id);
CREATE INDEX idx_positions_portfolio_id ON template_trading.positions(portfolio_id);
CREATE INDEX idx_positions_symbol ON template_trading.positions(symbol);
CREATE INDEX idx_trades_portfolio_id_executed ON template_trading.trades(portfolio_id, executed_at DESC);
CREATE INDEX idx_trades_symbol_executed ON template_trading.trades(symbol, executed_at DESC);

-- TimescaleDB hypertables
SELECT create_hypertable('template_trading.trades', 'executed_at', chunk_time_interval => INTERVAL '1 day');
SELECT create_hypertable('template_trading.market_data', 'timestamp', chunk_time_interval => INTERVAL '1 hour');
```

### Rapid Schema Provisioning Implementation

```python
# tenant-service/app/services/schema_provisioner.py
import asyncio
import asyncpg
import secrets
import time
from typing import Dict, Optional
import hashlib

class SchemaProvisioner:
    def __init__(self, db_pool: asyncpg.Pool):
        self.db_pool = db_pool
        self.template_cache = {}
        
    async def provision_tenant_schema(
        self, 
        tenant_id: str, 
        template: str = "trading"
    ) -> Dict:
        """Provision a new tenant schema in <10 seconds."""
        start_time = time.time()
        
        # Generate cryptographically secure schema name
        schema_name = self._generate_schema_name(tenant_id)
        
        try:
            # Use dedicated connection for schema operations
            async with self.db_pool.acquire() as conn:
                # Begin transaction for atomicity
                async with conn.transaction():
                    # Step 1: Create schema (50ms)
                    await conn.execute(f"""
                        CREATE SCHEMA IF NOT EXISTS {schema_name}
                        AUTHORIZATION current_user
                    """)
                    
                    # Step 2: Clone template using parallel operations (2-3s)
                    await self._clone_template_optimized(
                        conn, 
                        f"template_{template}", 
                        schema_name
                    )
                    
                    # Step 3: Set security policies (100ms)
                    await self._apply_security_policies(conn, schema_name)
                    
                    # Step 4: Create tenant metadata (50ms)
                    await self._create_tenant_metadata(
                        conn, 
                        tenant_id, 
                        schema_name
                    )
                    
                    # Step 5: Initialize monitoring (100ms)
                    await self._initialize_monitoring(conn, schema_name)
            
            provisioning_time = time.time() - start_time
            
            # Verify under 10 seconds
            if provisioning_time > 10:
                raise Exception(
                    f"Schema provisioning exceeded 10s: {provisioning_time:.2f}s"
                )
            
            return {
                "schema_name": schema_name,
                "tenant_id": tenant_id,
                "provisioning_time": provisioning_time,
                "status": "active"
            }
            
        except Exception as e:
            # Rollback is automatic with transaction
            await self._log_provisioning_failure(tenant_id, str(e))
            raise
    
    def _generate_schema_name(self, tenant_id: str) -> str:
        """Generate cryptographically secure schema name."""
        # Use SHA256 of tenant_id + random salt
        salt = secrets.token_hex(8)
        hash_input = f"{tenant_id}:{salt}".encode()
        hash_output = hashlib.sha256(hash_input).hexdigest()[:12]
        return f"tenant_{hash_output}"
    
    async def _clone_template_optimized(
        self, 
        conn: asyncpg.Connection,
        template_schema: str,
        target_schema: str
    ):
        """Optimized template cloning using parallel operations."""
        # Get all objects from template
        objects = await conn.fetch(f"""
            SELECT 
                'TABLE' as type,
                table_name as name,
                NULL as definition
            FROM information_schema.tables
            WHERE table_schema = $1
            UNION ALL
            SELECT 
                'INDEX' as type,
                indexname as name,
                indexdef as definition
            FROM pg_indexes
            WHERE schemaname = $1
        """, template_schema)
        
        # Prepare parallel tasks
        tasks = []
        
        # Clone tables
        for obj in objects:
            if obj['type'] == 'TABLE':
                task = conn.execute(f"""
                    CREATE TABLE {target_schema}.{obj['name']} 
                    (LIKE {template_schema}.{obj['name']} 
                    INCLUDING ALL)
                """)
                tasks.append(task)
        
        # Execute table creation in parallel
        await asyncio.gather(*tasks)
        
        # Clone indexes and constraints
        index_tasks = []
        for obj in objects:
            if obj['type'] == 'INDEX' and obj['definition']:
                new_def = obj['definition'].replace(
                    template_schema, 
                    target_schema
                )
                index_tasks.append(conn.execute(new_def))
        
        await asyncio.gather(*index_tasks)
        
        # Create TimescaleDB hypertables
        await conn.execute(f"""
            SELECT create_hypertable(
                '{target_schema}.trades',
                'executed_at',
                chunk_time_interval => INTERVAL '1 day',
                if_not_exists => TRUE
            );
            SELECT create_hypertable(
                '{target_schema}.market_data',
                'timestamp',
                chunk_time_interval => INTERVAL '1 hour',
                if_not_exists => TRUE
            );
        """)
```

## Tenant Isolation Implementation

### Security Policies and RLS

```python
# tenant-service/app/services/security_manager.py
class TenantSecurityManager:
    def __init__(self, db_pool: asyncpg.Pool):
        self.db_pool = db_pool
        
    async def apply_tenant_isolation(self, schema_name: str, tenant_id: str):
        """Apply comprehensive security isolation for tenant schema."""
        async with self.db_pool.acquire() as conn:
            # 1. Create tenant-specific database user
            user_name = f"{schema_name}_user"
            user_password = self._generate_secure_password()
            
            await conn.execute(f"""
                -- Create user if not exists
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '{user_name}') THEN
                        CREATE USER {user_name} WITH PASSWORD '{user_password}';
                    END IF;
                END
                $$;
                
                -- Revoke all default permissions
                REVOKE ALL ON SCHEMA {schema_name} FROM PUBLIC;
                REVOKE ALL ON ALL TABLES IN SCHEMA {schema_name} FROM PUBLIC;
                REVOKE ALL ON ALL SEQUENCES IN SCHEMA {schema_name} FROM PUBLIC;
                REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {schema_name} FROM PUBLIC;
                
                -- Grant schema access only to tenant user
                GRANT USAGE ON SCHEMA {schema_name} TO {user_name};
                GRANT CREATE ON SCHEMA {schema_name} TO {user_name};
                
                -- Grant table permissions
                GRANT ALL ON ALL TABLES IN SCHEMA {schema_name} TO {user_name};
                GRANT ALL ON ALL SEQUENCES IN SCHEMA {schema_name} TO {user_name};
                
                -- Set default privileges for future objects
                ALTER DEFAULT PRIVILEGES IN SCHEMA {schema_name}
                GRANT ALL ON TABLES TO {user_name};
                
                ALTER DEFAULT PRIVILEGES IN SCHEMA {schema_name}
                GRANT ALL ON SEQUENCES TO {user_name};
            """)
            
            # 2. Enable Row Level Security
            tables = ['portfolios', 'positions', 'trades']
            for table in tables:
                await conn.execute(f"""
                    -- Enable RLS
                    ALTER TABLE {schema_name}.{table} ENABLE ROW LEVEL SECURITY;
                    ALTER TABLE {schema_name}.{table} FORCE ROW LEVEL SECURITY;
                    
                    -- Create tenant isolation policy
                    CREATE POLICY {table}_tenant_isolation ON {schema_name}.{table}
                    AS RESTRICTIVE
                    FOR ALL
                    TO {user_name}
                    USING (true)  -- All rows in this schema belong to this tenant
                    WITH CHECK (true);
                    
                    -- Create admin bypass policy
                    CREATE POLICY {table}_admin_bypass ON {schema_name}.{table}
                    AS PERMISSIVE
                    FOR ALL
                    TO postgres
                    USING (true)
                    WITH CHECK (true);
                """)
            
            # 3. Store credentials securely
            await self._store_tenant_credentials(tenant_id, user_name, user_password)
            
            # 4. Create audit trigger
            await self._create_audit_triggers(conn, schema_name)
    
    async def validate_tenant_isolation(self, schema_name: str) -> bool:
        """Validate that tenant isolation is properly enforced."""
        async with self.db_pool.acquire() as conn:
            # Check 1: No PUBLIC access
            public_access = await conn.fetchval("""
                SELECT COUNT(*)
                FROM information_schema.table_privileges
                WHERE table_schema = $1
                AND grantee = 'PUBLIC'
            """, schema_name)
            
            if public_access > 0:
                raise SecurityError(f"PUBLIC access detected in schema {schema_name}")
            
            # Check 2: RLS is enabled
            rls_check = await conn.fetch("""
                SELECT tablename
                FROM pg_tables t
                WHERE schemaname = $1
                AND tablename IN ('portfolios', 'positions', 'trades')
                AND NOT EXISTS (
                    SELECT 1 FROM pg_policies p
                    WHERE p.schemaname = t.schemaname
                    AND p.tablename = t.tablename
                )
            """, schema_name)
            
            if rls_check:
                raise SecurityError(f"Tables without RLS: {rls_check}")
            
            # Check 3: No cross-schema references
            cross_refs = await conn.fetch("""
                SELECT DISTINCT
                    conname,
                    conrelid::regclass,
                    confrelid::regclass
                FROM pg_constraint
                WHERE contype = 'f'
                AND connamespace::regnamespace::text = $1
                AND confrelid::regclass::text NOT LIKE $1 || '.%'
            """, schema_name)
            
            if cross_refs:
                raise SecurityError(f"Cross-schema references detected: {cross_refs}")
            
            return True
```

## Monitoring and Health Tracking

### Real-time Monitoring System

```python
# tenant-service/app/services/monitoring_service.py
from prometheus_client import Counter, Gauge, Histogram
import psutil

class TenantMonitoringService:
    def __init__(self, db_pool: asyncpg.Pool, redis_client):
        self.db_pool = db_pool
        self.redis = redis_client
        
        # Prometheus metrics
        self.schema_size_gauge = Gauge(
            'tenant_schema_size_bytes',
            'Size of tenant schema in bytes',
            ['tenant_id', 'schema_name']
        )
        
        self.connection_gauge = Gauge(
            'tenant_active_connections',
            'Active database connections per tenant',
            ['tenant_id', 'schema_name']
        )
        
        self.query_duration_histogram = Histogram(
            'tenant_query_duration_seconds',
            'Query execution time per tenant',
            ['tenant_id', 'schema_name', 'query_type']
        )
        
    async def collect_tenant_metrics(self, tenant_id: str, schema_name: str) -> Dict:
        """Collect comprehensive tenant metrics."""
        metrics = {
            "tenant_id": tenant_id,
            "schema_name": schema_name,
            "timestamp": datetime.utcnow().isoformat(),
            "database": {},
            "performance": {},
            "resources": {}
        }
        
        async with self.db_pool.acquire() as conn:
            # 1. Schema size and table statistics
            size_stats = await conn.fetchrow("""
                WITH schema_size AS (
                    SELECT 
                        sum(pg_total_relation_size(schemaname||'.'||tablename))::bigint as total_size,
                        count(distinct tablename) as table_count,
                        sum(n_live_tup) as total_rows
                    FROM pg_stat_user_tables
                    WHERE schemaname = $1
                )
                SELECT * FROM schema_size
            """, schema_name)
            
            metrics["database"]["size_bytes"] = size_stats["total_size"] or 0
            metrics["database"]["table_count"] = size_stats["table_count"] or 0
            metrics["database"]["total_rows"] = size_stats["total_rows"] or 0
            
            # Update Prometheus metric
            self.schema_size_gauge.labels(
                tenant_id=tenant_id,
                schema_name=schema_name
            ).set(metrics["database"]["size_bytes"])
            
            # 2. Connection metrics
            conn_stats = await conn.fetchrow("""
                SELECT 
                    count(*) as total_connections,
                    count(*) FILTER (WHERE state = 'active') as active_queries,
                    count(*) FILTER (WHERE state = 'idle') as idle_connections,
                    max(EXTRACT(epoch FROM (now() - state_change))) as longest_connection_seconds
                FROM pg_stat_activity
                WHERE datname = current_database()
                AND usename = $1 || '_user'
            """, schema_name)
            
            metrics["performance"]["connections"] = {
                "total": conn_stats["total_connections"] or 0,
                "active": conn_stats["active_queries"] or 0,
                "idle": conn_stats["idle_connections"] or 0,
                "longest_seconds": conn_stats["longest_connection_seconds"] or 0
            }
            
            self.connection_gauge.labels(
                tenant_id=tenant_id,
                schema_name=schema_name
            ).set(conn_stats["total_connections"] or 0)
            
            # 3. Query performance (if pg_stat_statements available)
            try:
                query_stats = await conn.fetch("""
                    SELECT 
                        queryid,
                        calls,
                        total_exec_time,
                        mean_exec_time,
                        stddev_exec_time,
                        rows
                    FROM pg_stat_statements
                    WHERE query LIKE '%' || $1 || '%'
                    AND calls > 0
                    ORDER BY total_exec_time DESC
                    LIMIT 10
                """, schema_name)
                
                metrics["performance"]["top_queries"] = [
                    {
                        "calls": row["calls"],
                        "total_time_ms": row["total_exec_time"],
                        "mean_time_ms": row["mean_exec_time"],
                        "rows_returned": row["rows"]
                    }
                    for row in query_stats
                ]
            except:
                metrics["performance"]["top_queries"] = []
            
            # 4. Resource usage
            metrics["resources"]["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            metrics["resources"]["memory_mb"] = psutil.virtual_memory().used / 1024 / 1024
            
            # 5. Business metrics
            business_stats = await conn.fetchrow(f"""
                SELECT 
                    (SELECT COUNT(*) FROM {schema_name}.portfolios) as portfolio_count,
                    (SELECT COUNT(*) FROM {schema_name}.positions) as position_count,
                    (SELECT COUNT(*) FROM {schema_name}.trades 
                     WHERE executed_at > NOW() - INTERVAL '24 hours') as trades_24h
            """)
            
            metrics["business"] = dict(business_stats)
        
        # Cache metrics in Redis
        await self.redis.setex(
            f"metrics:{tenant_id}",
            300,  # 5 minute TTL
            json.dumps(metrics)
        )
        
        return metrics
    
    async def check_resource_limits(self, tenant_id: str, metrics: Dict) -> List[Dict]:
        """Check if tenant is approaching resource limits."""
        alerts = []
        
        # Get tenant limits
        limits = await self._get_tenant_limits(tenant_id)
        
        # Check database size
        size_bytes = metrics["database"]["size_bytes"]
        size_limit = limits.get("max_schema_size_gb", 100) * 1024 * 1024 * 1024
        
        if size_bytes > size_limit * 0.9:  # 90% threshold
            alerts.append({
                "type": "schema_size_limit",
                "severity": "critical",
                "message": f"Schema size {size_bytes / 1024 / 1024 / 1024:.2f}GB approaching limit {limits['max_schema_size_gb']}GB",
                "value": size_bytes,
                "limit": size_limit
            })
        
        # Check connections
        connections = metrics["performance"]["connections"]["total"]
        conn_limit = limits.get("max_connections", 50)
        
        if connections > conn_limit * 0.8:  # 80% threshold
            alerts.append({
                "type": "connection_limit",
                "severity": "warning",
                "message": f"Connections {connections} approaching limit {conn_limit}",
                "value": connections,
                "limit": conn_limit
            })
        
        return alerts
```

## Backup and Recovery

### Automated Backup System

```python
# tenant-service/app/services/backup_service.py
import subprocess
import boto3
from datetime import datetime, timedelta

class TenantBackupService:
    def __init__(self, db_config: Dict, s3_config: Dict):
        self.db_config = db_config
        self.s3 = boto3.client('s3', **s3_config)
        self.bucket = s3_config['bucket']
        
    async def create_tenant_backup(
        self, 
        tenant_id: str, 
        schema_name: str,
        backup_type: str = "scheduled"
    ) -> Dict:
        """Create point-in-time backup of tenant schema."""
        backup_id = f"{tenant_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        backup_file = f"/tmp/{backup_id}.dump"
        
        try:
            # 1. Create schema-specific backup using pg_dump
            dump_command = [
                "pg_dump",
                f"--dbname={self.db_config['dsn']}",
                f"--schema={schema_name}",
                "--format=custom",
                "--compress=9",
                "--no-owner",
                "--no-privileges",
                "--verbose",
                f"--file={backup_file}"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *dump_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Backup failed: {stderr.decode()}")
            
            # 2. Get backup file size
            file_size = os.path.getsize(backup_file)
            
            # 3. Upload to S3 with encryption
            s3_key = f"tenants/{tenant_id}/backups/{backup_id}.dump"
            
            self.s3.upload_file(
                backup_file,
                self.bucket,
                s3_key,
                ExtraArgs={
                    'ServerSideEncryption': 'AES256',
                    'StorageClass': 'STANDARD_IA',
                    'Metadata': {
                        'tenant_id': tenant_id,
                        'schema_name': schema_name,
                        'backup_type': backup_type,
                        'backup_date': datetime.utcnow().isoformat()
                    }
                }
            )
            
            # 4. Create backup record
            backup_record = {
                "backup_id": backup_id,
                "tenant_id": tenant_id,
                "schema_name": schema_name,
                "backup_type": backup_type,
                "file_size": file_size,
                "s3_key": s3_key,
                "created_at": datetime.utcnow(),
                "expires_at": self._calculate_expiry(backup_type)
            }
            
            await self._save_backup_record(backup_record)
            
            # 5. Clean up local file
            os.remove(backup_file)
            
            return backup_record
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(backup_file):
                os.remove(backup_file)
            raise
    
    async def restore_tenant_backup(
        self,
        tenant_id: str,
        backup_id: str,
        target_schema: Optional[str] = None
    ) -> Dict:
        """Restore tenant schema from backup."""
        # 1. Get backup metadata
        backup = await self._get_backup_record(tenant_id, backup_id)
        if not backup:
            raise Exception(f"Backup {backup_id} not found")
        
        # 2. Download from S3
        local_file = f"/tmp/restore_{backup_id}.dump"
        self.s3.download_file(
            self.bucket,
            backup['s3_key'],
            local_file
        )
        
        try:
            # 3. Determine target schema
            if not target_schema:
                target_schema = backup['schema_name']
            
            # 4. Drop existing schema if requested
            async with self.db_pool.acquire() as conn:
                await conn.execute(f"""
                    DROP SCHEMA IF EXISTS {target_schema} CASCADE
                """)
            
            # 5. Restore backup
            restore_command = [
                "pg_restore",
                f"--dbname={self.db_config['dsn']}",
                f"--schema={backup['schema_name']}",
                "--no-owner",
                "--no-privileges",
                "--clean",
                "--if-exists",
                "--verbose",
                local_file
            ]
            
            # If restoring to different schema, need to rename
            if target_schema != backup['schema_name']:
                # This requires post-processing
                restore_command.extend([
                    "--file=-",  # Output to stdout
                ])
                
                process = await asyncio.create_subprocess_exec(
                    *restore_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                # Replace schema names in the dump
                restored_sql = stdout.decode().replace(
                    backup['schema_name'],
                    target_schema
                )
                
                # Apply the modified SQL
                async with self.db_pool.acquire() as conn:
                    await conn.execute(restored_sql)
            else:
                # Direct restore
                process = await asyncio.create_subprocess_exec(
                    *restore_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode != 0:
                    raise Exception(f"Restore failed: {stderr.decode()}")
            
            # 6. Re-apply security policies
            security_manager = TenantSecurityManager(self.db_pool)
            await security_manager.apply_tenant_isolation(target_schema, tenant_id)
            
            # 7. Log restore operation
            await self._log_restore_operation(tenant_id, backup_id, target_schema)
            
            return {
                "status": "success",
                "backup_id": backup_id,
                "restored_to": target_schema,
                "restored_at": datetime.utcnow().isoformat()
            }
            
        finally:
            # Clean up
            if os.path.exists(local_file):
                os.remove(local_file)
    
    def _calculate_expiry(self, backup_type: str) -> datetime:
        """Calculate backup expiry based on retention policy."""
        retention_days = {
            "scheduled": 7,      # Daily backups kept for 7 days
            "weekly": 30,        # Weekly backups kept for 30 days
            "monthly": 365,      # Monthly backups kept for 1 year
            "manual": 90,        # Manual backups kept for 90 days
            "pre_migration": 180 # Pre-migration backups kept for 180 days
        }
        
        days = retention_days.get(backup_type, 30)
        return datetime.utcnow() + timedelta(days=days)
```

## Configuration Management

### Dynamic Configuration System

```yaml
# tenant-service/config/tenant_templates.yaml
templates:
  basic:
    name: "Basic Trading"
    description: "Standard trading features"
    features:
      - portfolios
      - positions
      - trades
      - basic_analytics
    limits:
      max_portfolios: 5
      max_positions_per_portfolio: 100
      max_trades_per_day: 1000
      max_api_calls_per_minute: 100
      max_schema_size_gb: 10
      max_connections: 25
    
  professional:
    name: "Professional Trading"
    description: "Advanced trading features"
    features:
      - portfolios
      - positions
      - trades
      - advanced_analytics
      - algorithmic_trading
      - risk_management
      - backtesting
    limits:
      max_portfolios: 50
      max_positions_per_portfolio: 1000
      max_trades_per_day: 10000
      max_api_calls_per_minute: 1000
      max_schema_size_gb: 100
      max_connections: 100
    
  enterprise:
    name: "Enterprise Trading"
    description: "Full platform capabilities"
    features:
      - all
    limits:
      max_portfolios: unlimited
      max_positions_per_portfolio: unlimited
      max_trades_per_day: unlimited
      max_api_calls_per_minute: 10000
      max_schema_size_gb: 1000
      max_connections: 500
```

## Error Handling and Logging

### Comprehensive Error Management

```python
# tenant-service/app/services/error_handler.py
class TenantErrorHandler:
    def __init__(self, logger, alert_service):
        self.logger = logger
        self.alert_service = alert_service
        
    async def handle_provisioning_error(
        self, 
        tenant_id: str, 
        error: Exception,
        context: Dict
    ):
        """Handle errors during tenant provisioning."""
        error_id = str(uuid.uuid4())
        
        # Classify error
        if isinstance(error, asyncio.TimeoutError):
            error_type = "timeout"
            severity = "critical"
            user_message = "Tenant provisioning timed out. Please try again."
        elif "permission denied" in str(error).lower():
            error_type = "permission"
            severity = "critical"
            user_message = "Database permission error. Contact support."
        elif "already exists" in str(error).lower():
            error_type = "duplicate"
            severity = "warning"
            user_message = "Tenant already exists."
        else:
            error_type = "unknown"
            severity = "error"
            user_message = "An error occurred during provisioning."
        
        # Log detailed error
        self.logger.error(
            "Tenant provisioning failed",
            error_id=error_id,
            tenant_id=tenant_id,
            error_type=error_type,
            error_message=str(error),
            context=context,
            stack_trace=traceback.format_exc()
        )
        
        # Send alert for critical errors
        if severity == "critical":
            await self.alert_service.send_alert({
                "type": "provisioning_failure",
                "severity": severity,
                "tenant_id": tenant_id,
                "error_id": error_id,
                "message": str(error)
            })
        
        # Return sanitized error response
        return {
            "error_id": error_id,
            "message": user_message,
            "tenant_id": tenant_id,
            "timestamp": datetime.utcnow().isoformat()
        }
```

## Testing Suite

### Comprehensive Test Coverage

```python
# tests/test_tenant_isolation.py
import pytest
import asyncio
from uuid import uuid4

class TestTenantIsolation:
    @pytest.mark.asyncio
    async def test_absolute_data_isolation(self, db_pool):
        """Verify complete data isolation between tenants."""
        provisioner = SchemaProvisioner(db_pool)
        
        # Create two tenants
        tenant1_id = str(uuid4())
        tenant2_id = str(uuid4())
        
        tenant1 = await provisioner.provision_tenant_schema(tenant1_id)
        tenant2 = await provisioner.provision_tenant_schema(tenant2_id)
        
        # Insert data in tenant1
        async with db_pool.acquire() as conn:
            await conn.execute(f"""
                INSERT INTO {tenant1['schema_name']}.portfolios 
                (user_id, name) VALUES 
                ('{uuid4()}', 'Test Portfolio')
            """)
        
        # Try to access tenant1 data from tenant2 context
        # This should fail
        with pytest.raises(Exception) as exc_info:
            async with db_pool.acquire() as conn:
                # Set role to tenant2 user
                await conn.execute(f"SET ROLE {tenant2['schema_name']}_user")
                
                # Try to access tenant1 data
                await conn.fetch(f"""
                    SELECT * FROM {tenant1['schema_name']}.portfolios
                """)
        
        assert "permission denied" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_schema_creation_performance(self, db_pool):
        """Verify schema creation completes in <10 seconds."""
        provisioner = SchemaProvisioner(db_pool)
        
        results = []
        for i in range(5):
            start = time.time()
            tenant = await provisioner.provision_tenant_schema(str(uuid4()))
            duration = time.time() - start
            results.append(duration)
            
            assert duration < 10, f"Schema creation took {duration}s"
        
        avg_time = sum(results) / len(results)
        assert avg_time < 5, f"Average creation time {avg_time}s exceeds target"
    
    @pytest.mark.asyncio
    async def test_concurrent_schema_creation(self, db_pool):
        """Test creating 100 schemas concurrently."""
        provisioner = SchemaProvisioner(db_pool)
        
        # Create 100 tenants concurrently
        tasks = []
        for i in range(100):
            task = provisioner.provision_tenant_schema(str(uuid4()))
            tasks.append(task)
        
        start = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start
        
        # Check results
        successful = sum(1 for r in results if isinstance(r, dict))
        failed = sum(1 for r in results if isinstance(r, Exception))
        
        assert successful >= 95, f"Only {successful}/100 schemas created successfully"
        assert duration < 300, f"Concurrent creation took {duration}s"
        
        # Verify each successful schema is isolated
        for result in results:
            if isinstance(result, dict):
                security_manager = TenantSecurityManager(db_pool)
                assert await security_manager.validate_tenant_isolation(
                    result['schema_name']
                )
```

## Performance Benchmarks

### Expected Performance Metrics

```yaml
performance_targets:
  schema_creation:
    average: 3 seconds
    p95: 7 seconds
    p99: 9 seconds
    max: 10 seconds
  
  concurrent_operations:
    100_schemas: 180 seconds
    connection_pool_size: 100
    parallel_operations: 20
  
  query_performance:
    simple_select: <10ms
    complex_join: <100ms
    aggregation: <500ms
    bulk_insert_1000_rows: <1s
  
  backup_restore:
    1gb_schema_backup: 30 seconds
    1gb_schema_restore: 45 seconds
    10gb_schema_backup: 5 minutes
    10gb_schema_restore: 8 minutes
  
  resource_usage:
    schema_overhead: 5MB
    connection_overhead: 10MB
    index_overhead: 20% of data size
```

## Deployment Checklist

### Pre-deployment Validation

- [ ] PostgreSQL 15+ installed with TimescaleDB extension
- [ ] PgBouncer configured with proper limits
- [ ] Read replicas configured and tested
- [ ] Backup storage (S3) configured
- [ ] Monitoring infrastructure ready
- [ ] Security scan completed
- [ ] Load testing passed
- [ ] Disaster recovery plan documented
- [ ] Team trained on procedures

### Post-deployment Monitoring

- [ ] Schema creation times <10s verified
- [ ] No cross-tenant data access confirmed
- [ ] Backup automation working
- [ ] Alerts configured and tested
- [ ] Performance baselines established
