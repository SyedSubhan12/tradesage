# app/services/schema_provisioner.py

import asyncio
import asyncpg
import secrets
import time
import hashlib
import json
from typing import Dict, Optional, List
from datetime import datetime
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = structlog.get_logger(__name__)


class SchemaProvisioner:
    """High-performance schema provisioning for multi-tenant system."""
    
    def __init__(self, db_pool: asyncpg.Pool):
        """Initialize the schema provisioner.
        
        Args:
            db_pool (asyncpg.Pool): Connection pool for database operations
            
        Attributes:
            db_pool (asyncpg.Pool): Pool of database connections for schema operations
            template_cache (dict): Cache for storing schema templates to optimize cloning
        """
        self.db_pool = db_pool
        self.template_cache = {}
        
    async def provision_tenant_schema(
        self, 
        tenant_id: str, 
        template: str = "trading"
    ) -> Dict:
        """
        Provision a new tenant schema in <10 seconds.
        
        Args:
            tenant_id: Unique tenant identifier
            template: Schema template to use
            
        Returns:
            Dict with schema details and provisioning metrics
        """
        start_time = time.time()
        
        # Generate cryptographically secure schema name
        schema_name = self._generate_schema_name(tenant_id)
        
        try:
            # Use dedicated connection for schema operations
            async with self.db_pool.acquire() as conn:
                # Begin transaction for atomicity
                async with conn.transaction():
                    # Step 1: Create schema (50ms)
                    await self._create_schema(conn, schema_name)
                    
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
                        schema_name,
                        template
                    )
                    
                    # Step 5: Initialize monitoring (100ms)
                    await self._initialize_monitoring(conn, schema_name)
                    
                    # Step 6: Create indexes in parallel (1-2s)
                    await self._create_indexes_parallel(conn, schema_name)
            
            provisioning_time = time.time() - start_time
            
            # Verify under 10 seconds
            if provisioning_time > 10:
                raise Exception(
                    f"Schema provisioning exceeded 10s: {provisioning_time:.2f}s"
                )
            
            logger.info(
                "Tenant schema provisioned successfully",
                tenant_id=tenant_id,
                schema_name=schema_name,
                provisioning_time=provisioning_time
            )
            
            return {
                "schema_name": schema_name,
                "tenant_id": tenant_id,
                "template": template,
                "provisioning_time": provisioning_time,
                "status": "active",
                "created_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            # Rollback is automatic with transaction
            await self._log_provisioning_failure(tenant_id, str(e))
            logger.error(
                "Schema provisioning failed",
                tenant_id=tenant_id,
                error=str(e),
                exc_info=True
            )
            raise
    
    def _generate_schema_name(self, tenant_id: str) -> str:
        """Generate cryptographically secure schema name."""
        # Use SHA256 of tenant_id + random salt
        salt = secrets.token_hex(8)
        hash_input = f"{tenant_id}:{salt}".encode()
        hash_output = hashlib.sha256(hash_input).hexdigest()[:12]
        return f"tenant_{hash_output}"
    
    async def _create_schema(self, conn: asyncpg.Connection, schema_name: str):
        """Create a new database schema."""
        # Check if schema already exists
        exists = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = $1)",
            schema_name
        )
        
        if exists:
            raise Exception(f"Schema {schema_name} already exists")
        
        # Create schema with proper permissions
        await conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"')
        
        # Set search path for this connection
        await conn.execute(f'SET search_path TO "{schema_name}", public')
        
        logger.info("Schema created", schema_name=schema_name)
    
    async def _clone_template_optimized(
        self, 
        conn: asyncpg.Connection, 
        template_schema: str, 
        target_schema: str
    ):
        """Clone template schema using parallel operations."""
        # Get all tables from template schema
        tables = await conn.fetch(f"""
            SELECT tablename 
            FROM pg_tables 
            WHERE schemaname = '{template_schema}'
            ORDER BY tablename
        """)
        
        # Clone tables in parallel batches
        batch_size = 5
        # for loop for batching 
        for i in range(0, len(tables), batch_size):
            batch = tables[i:i+batch_size]
            tasks = []
            
            for table in batch:
                table_name = table['tablename']
                # Create table structure
                create_sql = f"""
                    CREATE TABLE "{target_schema}"."{table_name}" 
                    (LIKE "{template_schema}"."{table_name}" 
                    INCLUDING ALL)
                """
                tasks.append(conn.execute(create_sql))
            
            await asyncio.gather(*tasks)
        
        # Clone sequences
        sequences = await conn.fetch(f"""
            SELECT sequence_name 
            FROM information_schema.sequences 
            WHERE sequence_schema = '{template_schema}'
        """)
        
        for seq in sequences:
            seq_name = seq['sequence_name']
            await conn.execute(f"""
                CREATE SEQUENCE "{target_schema}"."{seq_name}"
                AS BIGINT
                START WITH 1
            """)
        
        logger.info(
            "Template cloned", 
            template=template_schema, 
            target=target_schema,
            table_count=len(tables)
        )
    
    async def _apply_security_policies(self, conn: asyncpg.Connection, schema_name: str):
        """Apply row-level security policies to schema."""
        # Enable RLS on all tables
        tables = await conn.fetch(f"""
            SELECT tablename 
            FROM pg_tables 
            WHERE schemaname = '{schema_name}'
        """)
        
        for table in tables:
            table_name = table['tablename']
            
            # Enable RLS
            await conn.execute(f"""
                ALTER TABLE "{schema_name}"."{table_name}" 
                ENABLE ROW LEVEL SECURITY
            """)
            
            # Create default policy (tenant isolation)
            await conn.execute(f"""
                CREATE POLICY tenant_isolation_policy 
                ON "{schema_name}"."{table_name}"
                FOR ALL
                USING (true)  -- Will be customized per tenant
            """)
        
        # Revoke default permissions and grant specific ones
        await conn.execute(f"""
            REVOKE ALL ON SCHEMA "{schema_name}" FROM PUBLIC;
            GRANT USAGE ON SCHEMA "{schema_name}" TO tenant_role;
        """)
        
        logger.info("Security policies applied", schema_name=schema_name)
    
    async def _create_tenant_metadata(
        self, 
        conn: asyncpg.Connection, 
        tenant_id: str, 
        schema_name: str,
        template: str
    ):
        """Create tenant metadata record."""
        await conn.execute("""
            INSERT INTO tenant_schemas (
                tenant_id, 
                schema_name, 
                template_used,
                provisioning_time_seconds
            ) VALUES ($1, $2, $3, $4)
        """, tenant_id, schema_name, template, None)
        
        # Create tenant-specific configuration table
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS "{schema_name}".tenant_config (
                key VARCHAR(255) PRIMARY KEY,
                value JSONB NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        
        # Insert default configuration
        await conn.execute(f"""
            INSERT INTO "{schema_name}".tenant_config (key, value)
            VALUES 
                ('tenant_id', '"{tenant_id}"'::jsonb),
                ('schema_version', '"1.0.0"'::jsonb),
                ('features', '{{"trading": true, "analytics": true}}'::jsonb)
        """)
        
        logger.info("Tenant metadata created", tenant_id=tenant_id)
    
    async def _initialize_monitoring(self, conn: asyncpg.Connection, schema_name: str):
        """Initialize monitoring for the tenant schema."""
        # Create monitoring views
        await conn.execute(f"""
            CREATE OR REPLACE VIEW "{schema_name}".schema_statistics AS
            SELECT 
                nspname AS schema_name,
                pg_size_pretty(sum(pg_relation_size(C.oid))) AS total_size,
                count(DISTINCT C.oid) AS table_count
            FROM pg_class C
            LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
            WHERE nspname = '{schema_name}'
            AND C.relkind IN ('r', 'i')
            GROUP BY nspname
        """)
        
        # Create activity monitoring table
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS "{schema_name}".activity_log (
                id BIGSERIAL PRIMARY KEY,
                user_id UUID,
                action VARCHAR(100),
                resource VARCHAR(255),
                details JSONB,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        
        # Create index for performance
        await conn.execute(f"""
            CREATE INDEX idx_activity_log_created 
            ON "{schema_name}".activity_log(created_at DESC)
        """)
        
        logger.info("Monitoring initialized", schema_name=schema_name)
    
    async def _create_indexes_parallel(self, conn: asyncpg.Connection, schema_name: str):
        """Create indexes in parallel for better performance."""
        # Define indexes to create
        index_definitions = [
            # Add your specific index definitions here
            # Example:
            # (f'CREATE INDEX idx_orders_user ON "{schema_name}".orders(user_id)', ),
            # (f'CREATE INDEX idx_trades_timestamp ON "{schema_name}".trades(timestamp DESC)', ),
        ]
        
        # Create indexes concurrently
        if index_definitions:
            tasks = []
            for index_sql in index_definitions:
                tasks.append(conn.execute(index_sql))
            
            await asyncio.gather(*tasks)
            
        logger.info("Indexes created", schema_name=schema_name, count=len(index_definitions))
    
    async def _log_provisioning_failure(self, tenant_id: str, error: str):
        """Log provisioning failures for debugging."""
        # In production, this would write to a failure log table
        logger.error(
            "Provisioning failed",
            tenant_id=tenant_id,
            error=error,
            timestamp=datetime.utcnow().isoformat()
        )
