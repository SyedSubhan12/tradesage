# app/services/monitoring_service.py

import asyncio
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import asyncpg
from redis import Redis

logger = structlog.get_logger(__name__)


class TenantMonitoringService:
    """Service for monitoring tenant resource usage and health."""
    
    def __init__(self, db_session_factory, redis_client: Redis):
        """Initialize the monitoring service.
        
        Args:
            db_session_factory: Factory for creating database sessions
            redis_client: Redis client for caching metrics
        """
        self.db_session_factory = db_session_factory
        self.redis = redis_client
        self.metric_cache_ttl = 300  # 5 minutes
        
    async def collect_tenant_metrics(self, tenant_id: str, schema_name: str) -> Dict[str, Any]:
        """Collect comprehensive metrics for a tenant schema.
        
        Args:
            tenant_id: Tenant identifier
            schema_name: Database schema name
            
        Returns:
            Dictionary containing various metrics
        """
        async with self.db_session_factory() as session:
            try:
                # Collect storage metrics
                storage_metrics = await self._collect_storage_metrics(session, schema_name)
                
                # Collect performance metrics
                performance_metrics = await self._collect_performance_metrics(session, schema_name)
                
                # Collect usage metrics
                usage_metrics = await self._collect_usage_metrics(session, schema_name)
                
                # Combine all metrics
                metrics = {
                    "tenant_id": tenant_id,
                    "schema_name": schema_name,
                    "collected_at": datetime.utcnow().isoformat(),
                    "storage": storage_metrics,
                    "performance": performance_metrics,
                    "usage": usage_metrics
                }
                
                # Store in database
                await self._store_metrics(session, tenant_id, schema_name, metrics)
                
                # Cache in Redis
                await self._cache_metrics(tenant_id, metrics)
                
                logger.info(
                    "Metrics collected",
                    tenant_id=tenant_id,
                    schema_name=schema_name
                )
                
                return metrics
                
            except Exception as e:
                logger.error(
                    "Failed to collect metrics",
                    tenant_id=tenant_id,
                    error=str(e),
                    exc_info=True
                )
                raise
    
    async def _collect_storage_metrics(self, session: AsyncSession, schema_name: str) -> Dict[str, Any]:
        """Collect storage-related metrics."""
        # Get total schema size
        size_query = text("""
            SELECT 
                pg_size_pretty(sum(pg_total_relation_size(schemaname||'.'||tablename))) as total_size,
                sum(pg_total_relation_size(schemaname||'.'||tablename)) as size_bytes,
                count(*) as table_count
            FROM pg_tables
            WHERE schemaname = :schema_name
        """)
        
        result = await session.execute(size_query, {"schema_name": schema_name})
        storage_data = result.first()
        
        # Get table sizes
        table_sizes_query = text("""
            SELECT 
                tablename,
                pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
            FROM pg_tables
            WHERE schemaname = :schema_name
            ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
            LIMIT 10
        """)
        
        table_result = await session.execute(table_sizes_query, {"schema_name": schema_name})
        top_tables = [
            {
                "table_name": row.tablename,
                "size": row.size,
                "size_bytes": row.size_bytes
            }
            for row in table_result
        ]
        
        # Get index count and size
        index_query = text("""
            SELECT 
                count(*) as index_count,
                pg_size_pretty(sum(pg_relation_size(indexrelid))) as total_index_size
            FROM pg_indexes
            JOIN pg_class ON pg_class.relname = indexname
            WHERE schemaname = :schema_name
        """)
        
        index_result = await session.execute(index_query, {"schema_name": schema_name})
        index_data = index_result.first()
        
        return {
            "total_size": storage_data.total_size if storage_data else "0 bytes",
            "size_bytes": storage_data.size_bytes if storage_data else 0,
            "table_count": storage_data.table_count if storage_data else 0,
            "index_count": index_data.index_count if index_data else 0,
            "index_size": index_data.total_index_size if index_data else "0 bytes",
            "top_tables": top_tables
        }
    
    async def _collect_performance_metrics(self, session: AsyncSession, schema_name: str) -> Dict[str, Any]:
        """Collect performance-related metrics."""
        # Get query statistics
        query_stats = text("""
            SELECT 
                count(*) as total_queries,
                avg(mean_exec_time) as avg_query_time_ms,
                max(mean_exec_time) as max_query_time_ms,
                sum(calls) as total_calls
            FROM pg_stat_statements
            WHERE query LIKE '%' || :schema_name || '%'
            AND query NOT LIKE '%pg_stat_statements%'
        """)
        
        try:
            stats_result = await session.execute(query_stats, {"schema_name": schema_name})
            stats_data = stats_result.first()
        except:
            # pg_stat_statements might not be enabled
            stats_data = None
        
        # Get connection count
        conn_query = text("""
            SELECT count(*) as active_connections
            FROM pg_stat_activity
            WHERE datname = current_database()
            AND query LIKE '%' || :schema_name || '%'
            AND state != 'idle'
        """)
        
        conn_result = await session.execute(conn_query, {"schema_name": schema_name})
        conn_data = conn_result.first()
        
        # Get cache hit ratio
        cache_query = text("""
            SELECT 
                sum(heap_blks_hit) / nullif(sum(heap_blks_hit) + sum(heap_blks_read), 0) as cache_hit_ratio
            FROM pg_statio_user_tables
            WHERE schemaname = :schema_name
        """)
        
        cache_result = await session.execute(cache_query, {"schema_name": schema_name})
        cache_data = cache_result.first()
        
        return {
            "avg_query_time_ms": float(stats_data.avg_query_time_ms) if stats_data and stats_data.avg_query_time_ms else 0,
            "max_query_time_ms": float(stats_data.max_query_time_ms) if stats_data and stats_data.max_query_time_ms else 0,
            "total_queries": stats_data.total_queries if stats_data else 0,
            "active_connections": conn_data.active_connections if conn_data else 0,
            "cache_hit_ratio": float(cache_data.cache_hit_ratio) if cache_data and cache_data.cache_hit_ratio else 0
        }
    
    async def _collect_usage_metrics(self, session: AsyncSession, schema_name: str) -> Dict[str, Any]:
        """Collect usage-related metrics."""
        # Get row counts for main tables
        row_counts = {}
        
        # Get list of tables
        tables_query = text("""
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = :schema_name
            AND tablename NOT LIKE 'pg_%'
            ORDER BY tablename
        """)
        
        tables_result = await session.execute(tables_query, {"schema_name": schema_name})
        
        for row in tables_result:
            table_name = row.tablename
            count_query = text(f"""
                SELECT count(*) as row_count
                FROM "{schema_name}"."{table_name}"
            """)
            
            try:
                count_result = await session.execute(count_query)
                count_data = count_result.first()
                row_counts[table_name] = count_data.row_count if count_data else 0
            except:
                row_counts[table_name] = "error"
        
        # Get transaction count
        tx_query = text("""
            SELECT 
                xact_commit + xact_rollback as total_transactions,
                xact_commit as commits,
                xact_rollback as rollbacks
            FROM pg_stat_database
            WHERE datname = current_database()
        """)
        
        tx_result = await session.execute(tx_query)
        tx_data = tx_result.first()
        
        return {
            "row_counts": row_counts,
            "total_rows": sum(v for v in row_counts.values() if isinstance(v, int)),
            "transactions": {
                "total": tx_data.total_transactions if tx_data else 0,
                "commits": tx_data.commits if tx_data else 0,
                "rollbacks": tx_data.rollbacks if tx_data else 0
            }
        }
    
    async def _store_metrics(
        self, 
        session: AsyncSession, 
        tenant_id: str, 
        schema_name: str, 
        metrics: Dict[str, Any]
    ):
        """Store metrics in the database."""
        # Store storage metrics
        await session.execute(text("""
            INSERT INTO tenant_metrics (tenant_id, schema_name, metric_type, metric_value)
            VALUES (:tenant_id, :schema_name, 'storage', :metric_value)
        """), {
            "tenant_id": tenant_id,
            "schema_name": schema_name,
            "metric_value": json.dumps(metrics["storage"])
        })
        
        # Store performance metrics
        await session.execute(text("""
            INSERT INTO tenant_metrics (tenant_id, schema_name, metric_type, metric_value)
            VALUES (:tenant_id, :schema_name, 'performance', :metric_value)
        """), {
            "tenant_id": tenant_id,
            "schema_name": schema_name,
            "metric_value": json.dumps(metrics["performance"])
        })
        
        # Store usage metrics
        await session.execute(text("""
            INSERT INTO tenant_metrics (tenant_id, schema_name, metric_type, metric_value)
            VALUES (:tenant_id, :schema_name, 'usage', :metric_value)
        """), {
            "tenant_id": tenant_id,
            "schema_name": schema_name,
            "metric_value": json.dumps(metrics["usage"])
        })
        
        await session.commit()
    
    async def _cache_metrics(self, tenant_id: str, metrics: Dict[str, Any]):
        """Cache metrics in Redis."""
        cache_key = f"tenant:metrics:{tenant_id}"
        await self.redis.setex(
            cache_key,
            self.metric_cache_ttl,
            json.dumps(metrics)
        )
    
    async def get_tenant_metrics(
        self, 
        tenant_id: str, 
        from_cache: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Get tenant metrics from cache or database."""
        if from_cache:
            cache_key = f"tenant:metrics:{tenant_id}"
            cached = await self.redis.get(cache_key)
            if cached:
                return json.loads(cached)
        
        # Get from database
        async with self.db_session_factory() as session:
            query = text("""
                SELECT metric_type, metric_value, collected_at
                FROM tenant_metrics
                WHERE tenant_id = :tenant_id
                AND collected_at > :since
                ORDER BY collected_at DESC
            """)
            
            result = await session.execute(query, {
                "tenant_id": tenant_id,
                "since": datetime.utcnow() - timedelta(hours=1)
            })
            
            metrics = {}
            for row in result:
                metrics[row.metric_type] = row.metric_value
            
            return metrics if metrics else None
    
    async def get_tenant_health_status(self, tenant_id: str) -> str:
        """Determine tenant health status based on metrics."""
        metrics = await self.get_tenant_metrics(tenant_id)
        
        if not metrics:
            return "unknown"
        
        # Check various health indicators
        health_score = 100
        
        # Check storage usage (if > 80% of limit, reduce score)
        if "storage" in metrics:
            size_bytes = metrics["storage"].get("size_bytes", 0)
            size_limit = 10 * 1024 * 1024 * 1024  # 10GB limit
            usage_percent = (size_bytes / size_limit) * 100
            
            if usage_percent > 80:
                health_score -= 20
            elif usage_percent > 90:
                health_score -= 40
        
        # Check performance
        if "performance" in metrics:
            avg_query_time = metrics["performance"].get("avg_query_time_ms", 0)
            if avg_query_time > 100:  # > 100ms average
                health_score -= 20
            elif avg_query_time > 500:  # > 500ms average
                health_score -= 40
        
        # Determine status
        if health_score >= 80:
            return "healthy"
        elif health_score >= 60:
            return "degraded"
        else:
            return "unhealthy" 