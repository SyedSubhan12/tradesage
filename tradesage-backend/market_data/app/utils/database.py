import psycopg2
import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import asynccontextmanager
import redis
import redis.asyncio
from redis.cluster import ClusterNode
from psycopg2.extras import RealDictCursor
import pandas as pd
import json
from datetime import datetime
from .config import get_settings
import logging
from typing import List, Dict, Optional, Any, AsyncGenerator
import os
from urllib.parse import urlparse
import time
import asyncio
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OptimizedDatabaseManager:
    """Production-grade database manager with separate read/write pools and advanced caching"""
    
    def __init__(self, config):
        self.config = config
        self.read_pool: Optional[asyncpg.pool.Pool] = None
        self.write_pool: Optional[asyncpg.pool.Pool] = None
        self.redis_cluster = None
        self.connection_health = {
            'read_pool': True,
            'write_pool': True,
            'redis': True
        }
        self.metrics = {
            'read_queries': 0,
            'write_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

    def _clean_database_url(self, url: str) -> str:
        """Clean SQLAlchemy-style DSN for use with asyncpg"""
        if '+asyncpg' in url:
            url = url.replace('+asyncpg', '')
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql://', 1)
        return url

    async def initialize(self):
        """Initialize optimized connection pools with circuit breaker protection"""
        try:
            # Get database URLs
            raw_database_url = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/postgres")
            self.asyncpg_database_url = self._clean_database_url(raw_database_url)
            
            # Read replica URL (fallback to primary if not set)
            read_replica_url = os.getenv("READ_REPLICA_URL", self.asyncpg_database_url)
            
            logger.info(f"Primary DB: {self.asyncpg_database_url}")
            logger.info(f"Read Replica: {read_replica_url}")

            # ----------------------- Optimized Connection Pools -----------------------
            
            # Read pool (for queries) - higher concurrency
            self.read_pool = await asyncpg.create_pool(
                dsn=read_replica_url,
                min_size=20,
                max_size=100,
                command_timeout=5,  # Fast timeout for reads
                max_inactive_connection_lifetime=300,
                server_settings={
                    'jit': 'off',  # Disable JIT for faster small queries
                    'application_name': 'tradesage_read_pool'
                }
            )
            
            # Write pool (for inserts/updates) - smaller pool, longer timeout
            self.write_pool = await asyncpg.create_pool(
                dsn=self.asyncpg_database_url,
                min_size=5,
                max_size=20,
                command_timeout=30,  # Longer timeout for writes
                max_inactive_connection_lifetime=600,
                server_settings={
                    'synchronous_commit': 'off',  # Faster writes
                    'application_name': 'tradesage_write_pool'
                }
            )

            # ----------------------- Redis Cluster Setup -----------------------
            redis_nodes = os.getenv("REDIS_CLUSTER_NODES", "localhost:7000,localhost:7001,localhost:7002").split(",")
            
            if len(redis_nodes) > 1:
                # Redis Cluster mode for production
                startup_nodes = [
                    ClusterNode(node.split(":")[0], int(node.split(":")[1]))
                    for node in redis_nodes
                ]
                
                self.redis_cluster = redis.asyncio.RedisCluster(startup_nodes=startup_nodes, decode_responses=True)
            else:
                # Single Redis instance for development
                redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
                self.redis_cluster = redis.asyncio.from_url(redis_url, decode_responses=True)

            # ----------------------- Synchronous Engine for ORM -----------------------
            self.sync_engine = create_engine(
                self.asyncpg_database_url,
                pool_pre_ping=True,
                pool_recycle=3600,
                pool_size=20,
                max_overflow=40,
                echo=False  # Disable SQL logging in production
            )
            
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.sync_engine
            )

            # Test all connections
            await self._test_connections()
            logger.info("Optimized database and Redis initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize optimized database: {e}")
            raise

    async def _test_connections(self):
        """Test all connection pools with health checks"""
        try:
            # Test read pool
            async with self.read_pool.acquire() as conn:
                result = await conn.fetchval('SELECT 1')
                logger.info(f"Read pool test: {result}")
                
            # Test write pool
            async with self.write_pool.acquire() as conn:
                result = await conn.fetchval('SELECT 1')
                logger.info(f"Write pool test: {result}")
            
            # Test Redis
            await self.redis_cluster.ping()
            logger.info("Redis cluster connection test successful")
            
            # Update health status
            self.connection_health = {
                'read_pool': True,
                'write_pool': True,
                'redis': True
            }
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            self._update_health_status(e)
            raise

    def _update_health_status(self, error: Exception):
        """Update connection health status based on error"""
        error_str = str(error).lower()
        if 'read' in error_str:
            self.connection_health['read_pool'] = False
        elif 'write' in error_str:
            self.connection_health['write_pool'] = False
        elif 'redis' in error_str:
            self.connection_health['redis'] = False

    @asynccontextmanager
    async def get_read_connection(self):
        """Get optimized read connection with circuit breaker"""
        if not self.connection_health['read_pool']:
            raise Exception("Read pool is unhealthy")
        
        start_time = time.time()
        try:
            async with self.read_pool.acquire() as conn:
                yield conn
                self.metrics['read_queries'] += 1
        except Exception as e:
            self._update_health_status(e)
            raise
        finally:
            query_time = time.time() - start_time
            if query_time > 1.0:  # Log slow queries
                logger.warning(f"Slow read query: {query_time:.2f}s")

    @asynccontextmanager 
    async def get_write_connection(self):
        """Get optimized write connection with circuit breaker"""
        if not self.connection_health['write_pool']:
            raise Exception("Write pool is unhealthy")
        
        start_time = time.time()
        try:
            async with self.write_pool.acquire() as conn:
                yield conn
                self.metrics['write_queries'] += 1
        except Exception as e:
            self._update_health_status(e)
            raise
        finally:
            query_time = time.time() - start_time
            if query_time > 5.0:  # Log slow writes
                logger.warning(f"Slow write query: {query_time:.2f}s")

    # ----------------------- FastAPI Dependencies -----------------------
    
    def get_sync_session(self) -> Session:
        """Return a new synchronous SQLAlchemy session"""
        return self.SessionLocal()

    def get_db(self):
        """Yield database session for FastAPI dependency."""
        db = self.get_sync_session()
        try:
            yield db
        finally:
            db.close()

    # ----------------------- High-Performance Data Operations -----------------------

    async def bulk_insert_ohlcv(self, records: List[Dict]) -> int:
        """Optimized bulk insert using COPY protocol"""
        if not records:
            return 0
        
        # Sort by timestamp for better index performance
        records.sort(key=lambda x: x['timestamp'])
        
        copy_sql = """
        COPY ohlcv_data (symbol, dataset, timeframe, timestamp, open, high, low, close, volume, vwap, trades_count)
        FROM STDIN WITH (FORMAT CSV, HEADER false)
        """
        
        async with self.get_write_connection() as conn:
            # Prepare CSV data
            csv_data = []
            for record in records:
                csv_data.append([
                    record['symbol'],
                    record['dataset'], 
                    record['timeframe'],
                    record['timestamp'],
                    record.get('open'),
                    record.get('high'),
                    record.get('low'),
                    record.get('close'),
                    record.get('volume'),
                    record.get('vwap'),
                    record.get('trades_count')
                ])
            
            result = await conn.copy_records_to_table(
                'ohlcv_data',
                records=csv_data,
                columns=['symbol', 'dataset', 'timeframe', 'timestamp', 'open', 'high', 'low', 'close', 'volume', 'vwap', 'trades_count']
            )
            
            logger.info(f"Bulk inserted {len(records)} OHLCV records")
            return len(records)

    async def upsert_ohlcv_batch(self, records: List[Dict]) -> int:
        """High-performance upsert using ON CONFLICT"""
        if not records:
            return 0
        
        upsert_sql = """
        INSERT INTO ohlcv_data (symbol, dataset, timeframe, timestamp, open, high, low, close, volume, vwap, trades_count)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (symbol, dataset, timeframe, timestamp) 
        DO UPDATE SET
            open = EXCLUDED.open,
            high = EXCLUDED.high,
            low = EXCLUDED.low,
            close = EXCLUDED.close,
            volume = EXCLUDED.volume,
            vwap = EXCLUDED.vwap,
            trades_count = EXCLUDED.trades_count
        """
        
        async with self.get_write_connection() as conn:
            await conn.executemany(upsert_sql, [
                (r['symbol'], r['dataset'], r['timeframe'], r['timestamp'],
                 r.get('open'), r.get('high'), r.get('low'), r.get('close'),
                 r.get('volume'), r.get('vwap'), r.get('trades_count'))
                for r in records
            ])
            
            return len(records)

    async def get_ohlcv_optimized(self, symbol: str, timeframe: str, 
                                start_date: datetime, end_date: datetime, 
                                dataset: str = None, limit: int = None) -> pd.DataFrame:
        """Optimized OHLCV retrieval with intelligent caching"""
        
        # Generate cache key
        cache_key = f"ohlcv:{symbol}:{timeframe}:{start_date.date()}:{end_date.date()}:{dataset or 'any'}"
        
        # Try Redis cache first
        try:
            cached_data = await self.redis_cluster.get(cache_key)
            if cached_data:
                self.metrics['cache_hits'] += 1
                logger.debug(f"Cache hit for {cache_key}")
                return pd.read_json(cached_data, orient='index')
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")
        
        self.metrics['cache_misses'] += 1
        
        # Build optimized query
        params = [symbol, timeframe, start_date, end_date]
        query = """
        SELECT timestamp, open, high, low, close, volume, vwap, trades_count
        FROM ohlcv_data 
        WHERE symbol = $1 AND timeframe = $2 AND timestamp >= $3 AND timestamp <= $4
        """
        
        if dataset:
            query += " AND dataset = $5"
            params.append(dataset)
        
        query += " ORDER BY timestamp"
        
        if limit:
            query += f" LIMIT ${len(params) + 1}"
            params.append(limit)
        
        # Execute query on read replica
        async with self.get_read_connection() as conn:
            rows = await conn.fetch(query, *params)
        
        # Convert to DataFrame
        if rows:
            df = pd.DataFrame([dict(row) for row in rows])
            df.set_index('timestamp', inplace=True)
            
            # Cache the result with appropriate TTL
            try:
                ttl = 300 if '1m' in timeframe else 3600 if '1d' in timeframe else 1800
                await self.redis_cluster.setex(cache_key, ttl, df.to_json(orient='index'))
            except Exception as e:
                logger.warning(f"Failed to cache data: {e}")
            
            return df
        
        return pd.DataFrame()

    async def get_symbols_cached(self, dataset: str = None) -> List[str]:
        """Get symbols with Redis caching"""
        cache_key = f"symbols:{dataset or 'all'}"
        
        try:
            cached_symbols = await self.redis_cluster.get(cache_key)
            if cached_symbols:
                self.metrics['cache_hits'] += 1
                return json.loads(cached_symbols)
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")
        
        self.metrics['cache_misses'] += 1
        
        # Query database
        query = "SELECT DISTINCT symbol FROM symbols WHERE is_active = true"
        params = []
        
        if dataset:
            query += " AND dataset = $1"
            params.append(dataset)
        
        async with self.get_read_connection() as conn:
            rows = await conn.fetch(query, *params)
        
        symbols = [row['symbol'] for row in rows]
        
        # Cache for 1 hour
        try:
            await self.redis_cluster.setex(cache_key, 3600, json.dumps(symbols))
        except Exception as e:
            logger.warning(f"Failed to cache symbols: {e}")
        
        return symbols

    # ----------------------- Advanced Caching Operations -----------------------

    async def pipeline_cache_operations(self, operations: List[Dict]) -> List:
        """Execute multiple Redis operations in a pipeline"""
        try:
            pipe = self.redis_cluster.pipeline()
            
            for op in operations:
                if op['command'] == 'get':
                    pipe.get(op['key'])
                elif op['command'] == 'set':
                    pipe.setex(op['key'], op['ttl'], op['value'])
                elif op['command'] == 'del':
                    pipe.delete(op['key'])
            
            return await pipe.execute()
        except Exception as e:
            logger.error(f"Pipeline cache operations failed: {e}")
            return []

    async def invalidate_pattern(self, pattern: str):
        """Efficiently invalidate cache entries matching pattern"""
        try:
            cursor = 0
            keys_to_delete = []
            
            while True:
                cursor, keys = await self.redis_cluster.scan(cursor, match=pattern, count=1000)
                keys_to_delete.extend(keys)
                
                if cursor == 0:
                    break
            
            if keys_to_delete:
                await self.redis_cluster.delete(*keys_to_delete)
                logger.info(f"Invalidated {len(keys_to_delete)} cache entries for pattern: {pattern}")
        except Exception as e:
            logger.error(f"Failed to invalidate cache pattern {pattern}: {e}")

    # ----------------------- Health and Metrics -----------------------

    def get_connection_stats(self) -> Dict:
        """Get connection pool statistics"""
        stats = {
            'health': self.connection_health,
            'metrics': self.metrics
        }
        
        if self.read_pool:
            stats['read_pool'] = {
                'size': self.read_pool.get_size(),
                'min_size': self.read_pool.get_min_size(),
                'max_size': self.read_pool.get_max_size(),
                'idle_connections': self.read_pool.get_idle_size()
            }
        
        if self.write_pool:
            stats['write_pool'] = {
                'size': self.write_pool.get_size(),
                'min_size': self.write_pool.get_min_size(), 
                'max_size': self.write_pool.get_max_size(),
                'idle_connections': self.write_pool.get_idle_size()
            }
        
        return stats

    async def health_check(self) -> Dict:
        """Comprehensive health check"""
        health_status = {'status': 'healthy', 'checks': {}}
        
        # Test read pool
        try:
            async with self.get_read_connection() as conn:
                await conn.fetchval('SELECT 1')
            health_status['checks']['read_pool'] = 'ok'
        except Exception as e:
            health_status['checks']['read_pool'] = f'error: {e}'
            health_status['status'] = 'unhealthy'
        
        # Test write pool
        try:
            async with self.get_write_connection() as conn:
                await conn.fetchval('SELECT 1')
            health_status['checks']['write_pool'] = 'ok'
        except Exception as e:
            health_status['checks']['write_pool'] = f'error: {e}'
            health_status['status'] = 'unhealthy'
        
        # Test Redis
        try:
            await self.redis_cluster.ping()
            health_status['checks']['redis'] = 'ok'
        except Exception as e:
            health_status['checks']['redis'] = f'error: {e}'
            health_status['status'] = 'unhealthy'
        
        return health_status

    async def close(self):
        """Gracefully close all connections"""
        try:
            if self.read_pool:
                await self.read_pool.close()
                logger.info("Read pool closed")
                
            if self.write_pool:
                await self.write_pool.close()
                logger.info("Write pool closed")
                
            if self.redis_cluster:
                await self.redis_cluster.aclose()
                logger.info("Redis cluster closed")
                
        except Exception as e:
            logger.error(f"Error closing connections: {e}")

# ----------------------- Singleton Instance -----------------------

_db_manager = None

def get_db_manager() -> OptimizedDatabaseManager:
    global _db_manager
    if _db_manager is None:
        settings = get_settings()
        _db_manager = OptimizedDatabaseManager(settings)
    return _db_manager

# ----------------------- Backward Compatibility -----------------------

# Keep original functions for existing code
def get_db():
    """Original dependency function for backward compatibility"""
    db_manager = get_db_manager()
    return db_manager.get_db()

class DatabaseManager:
    """Legacy class for backward compatibility"""
    def __init__(self, config):
        self.optimized_manager = OptimizedDatabaseManager(config)
    
    async def initialize(self):
        return await self.optimized_manager.initialize()
    
    async def close(self):
        return await self.optimized_manager.close()