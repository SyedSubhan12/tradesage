import psycopg2
import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker, Session

# Initialize a global synchronous engine & SessionLocal for quick access by FastAPI dependencies
from .config import get_settings
_settings_instance = get_settings()
_GLOBAL_DATABASE_URL = _settings_instance.POSTGRES_URL.replace('+asyncpg', '')
_GLOBAL_ENGINE = create_engine(
    _GLOBAL_DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_GLOBAL_ENGINE)

def get_db():
    """FastAPI dependency to provide DB session using global engine."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

import redis
import redis.asyncio
from psycopg2.extras import RealDictCursor
import pandas as pd
import json
from datetime import datetime
from .config import settings
import logging
from typing import List, Dict, Optional, Any
import os
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, config: settings):
        self.config = config
        self.pg_pool: Optional[asyncpg.pool.Pool] = None
        self.redis_client = None

    def _clean_database_url(self, url: str) -> str:
        """Clean SQLAlchemy-style DSN for use with asyncpg"""
        # Remove +asyncpg from the scheme
        if '+asyncpg' in url:
            url = url.replace('+asyncpg', '')
        
        # Ensure we use postgresql:// scheme (asyncpg accepts both postgresql:// and postgres://)
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql://', 1)
            
        return url

    async def initialize(self):
        """Initialize database connection pool and redis client"""
        try:
            # Get database URL from environment or use default
            raw_database_url = os.getenv(
                "DATABASE_URL",
                "postgresql://postgres:postgres@localhost:5432/postgres"
            )
            
            # Clean URL for asyncpg (remove +asyncpg if present)
            self.asyncpg_database_url = self._clean_database_url(raw_database_url)
            
            # Keep original format for SQLAlchemy
            self.sqlalchemy_database_url = raw_database_url
            if not self.sqlalchemy_database_url.startswith('postgresql+asyncpg://'):
                # Add +asyncpg for SQLAlchemy async engine if not present
                self.sqlalchemy_database_url = self.sqlalchemy_database_url.replace(
                    'postgresql://', 'postgresql+asyncpg://'
                )

            logger.info(f"Asyncpg URL: {self.asyncpg_database_url}")
            logger.info(f"SQLAlchemy URL: {self.sqlalchemy_database_url}")

            # ----------------------- AsyncPG Pool (low-level access) -----------------------
            self.pg_pool = await asyncpg.create_pool(
                dsn=self.asyncpg_database_url, 
                min_size=2, 
                max_size=20,
                command_timeout=30
            )
            logger.info("Postgres connection pool created with asyncpg")
            
            # ----------------------- ORM (synchronous) -----------------------
            # Standard SQLAlchemy engine for ORM models used across the codebase
            sync_url = self.asyncpg_database_url  # Use clean URL for sync engine too
            self.sync_engine = create_engine(
                sync_url,
                pool_pre_ping=True,
                pool_recycle=3600,
                pool_size=10,
                max_overflow=20
            )
            self.SessionLocal = sessionmaker(
                autocommit=False, 
                autoflush=False, 
                bind=self.sync_engine
            )

            # ----------------------- Async Engine (SQLAlchemy) -----------------------
            # For future async queries with SQLAlchemy ORM
            self.engine = create_async_engine(
                self.sqlalchemy_database_url,
                pool_size=20,
                max_overflow=30,
                pool_pre_ping=True,
                pool_recycle=3600,
            )

            self.async_session = async_sessionmaker(
                self.engine,
                expire_on_commit=False,
                class_=AsyncSession
            )

            # ----------------------- Redis Client -----------------------
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            # Use async Redis client with connection pool
            self.redis_client = redis.asyncio.from_url(
                redis_url, 
                decode_responses=True,
                max_connections=20,
                retry_on_timeout=True,
                socket_keepalive=True,
                socket_keepalive_options={},
                health_check_interval=30
            )
            logger.info("Redis client connected")
            
            # Test connections
            await self._test_connections()
            logger.info("Database and Redis initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize database and redis: {e}")
            raise

    async def _test_connections(self):
        """Test database and Redis connections"""
        try:
            # Test asyncpg pool
            async with self.pg_pool.acquire() as conn:
                result = await conn.fetchval('SELECT 1')
                logger.info(f"AsyncPG test query result: {result}")
            
            # Test Redis
            await self.redis_client.ping()
            logger.info("Redis connection test successful")
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            raise
        
    # ---------------- Dependency for FastAPI ----------------
    def get_sync_session(self) -> Session:
        """Return a new synchronous SQLAlchemy session"""
        return self.SessionLocal()

    # Backward-compat generator used by FastAPI dependencies
    def get_db(self):
        """Yield database session for FastAPI dependency."""
        db = self.get_sync_session()
        try:
            yield db
        finally:
            db.close()

    async def create_tables(self):
        """Create necessary tables"""
        create_symbols_table = """
        CREATE TABLE IF NOT EXISTS symbols (
            id SERIAL PRIMARY KEY,
            symbol VARCHAR(20) NOT NULL,
            dataset VARCHAR(50) NOT NULL,
            instrument_id BIGINT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(symbol, dataset)
        );
        """
        
        create_ohlcv_table = """
        CREATE TABLE IF NOT EXISTS ohlcv_data (
            id SERIAL PRIMARY KEY,
            symbol VARCHAR(20) NOT NULL,
            dataset VARCHAR(50) NOT NULL,
            timeframe VARCHAR(20) NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            open DECIMAL(20,8),
            high DECIMAL(20,8),
            low DECIMAL(20,8),
            close DECIMAL(20,8),
            volume BIGINT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(symbol, dataset, timeframe, timestamp)
        );
        """
        
        create_eod_table = """
        CREATE TABLE IF NOT EXISTS eod_data (
            id SERIAL PRIMARY KEY,
            symbol_id INTEGER,
            symbol VARCHAR(20) NOT NULL,
            trade_date DATE NOT NULL,
            open_price DECIMAL(20,8),
            high_price DECIMAL(20,8),
            low_price DECIMAL(20,8),
            close_price DECIMAL(20,8),
            volume BIGINT,
            adjusted_close DECIMAL(20,8),
            raw_data JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(symbol, trade_date)
        );
        """
        
        create_indices = """
        CREATE INDEX IF NOT EXISTS idx_ohlcv_symbol_timeframe_timestamp 
        ON ohlcv_data(symbol, timeframe, timestamp);
        
        CREATE INDEX IF NOT EXISTS idx_ohlcv_timestamp 
        ON ohlcv_data(timestamp);
        
        CREATE INDEX IF NOT EXISTS idx_symbols_symbol 
        ON symbols(symbol);
        
        CREATE INDEX IF NOT EXISTS idx_eod_symbol_date 
        ON eod_data(symbol, trade_date);
        """
        
        try:
            async with self.pg_pool.acquire() as conn:
                await conn.execute(create_symbols_table)
                await conn.execute(create_ohlcv_table)
                await conn.execute(create_eod_table)
                await conn.execute(create_indices)
                logger.info("Tables and indices created successfully")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise

    async def insert_symbol(self, symbols_data: List[Dict]):
        """Insert or update symbols into the database."""
        if not symbols_data:
            return
            
        try:
            async with self.pg_pool.acquire() as conn:
                await conn.executemany(
                    """
                    INSERT INTO symbols (symbol, dataset, instrument_id, description)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (symbol, dataset) DO UPDATE SET
                        instrument_id = EXCLUDED.instrument_id,
                        description = EXCLUDED.description,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    [(s['symbol'], s['dataset'], s.get('instrument_id'), s.get('description')) 
                     for s in symbols_data]
                )
                logger.info(f"Inserted/updated {len(symbols_data)} symbols")
        except Exception as e:
            logger.error(f"Failed to insert symbols: {e}")
            raise
        
    async def insert_ohlcv_data(self, ohlcv_data: List[Dict]):
        """Insert OHLCV data into database"""
        if not ohlcv_data:
            return
            
        try:
            async with self.pg_pool.acquire() as conn:
                await conn.executemany(
                    """
                    INSERT INTO ohlcv_data (symbol, dataset, timeframe, timestamp, open, high, low, close, volume)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (symbol, dataset, timeframe, timestamp) DO UPDATE SET
                        open = EXCLUDED.open,
                        high = EXCLUDED.high,
                        low = EXCLUDED.low,
                        close = EXCLUDED.close,
                        volume = EXCLUDED.volume
                    """,
                    [(s['symbol'], s['dataset'], s['timeframe'], s['timestamp'], 
                      s['open'], s['high'], s['low'], s['close'], s['volume']) 
                     for s in ohlcv_data]
                )
                logger.info(f"Inserted/updated {len(ohlcv_data)} OHLCV records")
        except Exception as e:
            logger.error(f"Failed to insert OHLCV data: {e}")
            raise

    async def get_ohlcv_data(self, symbol: str, timeframe: str, start_date: datetime, 
                           end_date: datetime, dataset: str = None) -> pd.DataFrame:
        """Retrieve OHLCV data for a symbol within a date range"""
        # Try Redis cache first
        cache_key = f"ohlcv:{symbol}:{timeframe}:{start_date}:{end_date}:{dataset}"
        
        try:
            cached_data = await self.redis_client.get(cache_key)
            if cached_data:
                logger.info(f"Cache hit for {cache_key}")
                return pd.read_json(cached_data)
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")
        
        # Fetch from PostgreSQL
        query = """
            SELECT timestamp, open, high, low, close, volume
            FROM ohlcv_data
            WHERE symbol = $1 AND timeframe = $2 AND timestamp >= $3 AND timestamp <= $4
        """
        params = [symbol, timeframe, start_date, end_date]
        
        if dataset:
            query += " AND dataset = $5"
            params.append(dataset)
        
        query += " ORDER BY timestamp"
        
        try:
            async with self.pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
            
            df = pd.DataFrame(rows)
            if not df.empty:
                df.set_index('timestamp', inplace=True)
            
            # Cache the result
            try:
                ttl = getattr(self.config, 'DAILY_CACHE_TTL', 86400) if '1d' in timeframe else getattr(self.config, 'CACHE_TTL', 300)
                await self.redis_client.setex(cache_key, ttl, df.to_json())
            except Exception as e:
                logger.warning(f"Failed to cache data: {e}")
            
            return df
            
        except Exception as e:
            logger.error(f"Failed to get OHLCV data: {e}")
            raise
    
    async def get_symbols(self, dataset: str = None) -> List[str]:
        """Get all available symbols"""
        cache_key = f"symbols:{dataset or 'all'}"
        
        try:
            cached_symbols = await self.redis_client.get(cache_key)
            if cached_symbols:
                return json.loads(cached_symbols)
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")
        
        query = "SELECT DISTINCT symbol FROM symbols"
        params = []
        
        if dataset:
            query += " WHERE dataset = $1"
            params.append(dataset)
            
        try:
            async with self.pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                
            symbols = [row['symbol'] for row in rows]
            
            # Cache for 1 hour
            try:
                await self.redis_client.setex(cache_key, 3600, json.dumps(symbols))
            except Exception as e:
                logger.warning(f"Failed to cache symbols: {e}")
            
            return symbols
            
        except Exception as e:
            logger.error(f"Failed to get symbols: {e}")
            raise

    async def insert_eod_data(self, eod_data: List[Dict]):
        """Insert EOD data from list of dictionaries"""
        if not eod_data:
            return
            
        try:
            async with self.pg_pool.acquire() as conn:
                await conn.executemany(
                    """
                    INSERT INTO eod_data (
                        symbol, trade_date, open_price, high_price, 
                        low_price, close_price, volume, adjusted_close, raw_data
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (symbol, trade_date) DO UPDATE SET
                        open_price = EXCLUDED.open_price,
                        high_price = EXCLUDED.high_price,
                        low_price = EXCLUDED.low_price,
                        close_price = EXCLUDED.close_price,
                        volume = EXCLUDED.volume,
                        adjusted_close = EXCLUDED.adjusted_close,
                        raw_data = EXCLUDED.raw_data
                    """,
                    [(
                        row['symbol'],
                        row['trade_date'],
                        row.get('open_price'),
                        row.get('high_price'),
                        row.get('low_price'),
                        row.get('close_price'),
                        row.get('volume'),
                        row.get('adjusted_close'),
                        json.dumps(row) if isinstance(row, dict) else row.get('raw_data')
                    ) for row in eod_data]
                )
                logger.info(f"Inserted/updated {len(eod_data)} EOD records")
        except Exception as e:
            logger.error(f"Failed to insert EOD data: {e}")
            raise

    async def get_eod_data(self, symbol: str, start_date=None, end_date=None, limit=None) -> List[Dict]:
        """Retrieve EOD Data for a symbol within a date range"""
        query = "SELECT * FROM eod_data WHERE symbol = $1"
        params = [symbol]
        
        if start_date:
            query += " AND trade_date >= $2"
            params.append(start_date)
        
        if end_date:
            param_num = len(params) + 1
            query += f" AND trade_date <= ${param_num}"
            params.append(end_date)
        
        query += " ORDER BY trade_date DESC"
        
        if limit:
            param_num = len(params) + 1
            query += f" LIMIT ${param_num}"
            params.append(limit)

        try:
            async with self.pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                
            return [dict(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to get EOD data: {e}")
            raise

    async def invalidate_cache(self, pattern: str):
        """Invalidate cache entries matching pattern"""
        try:
            # Note: keys() can be expensive on large datasets, use with caution
            keys = []
            async for key in self.redis_client.scan_iter(pattern):
                keys.append(key)
            
            if keys:
                await self.redis_client.delete(*keys)
                logger.info(f"Invalidated {len(keys)} cache entries for pattern: {pattern}")
        except Exception as e:
            logger.error(f"Failed to invalidate cache: {e}")

    async def set_cache(self, key: str, value: any, ttl: int = 300):
        """Set cache value with TTL"""
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            await self.redis_client.setex(key, ttl, value)
        except Exception as e:
            logger.warning(f"Failed to set cache {key}: {e}")

    async def get_cache(self, key: str):
        """Get cache value"""
        try:
            return await self.redis_client.get(key)
        except Exception as e:
            logger.warning(f"Failed to get cache {key}: {e}")
            return None
    
    async def close(self):
        """Close database connections"""
        try:
            if self.pg_pool:
                await self.pg_pool.close()
                logger.info("AsyncPG pool closed")
                
            if self.redis_client:
                await self.redis_client.aclose()
                logger.info("Redis client closed")
                
            if hasattr(self, 'engine'):
                await self.engine.dispose()
                logger.info("SQLAlchemy async engine disposed")
                
        except Exception as e:
            logger.error(f"Error closing connections: {e}")