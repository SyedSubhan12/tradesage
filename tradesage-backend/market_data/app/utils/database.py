import psycopg2
from psycopg2.extras import RealDictCursor
import pandas as pd
import json
from datetime import datetime
from .config import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
class DatabaseManager:
    def __init__(self, config: Config ):
        self.config = config
        self.pg_pool = None
        self.redis_client = None

    async def initialize(self):
        """Initialize database connection pool and redis client
        """
        try:
            #postgres connection pool
            self.pg_pool = await asyncpg.create_pool(
                host=self.config.POSTGRES_HOST,
                port=self.config.POSTGRES_PORT,
                database=self.config.POSTGRES_DB,
                user=self.config.POSTGRES_USER,
                password=self.config.POSTGRES_PASSWORD,
            )
            logger.info("Postgres connection pool created")
            
            #redis client
            self.redis_client = await redis.Redis(
                host=self.config.REDIS_HOST,
                port=self.config.REDIS_PORT,
                password=self.config.REDIS_PASSWORD,
                decode_responses=True
            )
            logger.info("Redis client created")
            
            # Test connections
            await self.create_tables()
            self.redis_client.ping()

            logger.info("Database and Redis initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize database and redis", error=str(e))
            raise
        
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
        
        create_indices = """
        CREATE INDEX IF NOT EXISTS idx_ohlcv_symbol_timeframe_timestamp 
        ON ohlcv_data(symbol, timeframe, timestamp);
        
        CREATE INDEX IF NOT EXISTS idx_ohlcv_timestamp 
        ON ohlcv_data(timestamp);
        
        CREATE INDEX IF NOT EXISTS idx_symbols_symbol 
        ON symbols(symbol);
        """
        
        async with self.pg_pool.acquire() as conn:
            await conn.execute(create_symbols_table)
            await conn.execute(create_ohlcv_table)
            await conn.execute(create_indices)

    async def insert_symbol(self, symbols_data: List[Dict]):
        """Insert or update a new symbol into the database."""
        if not symbols_data:
            return
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
        
    async def insert_ohlcv_data(self, ohlcv_data:List[Dict]):
        """Insert OHLCV data into database"""
        if not ohlcv_data:
            return
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
                    volume = EXCLUDED.volume,
                    updated_at = CURRENT_TIMESTAMP
                """,
                [(s['symbol'], s['dataset'], s['timeframe'], s['timestamp'], s['open'], s['high'], s['low'], s['close'], s['volume']) 
                 for s in ohlcv_data]
            )
        async def get_ohlcv_data(self, symbol: str, timeframe: str, start_date: datetime, end_date: datetime, dataset: str =None) -> pd.DataFrame:
            """Retrieve OHLCV data for a symbol within a date range"""
            # Try Redis cache first
            cache_key = f"ohlcv:{symbol}:{timeframe}:{start_date}:{end_date}:{dataset}"
            cached_data = self.redis_client.get(cache_key)
        
            if cached_data:
                logger.info(f"Cache hit for {cache_key}")
                return pd.read_json(cached_data)
        
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
        
            async with self.pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
            
            df = pd.DataFrame(rows)
            if not df.empty:
                df.set_index('timestamp', inplace=True)
            
            # Cache the result
            ttl = self.config.DAILY_CACHE_TTL if '1d' in timeframe else self.config.CACHE_TTL
            self.redis_client.setex(cache_key, ttl, df.to_json())
            
            return df
    
    async def get_symbols(self, dataset: str = None) -> List[str]:
        """Get all available symbols"""
        cache_key = f"symbols:{dataset or 'all'}"
        cached_symbols = self.redis_client.get(cache_key)
        
        if cached_symbols:
            return json.loads(cached_symbols)
        
        query = "SELECT DISTINCT symbol FROM symbols"
        params = []
        
        if dataset:
            query += " WHERE dataset = $1"
            params.append(dataset)
            
        async with self.pg_pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            
        symbols = [row['symbol'] for row in rows]
        
        # Cache for 1 hour
        self.redis_client.setex(cache_key, 3600, json.dumps(symbols))
        
        return symbols
    
    async def close(self):
        """Close database connections"""
        if self.pg_pool:
            await self.pg_pool.close()
        if self.redis_client:
            self.redis_client.close()


    async def insert_eod_data(self, df):
        """Insert EOD data from DataFrame"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                for _, row in df.iterrows():
                    # First ensure symbol exists
                    symbol_id = self.insert_symbol(row['symbol'])
                    
                    # Insert EOD data
                    cur.execute("""
                        INSERT INTO eod_data (
                            symbol_id, symbol, trade_date, open_price, 
                            high_price, low_price, close_price, volume, 
                            adjusted_close, raw_data
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (symbol, trade_date) DO UPDATE SET
                            open_price = EXCLUDED.open_price,
                            high_price = EXCLUDED.high_price,
                            low_price = EXCLUDED.low_price,
                            close_price = EXCLUDED.close_price,
                            volume = EXCLUDED.volume,
                            adjusted_close = EXCLUDED.adjusted_close,
                            raw_data = EXCLUDED.raw_data;
                    """, (
                        symbol_id,
                        row['symbol'],
                        row['trade_date'],
                        row.get('open_price'),
                        row.get('high_price'),
                        row.get('low_price'),
                        row.get('close_price'),
                        row.get('volume'),
                        row.get('adjusted_close'),
                        json.dumps(row.to_dict())
                    ))
    def get_eod_data(self, symbol, start_date=None, end_date=None, limit=None):
        """Retrieve EOD Data for a symbol within a date range"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query= """
                    SELECT * FROM eod_data 
                    WHERE symbol = %s
                    """
                params =[symbol]
                
                if start_date:
                    query += "AND trade_date >= %s"
                    params.append(start_date)
                
                if end_date:
                    query += "AND trade_date <= %s"
                    params.append(end_date)
                
                query += "ORDER BY trade_date DESC"
                if limit:
                    query += "LIMIT %s"
                    params.append(limit)

                cur.execute(query, params)
                return cur.fetchall()
        
        