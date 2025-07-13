import redis
import json
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple, Union
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, text, func
from ..models.market_data import Symbol, OHLCVData, TradeData, NewsData
from ..schemas.market_data import SymbolCreate, SymbolResponse, OHLCVCreateWithSymbol
import logging
import time
import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
import numpy as np
from contextlib import asynccontextmanager
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

@dataclass
class QueryMetrics:
    """Metrics for query performance monitoring"""
    query_type: str
    execution_time: float
    cache_hit: bool
    rows_returned: int
    timestamp: float

@dataclass
class CacheStats:
    """Cache performance statistics"""
    hits: int = 0
    misses: int = 0
    invalidations: int = 0
    memory_usage: int = 0
    
    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0

class QueryOptimizer:
    """Query optimization and planning"""
    
    @staticmethod
    def optimize_ohlcv_query(symbol: str, timeframe: str, start_date: datetime, 
                           end_date: datetime, limit: Optional[int] = None) -> str:
        """Generate optimized OHLCV query based on parameters"""
        
        # Calculate expected row count for optimization hints
        time_diff = end_date - start_date
        
        if timeframe == 'ohlcv-1m':
            estimated_rows = int(time_diff.total_seconds() / 60)
        elif timeframe == 'ohlcv-1h':
            estimated_rows = int(time_diff.total_seconds() / 3600)
        elif timeframe == 'ohlcv-1d':
            estimated_rows = time_diff.days
        else:
            estimated_rows = 1000  # Default estimate
        
        # Choose query strategy based on expected rows
        if estimated_rows > 10000:
            # Use index-only scan for large queries
            return """
            SELECT timestamp, open, high, low, close, volume, vwap, trades_count
            FROM ohlcv_data 
            WHERE symbol = %s AND timeframe = %s 
                AND timestamp >= %s AND timestamp <= %s
                AND is_market_hours = true
            ORDER BY timestamp
            """
        else:
            # Standard query for smaller result sets
            return """
            SELECT timestamp, open, high, low, close, volume, vwap, trades_count
            FROM ohlcv_data 
            WHERE symbol = %s AND timeframe = %s 
                AND timestamp >= %s AND timestamp <= %s
            ORDER BY timestamp
            """

class DataCompressionService:
    """Data compression for efficient storage and transfer"""
    
    @staticmethod
    def compress_ohlcv_dataframe(df: pd.DataFrame) -> bytes:
        """Compress OHLCV DataFrame to bytes using Parquet/Brotli"""
        import io, pickle
        try:
            df_copy = df.copy()
            float_cols = ['open', 'high', 'low', 'close', 'vwap']
            for col in float_cols:
                if col in df_copy.columns:
                    df_copy[col] = pd.to_numeric(df_copy[col], downcast='float')
            if 'volume' in df_copy.columns:
                df_copy['volume'] = pd.to_numeric(df_copy['volume'], downcast='integer')
            buf = io.BytesIO()
            df_copy.to_parquet(buf, compression='brotli', index=True)
            return buf.getvalue()
        except Exception as e:
            logger.warning(f"DataFrame compression failed: {e}")
            # Fallback to pickle bytes
            return pickle.dumps(df)

    
    @staticmethod
    def decompress_ohlcv_dataframe(compressed_data: bytes) -> pd.DataFrame:
        """Decompress OHLCV DataFrame bytes produced by compress_ohlcv_dataframe"""
        import io, pickle
        try:
            return pd.read_parquet(io.BytesIO(compressed_data))
        except Exception:
            # Fallback to pickle
            try:
                return pickle.loads(compressed_data)
            except Exception as e:
                logger.warning(f"Failed to decompress OHLCV DataFrame: {e}")
                return pd.DataFrame()


class ProductionDataStorageService:
    """Production-grade data storage service with advanced caching and optimization"""
    
    def __init__(self, db: Session, redis_client, enhanced_redis_service=None, config=None):
        self.db = db
        self.redis_client = redis_client
        self.enhanced_redis_service = enhanced_redis_service
        self.config = config
        
        # Performance monitoring
        self.query_metrics = deque(maxlen=1000)
        self.cache_stats = CacheStats()
        
        # Query optimizer
        self.query_optimizer = QueryOptimizer()
        
        # Thread pool for CPU-intensive operations
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        # Compression service
        self.compression_service = DataCompressionService()
        
        # Cache TTL configuration
        self.cache_ttl = {
            'ohlcv-1s': 60,
            'ohlcv-1m': 300,
            'ohlcv-5m': 900,
            'ohlcv-15m': 1800,
            'ohlcv-30m': 3600,
            'ohlcv-1h': 7200,
            'ohlcv-4h': 14400,
            'ohlcv-1d': 86400,
            'symbols': 3600,
            'trades': 300,
            'realtime': 30
        }
        
        # Update cache TTL from config if provided
        if config:
            self.cache_ttl.update({
                'ohlcv-1s': config.CACHE_TTL_REALTIME,
                'ohlcv-1m': config.CACHE_TTL_MINUTE,
                'ohlcv-1h': config.CACHE_TTL_HOUR,
                'ohlcv-1d': config.CACHE_TTL_DAILY,
                'symbols': config.CACHE_TTL_SYMBOLS
            })
        
        # Precomputed aggregations cache
        self.aggregation_cache = {}
        self.aggregation_lock = threading.RLock()

    # ==================== Enhanced OHLCV Data Access ====================

    async def get_ohlcv_data_optimized(self, symbol: str, timeframe: str, 
                                     start_date: datetime, end_date: datetime, 
                                     dataset: Optional[str] = None,
                                     limit: Optional[int] = None,
                                     use_compression: bool = True) -> pd.DataFrame:
        """Optimized OHLCV data retrieval with multi-tier caching and compression"""
        
        start_time = time.time()
        cache_hit = False
        
        try:
            # Ensure dates are timezone-aware
            if start_date.tzinfo is None:
                start_date = start_date.replace(tzinfo=timezone.utc)
            if end_date.tzinfo is None:
                end_date = end_date.replace(tzinfo=timezone.utc)

            # Generate optimized cache key
            cache_key = self._generate_cache_key(
                'ohlcv', symbol, timeframe, start_date, end_date, dataset, limit
            )
            
            # Try enhanced Redis service first (L1 + L2 cache)
            if self.enhanced_redis_service:
                cached_df = await self.enhanced_redis_service.get_ohlcv_cache(
                    symbol, timeframe, dataset
                )
                
                if cached_df is not None and not cached_df.empty:
                    # Filter cached data by date range
                    mask = (cached_df.index >= start_date) & (cached_df.index <= end_date)
                    filtered_df = cached_df.loc[mask]
                    
                    if not filtered_df.empty:
                        if limit:
                            filtered_df = filtered_df.tail(limit)
                        
                        cache_hit = True
                        self.cache_stats.hits += 1
                        
                        self._record_query_metrics(
                            'ohlcv_optimized', time.time() - start_time, 
                            cache_hit, len(filtered_df)
                        )
                        
                        return filtered_df

            # Try legacy Redis cache
            try:
                cached_data = await self._get_from_redis_async(cache_key)
                if cached_data:
                    if use_compression:
                        df = self.compression_service.decompress_ohlcv_dataframe(cached_data)
                    else:
                        df = pd.read_json(cached_data, orient='index')
                        df.index = pd.to_datetime(df.index)
                    
                    if limit:
                        df = df.tail(limit)
                    
                    cache_hit = True
                    self.cache_stats.hits += 1
                    logger.debug(f"Legacy cache hit for {cache_key}")
                    
                    self._record_query_metrics(
                        'ohlcv_optimized', time.time() - start_time, 
                        cache_hit, len(df)
                    )
                    
                    return df
                    
            except Exception as e:
                logger.warning(f"Redis cache error: {e}")

            # Cache miss - query database
            self.cache_stats.misses += 1
            df = await self._query_ohlcv_from_database(
                symbol, timeframe, start_date, end_date, dataset, limit
            )
            
            # Cache the result if not empty
            if not df.empty:
                await self._cache_ohlcv_result(
                    cache_key, df, timeframe, use_compression
                )
                
                # Also update enhanced Redis service cache
                if self.enhanced_redis_service:
                    await self.enhanced_redis_service.set_ohlcv_cache(
                        symbol, timeframe, df, dataset
                    )
            
            self._record_query_metrics(
                'ohlcv_optimized', time.time() - start_time, 
                cache_hit, len(df)
            )
            
            return df
            
        except Exception as e:
            logger.error(f"Error in optimized OHLCV retrieval: {e}")
            self._record_query_metrics(
                'ohlcv_optimized', time.time() - start_time, 
                cache_hit, 0
            )
            return pd.DataFrame()

    async def _query_ohlcv_from_database(self, symbol: str, timeframe: str,
                                       start_date: datetime, end_date: datetime,
                                       dataset: Optional[str] = None,
                                       limit: Optional[int] = None) -> pd.DataFrame:
        """Optimized database query for OHLCV data"""
        
        try:
            # Build optimized query
            query_parts = [
                "SELECT timestamp, open, high, low, close, volume, vwap, trades_count",
                "FROM ohlcv_data",
                "WHERE symbol = :symbol AND timeframe = :timeframe",
                "AND timestamp >= :start_date AND timestamp <= :end_date"
            ]
            
            params = {
                'symbol': symbol,
                'timeframe': timeframe,
                'start_date': start_date,
                'end_date': end_date
            }
            
            if dataset:
                query_parts.append("AND dataset = :dataset")
                params['dataset'] = dataset
            
            # Add market hours filter for better performance on large datasets
            if timeframe in ['ohlcv-1m', 'ohlcv-5m']:
                query_parts.append("AND is_market_hours = true")
            
            query_parts.append("ORDER BY timestamp")
            
            if limit:
                query_parts.append("LIMIT :limit")
                params['limit'] = limit
            
            query = " ".join(query_parts)
            
            # Execute query with performance monitoring
            start_time = time.time()
            
            # Use raw SQL for better performance
            sql_text = text(query)
            result = self.db.execute(sql_text, params)
            rows = result.fetchall()
            
            query_time = time.time() - start_time
            
            if query_time > 1.0:
                logger.warning(f"Slow OHLCV query: {query_time:.2f}s for {symbol}:{timeframe}")
            
            # Convert to DataFrame
            if rows:
                df = pd.DataFrame(rows, columns=[
                    'timestamp', 'open', 'high', 'low', 'close', 
                    'volume', 'vwap', 'trades_count'
                ])
                df.set_index('timestamp', inplace=True)
                
                # Ensure proper data types
                numeric_columns = ['open', 'high', 'low', 'close', 'vwap']
                for col in numeric_columns:
                    if col in df.columns:
                        df[col] = pd.to_numeric(df[col], errors='coerce')
                
                if 'volume' in df.columns:
                    df['volume'] = pd.to_numeric(df['volume'], errors='coerce', downcast='integer')
                
                return df
            
            return pd.DataFrame()
            
        except Exception as e:
            logger.error(f"Database query error for {symbol}:{timeframe}: {e}")
            return pd.DataFrame()

    # ==================== Advanced Caching Operations ====================

    async def _cache_ohlcv_result(self, cache_key: str, df: pd.DataFrame, 
                                timeframe: str, use_compression: bool = True):
        """Cache OHLCV result with optimal strategy"""
        try:
            ttl = self.cache_ttl.get(timeframe, 300)
            
            if use_compression and len(df) > 100:
                # Use compression for larger datasets
                compressed_data = await asyncio.get_event_loop().run_in_executor(
                    self.thread_pool,
                    self.compression_service.compress_ohlcv_dataframe,
                    df
                )
                await self._set_to_redis_async(cache_key, compressed_data, ttl)
            else:
                # Use JSON for smaller datasets
                json_data = df.to_json(orient='index', date_format='iso')
                await self._set_to_redis_async(cache_key, json_data, ttl)
                
        except Exception as e:
            logger.warning(f"Failed to cache OHLCV result: {e}")

    async def _get_from_redis_async(self, key: str) -> Optional[Any]:
        """Async Redis get operation"""
        try:
            import inspect
            if asyncio.iscoroutinefunction(self.redis_client.get):
                result = await self.redis_client.get(key)
            else:
                result = self.redis_client.get(key)
            return result
            
        except Exception as e:
            logger.warning(f"Redis get error for {key}: {e}")
            return None

    async def _set_to_redis_async(self, key: str, value: Any, ttl: int):
        """Async Redis set operation"""
        try:
            import inspect
            if asyncio.iscoroutinefunction(self.redis_client.setex):
                await self.redis_client.setex(key, ttl, value)
            else:
                self.redis_client.setex(key, ttl, value)
        except Exception as e:
            logger.warning(f"Redis set error for {key}: {e}")

    def _generate_cache_key(self, data_type: str, symbol: str, timeframe: str,
                          start_date: datetime, end_date: datetime,
                          dataset: Optional[str] = None, 
                          limit: Optional[int] = None) -> str:
        """Generate optimized cache key"""
        key_parts = [
            data_type,
            symbol,
            timeframe,
            start_date.strftime('%Y%m%d'),
            end_date.strftime('%Y%m%d')
        ]
        
        if dataset:
            key_parts.append(dataset)
        
        if limit:
            key_parts.append(f"limit{limit}")
        
        return ":".join(key_parts)

    # ==================== Symbol Management ====================

    async def get_symbols_optimized(self, dataset: Optional[str] = None,
                                  sector: Optional[str] = None,
                                  active_only: bool = True) -> List[Dict[str, Any]]:
        """Optimized symbol retrieval with filtering"""
        
        start_time = time.time()
        cache_hit = False
        
        try:
            # Generate cache key
            cache_key = f"symbols:{dataset or 'all'}:{sector or 'all'}:{active_only}"
            
            # Try enhanced Redis service first
            if self.enhanced_redis_service:
                cached_symbols = await self.enhanced_redis_service.get_with_l1_fallback(
                    cache_key, 'symbols'
                )
                
                if cached_symbols:
                    cache_hit = True
                    self.cache_stats.hits += 1
                    
                    self._record_query_metrics(
                        'symbols_optimized', time.time() - start_time,
                        cache_hit, len(cached_symbols)
                    )
                    
                    return cached_symbols

            # Try legacy Redis cache
            try:
                cached_data = await self._get_from_redis_async(cache_key)
                if cached_data:
                    symbols = json.loads(cached_data)
                    cache_hit = True
                    self.cache_stats.hits += 1
                    
                    self._record_query_metrics(
                        'symbols_optimized', time.time() - start_time,
                        cache_hit, len(symbols)
                    )
                    
                    return symbols
                    
            except Exception as e:
                logger.warning(f"Redis cache error for symbols: {e}")

            # Cache miss - query database
            self.cache_stats.misses += 1
            symbols = await self._query_symbols_from_database(dataset, sector, active_only)
            
            # Cache the result
            if symbols:
                await self._set_to_redis_async(
                    cache_key, 
                    json.dumps(symbols, default=str),
                    self.cache_ttl['symbols']
                )
                
                # Also update enhanced Redis service
                if self.enhanced_redis_service:
                    await self.enhanced_redis_service.set_multi_tier(
                        cache_key, symbols, 'symbols', self.cache_ttl['symbols']
                    )
            
            self._record_query_metrics(
                'symbols_optimized', time.time() - start_time,
                cache_hit, len(symbols)
            )
            
            return symbols
            
        except Exception as e:
            logger.error(f"Error in optimized symbol retrieval: {e}")
            return []

    async def _query_symbols_from_database(self, dataset: Optional[str] = None,
                                         sector: Optional[str] = None,
                                         active_only: bool = True) -> List[Dict[str, Any]]:
        """Query symbols from database with optimizations"""
        try:
            query = self.db.query(Symbol)
            
            if dataset:
                query = query.filter(Symbol.dataset == dataset)
            
            if sector:
                query = query.filter(Symbol.sector == sector)
            
            if active_only:
                query = query.filter(Symbol.is_active == True)
            
            # Order by symbol for consistent results
            query = query.order_by(Symbol.symbol)
            
            results = query.all()
            
            # Convert to dictionaries
            symbols = []
            for symbol in results:
                symbols.append({
                    'id': symbol.id,
                    'symbol': symbol.symbol,
                    'dataset': symbol.dataset,
                    'description': symbol.description,
                    'sector': symbol.sector,
                    'industry': symbol.industry,
                    'market_cap': symbol.market_cap,
                    'currency': symbol.currency,
                    'exchange': symbol.exchange,
                    'instrument_id': symbol.instrument_id,
                    'is_active': symbol.is_active,
                    'created_at': symbol.created_at,
                    'updated_at': symbol.updated_at
                })
            
            return symbols
            
        except Exception as e:
            logger.error(f"Database query error for symbols: {e}")
            return []

    # ==================== Trade Data Operations ====================

    async def get_trade_data_optimized(self, symbol: str, start_date: datetime,
                                     end_date: datetime, dataset: Optional[str] = None,
                                     limit: Optional[int] = None,
                                     trade_side: Optional[str] = None) -> pd.DataFrame:
        """Optimized trade data retrieval"""
        
        start_time = time.time()
        cache_hit = False
        
        try:
            # Ensure dates are timezone-aware
            if start_date.tzinfo is None:
                start_date = start_date.replace(tzinfo=timezone.utc)
            if end_date.tzinfo is None:
                end_date = end_date.replace(tzinfo=timezone.utc)

            # Generate cache key
            cache_key = self._generate_cache_key(
                'trades', symbol, 'all', start_date, end_date, dataset, limit
            )
            
            # Try cache first
            try:
                cached_data = await self._get_from_redis_async(cache_key)
                if cached_data:
                    df = pd.read_json(cached_data, orient='index')
                    df.index = pd.to_datetime(df.index)
                    
                    # Filter by trade side if specified
                    if trade_side and 'side' in df.columns:
                        df = df[df['side'] == trade_side]
                    
                    cache_hit = True
                    self.cache_stats.hits += 1
                    
                    self._record_query_metrics(
                        'trades_optimized', time.time() - start_time,
                        cache_hit, len(df)
                    )
                    
                    return df
                    
            except Exception as e:
                logger.warning(f"Redis cache error for trades: {e}")

            # Cache miss - query database
            self.cache_stats.misses += 1
            df = await self._query_trades_from_database(
                symbol, start_date, end_date, dataset, limit, trade_side
            )
            
            # Cache the result
            if not df.empty:
                try:
                    json_data = df.to_json(orient='index', date_format='iso')
                    await self._set_to_redis_async(
                        cache_key, json_data, self.cache_ttl['trades']
                    )
                except Exception as e:
                    logger.warning(f"Failed to cache trade data: {e}")
            
            self._record_query_metrics(
                'trades_optimized', time.time() - start_time,
                cache_hit, len(df)
            )
            
            return df
            
        except Exception as e:
            logger.error(f"Error in optimized trade retrieval: {e}")
            return pd.DataFrame()

    async def _query_trades_from_database(self, symbol: str, start_date: datetime,
                                        end_date: datetime, dataset: Optional[str] = None,
                                        limit: Optional[int] = None,
                                        trade_side: Optional[str] = None) -> pd.DataFrame:
        """Query trade data from database"""
        try:
            query = self.db.query(TradeData).filter(
                and_(
                    TradeData.symbol == symbol,
                    TradeData.timestamp >= start_date,
                    TradeData.timestamp <= end_date
                )
            )
            
            if dataset:
                query = query.filter(TradeData.dataset == dataset)
            
            if trade_side:
                query = query.filter(TradeData.side == trade_side)
            
            query = query.order_by(TradeData.timestamp.desc())
            
            if limit:
                query = query.limit(limit)
            
            results = query.all()
            
            if results:
                data = [{
                    'timestamp': r.timestamp,
                    'price': float(r.price) if r.price else None,
                    'size': r.size,
                    'side': r.side,
                    'trade_id': r.trade_id
                } for r in results]
                
                df = pd.DataFrame(data)
                df.set_index('timestamp', inplace=True)
                return df
            
            return pd.DataFrame()
            
        except Exception as e:
            logger.error(f"Database query error for trades: {e}")
            return pd.DataFrame()

    # ==================== Analytics and Aggregations ====================

    async def get_market_summary(self, symbols: List[str], timeframe: str = 'ohlcv-1d') -> Dict[str, Any]:
        """Get market summary with advanced analytics"""
        
        try:
            summary = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'timeframe': timeframe,
                'symbol_count': len(symbols),
                'market_stats': {},
                'top_movers': {},
                'volume_leaders': {}
            }
            
            # Get latest data for all symbols
            latest_data = {}
            for symbol in symbols[:20]:  # Limit to prevent overload
                try:
                    end_date = datetime.now(timezone.utc)
                    start_date = end_date - timedelta(days=2)
                    
                    df = await self.get_ohlcv_data_optimized(
                        symbol, timeframe, start_date, end_date, limit=2
                    )
                    
                    if not df.empty:
                        latest_data[symbol] = df.iloc[-1].to_dict()
                        latest_data[symbol]['timestamp'] = df.index[-1].isoformat()
                        
                        # Calculate change if we have previous data
                        if len(df) > 1:
                            prev_close = df.iloc[-2]['close']
                            curr_close = df.iloc[-1]['close']
                            change = curr_close - prev_close
                            change_pct = (change / prev_close) * 100 if prev_close else 0
                            
                            latest_data[symbol]['change'] = float(change)
                            latest_data[symbol]['change_pct'] = float(change_pct)
                        
                except Exception as e:
                    logger.warning(f"Error getting summary for {symbol}: {e}")
                    continue
            
            if latest_data:
                # Calculate market statistics
                prices = [data['close'] for data in latest_data.values() if 'close' in data]
                volumes = [data['volume'] for data in latest_data.values() if 'volume' in data and data['volume']]
                changes = [data.get('change_pct', 0) for data in latest_data.values()]
                
                summary['market_stats'] = {
                    'avg_price': float(np.mean(prices)) if prices else 0,
                    'total_volume': int(np.sum(volumes)) if volumes else 0,
                    'avg_change_pct': float(np.mean(changes)) if changes else 0,
                    'advancing_issues': len([c for c in changes if c > 0]),
                    'declining_issues': len([c for c in changes if c < 0])
                }
                
                # Top movers by percentage change
                sorted_by_change = sorted(
                    latest_data.items(),
                    key=lambda x: x[1].get('change_pct', 0),
                    reverse=True
                )
                
                summary['top_movers'] = {
                    'gainers': [
                        {
                            'symbol': symbol,
                            'change_pct': data.get('change_pct', 0),
                            'price': data.get('close', 0)
                        }
                        for symbol, data in sorted_by_change[:5]
                    ],
                    'losers': [
                        {
                            'symbol': symbol,
                            'change_pct': data.get('change_pct', 0),
                            'price': data.get('close', 0)
                        }
                        for symbol, data in sorted_by_change[-5:]
                    ]
                }
                
                # Volume leaders
                sorted_by_volume = sorted(
                    latest_data.items(),
                    key=lambda x: x[1].get('volume', 0),
                    reverse=True
                )
                
                summary['volume_leaders'] = [
                    {
                        'symbol': symbol,
                        'volume': data.get('volume', 0),
                        'price': data.get('close', 0)
                    }
                    for symbol, data in sorted_by_volume[:10]
                ]
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating market summary: {e}")
            return {'error': str(e)}

    # ==================== Performance Monitoring ====================

    def _record_query_metrics(self, query_type: str, execution_time: float,
                             cache_hit: bool, rows_returned: int):
        """Record query performance metrics"""
        metric = QueryMetrics(
            query_type=query_type,
            execution_time=execution_time,
            cache_hit=cache_hit,
            rows_returned=rows_returned,
            timestamp=time.time()
        )
        
        self.query_metrics.append(metric)

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        if not self.query_metrics:
            return {'error': 'No metrics available'}
        
        # Calculate aggregate statistics
        total_queries = len(self.query_metrics)
        cache_hits = sum(1 for m in self.query_metrics if m.cache_hit)
        avg_execution_time = sum(m.execution_time for m in self.query_metrics) / total_queries
        
        # Group by query type
        by_type = defaultdict(list)
        for metric in self.query_metrics:
            by_type[metric.query_type].append(metric)
        
        type_stats = {}
        for query_type, metrics in by_type.items():
            type_stats[query_type] = {
                'count': len(metrics),
                'avg_execution_time': sum(m.execution_time for m in metrics) / len(metrics),
                'cache_hit_rate': sum(1 for m in metrics if m.cache_hit) / len(metrics) * 100,
                'avg_rows_returned': sum(m.rows_returned for m in metrics) / len(metrics)
            }
        
        return {
            'overall': {
                'total_queries': total_queries,
                'cache_hit_rate': (cache_hits / total_queries * 100) if total_queries > 0 else 0,
                'avg_execution_time': avg_execution_time,
                'cache_stats': {
                    'hits': self.cache_stats.hits,
                    'misses': self.cache_stats.misses,
                    'hit_rate': self.cache_stats.hit_rate,
                    'invalidations': self.cache_stats.invalidations
                }
            },
            'by_query_type': type_stats,
            'recent_slow_queries': [
                {
                    'type': m.query_type,
                    'execution_time': m.execution_time,
                    'timestamp': m.timestamp
                }
                for m in self.query_metrics
                if m.execution_time > 1.0
            ][-10:]  # Last 10 slow queries
        }

    # ==================== Cache Management ====================

    async def invalidate_cache_pattern(self, pattern: str):
        """Invalidate cache entries matching pattern"""
        try:
            if self.enhanced_redis_service:
                await self.enhanced_redis_service.invalidate_pattern(pattern)
            else:
                # Fallback to manual pattern matching
                # This is a simplified implementation
                pass
            
            self.cache_stats.invalidations += 1
            logger.info(f"Invalidated cache pattern: {pattern}")
            
        except Exception as e:
            logger.error(f"Failed to invalidate cache pattern {pattern}: {e}")

    async def warm_cache_for_symbols(self, symbols: List[str], timeframes: List[str] = None):
        """Warm cache for frequently accessed symbols"""
        timeframes = timeframes or ['ohlcv-1m', 'ohlcv-1h', 'ohlcv-1d']
        
        logger.info(f"Warming cache for {len(symbols)} symbols")
        
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=7)
        
        for symbol in symbols:
            for timeframe in timeframes:
                try:
                    await self.get_ohlcv_data_optimized(
                        symbol, timeframe, start_date, end_date, limit=100
                    )
                    await asyncio.sleep(0.1)  # Small delay to prevent overload
                    
                except Exception as e:
                    logger.warning(f"Cache warming failed for {symbol}:{timeframe}: {e}")
                    continue
        
        logger.info("Cache warming completed")

    def close(self):
        """Cleanup resources"""
        try:
            if hasattr(self, 'thread_pool'):
                self.thread_pool.shutdown(wait=True)
        except Exception as e:
            logger.error(f"Error closing data storage service: {e}")

# ==================== Backward Compatibility ====================

class DataStorageService:
    """Legacy class for backward compatibility"""
    
    def __init__(self, db: Session, redis_client):
        self.enhanced_service = ProductionDataStorageService(db, redis_client)
    
    def get_ohlcv_data(self, symbol: str, timeframe: str, start_date: datetime, 
                       end_date: datetime, dataset: str = None) -> pd.DataFrame:
        """Legacy sync method"""
        try:
            # Run async method in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                self.enhanced_service.get_ohlcv_data_optimized(
                    symbol, timeframe, start_date, end_date, dataset
                )
            )
        except Exception as e:
            logger.error(f"Legacy OHLCV query error: {e}")
            return pd.DataFrame()
        finally:
            loop.close()
    
    def get_symbols(self, dataset: str = None) -> List[str]:
        """Legacy sync method for symbols"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            symbols_data = loop.run_until_complete(
                self.enhanced_service.get_symbols_optimized(dataset)
            )
            return [s['symbol'] for s in symbols_data]
        except Exception as e:
            logger.error(f"Legacy symbols query error: {e}")
            return []
        finally:
            loop.close()
    
    def get_trade_data(self, symbol: str, start_date: datetime, end_date: datetime,
                       dataset: str = None, limit: int = None) -> pd.DataFrame:
        """Legacy sync method for trades"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                self.enhanced_service.get_trade_data_optimized(
                    symbol, start_date, end_date, dataset, limit
                )
            )
        except Exception as e:
            logger.error(f"Legacy trade query error: {e}")
            return pd.DataFrame()
        finally:
            loop.close()
    
    def invalidate_cache(self, pattern: str):
        """Legacy sync method for cache invalidation"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(
                self.enhanced_service.invalidate_cache_pattern(pattern)
            )
        except Exception as e:
            logger.error(f"Legacy cache invalidation error: {e}")
        finally:
            loop.close()