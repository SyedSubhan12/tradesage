import redis.asyncio as redis
import json
import pickle
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Union
import logging
from decimal import Decimal
import time
import asyncio
from collections import OrderedDict, defaultdict
import threading
from dataclasses import dataclass
import hashlib
import os
from redis.cluster import ClusterNode

logger = logging.getLogger(__name__)

@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    data: Any
    timestamp: float
    ttl: int
    access_count: int = 0
    last_access: float = 0

class L1InMemoryCache:
    """Ultra-fast in-memory L1 cache with LRU eviction"""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'sets': 0
        }

    def _is_expired(self, entry: CacheEntry) -> bool:
        """Check if cache entry is expired"""
        return time.time() - entry.timestamp > entry.ttl

    def _evict_lru(self):
        """Evict least recently used item"""
        if self.cache:
            evicted_key, _ = self.cache.popitem(last=False)
            self.stats['evictions'] += 1
            logger.debug(f"L1 cache evicted: {evicted_key}")

    def get(self, key: str) -> Optional[Any]:
        """Get item from L1 cache (thread-safe)"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                
                if self._is_expired(entry):
                    del self.cache[key]
                    self.stats['misses'] += 1
                    return None
                
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                entry.access_count += 1
                entry.last_access = time.time()
                self.stats['hits'] += 1
                
                return entry.data
            
            self.stats['misses'] += 1
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set item in L1 cache (thread-safe)"""
        with self.lock:
            ttl = ttl or self.default_ttl
            
            # Remove existing entry if present
            if key in self.cache:
                del self.cache[key]
            
            # Evict if at capacity
            elif len(self.cache) >= self.max_size:
                self._evict_lru()
            
            # Add new entry
            entry = CacheEntry(
                data=value,
                timestamp=time.time(),
                ttl=ttl,
                access_count=1,
                last_access=time.time()
            )
            
            self.cache[key] = entry
            self.stats['sets'] += 1

    def delete(self, key: str) -> bool:
        """Delete item from L1 cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = self.stats['hits'] / total_requests if total_requests > 0 else 0
            
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_rate': hit_rate,
                'stats': self.stats.copy()
            }

class EnhancedTradingRedisService:
    """Enhanced Redis service with multi-tier caching and optimization"""
    
    def __init__(self, redis_url: str = 'redis://localhost:6379/0'):
        self.redis_url = redis_url
        self.redis_client: Optional[redis.Redis] = None
        self.redis_cluster: Optional[redis.RedisCluster] = None
        
        # L1 Cache instances for different data types
        self.l1_price_cache = L1InMemoryCache(max_size=5000, default_ttl=60)  # 1 minute for prices
        self.l1_ohlcv_cache = L1InMemoryCache(max_size=2000, default_ttl=300)  # 5 minutes for OHLCV
        self.l1_symbols_cache = L1InMemoryCache(max_size=100, default_ttl=3600)  # 1 hour for symbols
        
        # Cache key prefixes
        self.key_prefixes = {
            'price': 'price:',
            'ohlcv': 'ohlcv:',
            'indicators': 'indicators:',
            'watchlist': 'watchlist:',
            'alerts': 'alerts:',
            'market_status': 'market:',
            'realtime': 'rt:',
            'volume': 'vol:',
            'symbols': 'symbols:',
            'trades': 'trades:'
        }
        
        # TTL configuration for different data types
        self.ttl_config = {
            'realtime_price': 30,      # 30 seconds for real-time prices
            'ohlcv_1s': 60,            # 1 minute for 1-second data
            'ohlcv_1m': 300,           # 5 minutes for 1-minute data
            'ohlcv_5m': 900,           # 15 minutes for 5-minute data
            'ohlcv_15m': 1800,         # 30 minutes for 15-minute data
            'ohlcv_30m': 3600,         # 1 hour for 30-minute data
            'ohlcv_1h': 7200,          # 2 hours for hourly data
            'ohlcv_4h': 14400,         # 4 hours for 4-hour data
            'ohlcv_1d': 86400,         # 24 hours for daily data
            'indicators': 1800,         # 30 minutes for indicators
            'market_status': 60,        # 1 minute for market status
            'symbols': 3600,            # 1 hour for symbols
            'trades': 300               # 5 minutes for trade data
        }
        
        self.connection_attempts = 0
        self.max_retries = 3
        self.retry_delay = 5

    async def connect(self):
        """Connect to Redis with retry logic"""
        while self.connection_attempts < self.max_retries:
            self.connection_attempts += 1
            try:
                if not self.redis_client:
                    # Redis Cluster mode - only if explicitly configured
                    redis_cluster_env = os.getenv("REDIS_CLUSTER_NODES")
                    
                    if redis_cluster_env:
                        redis_nodes = redis_cluster_env.split(",")
                        startup_nodes = []
                        
                        for node in redis_nodes:
                            if ':' in node:
                                try:
                                    host, port = node.split(':')
                                    startup_nodes.append(ClusterNode(host.strip(), int(port.strip())))
                                except ValueError as e:
                                    logger.warning(f"Invalid Redis cluster node format '{node}': {e}")
                                    continue
                        
                        if startup_nodes:
                            self.redis_cluster = redis.RedisCluster(
                                startup_nodes=startup_nodes,
                                decode_responses=True,
                                max_connections=100,
                                socket_timeout=10,
                                socket_connect_timeout=5,
                                health_check_interval=30
                            )
                            
                            self.redis_client = self.redis_cluster
                            logger.info(f"Connected to Redis cluster with {len(startup_nodes)} nodes")
                        else:
                            logger.warning("No valid Redis cluster nodes, falling back to single instance")
                            redis_cluster_env = None
                    
                    if not redis_cluster_env:
                        # Single Redis instance
                        self.redis_client = redis.from_url(
                            self.redis_url,
                            decode_responses=True,
                            max_connections=50,
                            socket_timeout=10,
                            socket_connect_timeout=5
                        )
                        logger.info("Connected to single Redis instance")
                    
                    # Test connection
                    await self.redis_client.ping()
                    logger.info("Redis connection established successfully")
                    
                return
            except Exception as e:
                logger.error(f"Redis connection attempt {self.connection_attempts} failed: {e}")
                if self.connection_attempts == self.max_retries:
                    logger.error(f"Failed to connect to Redis after {self.max_retries} attempts")
                    raise
                delay = self.retry_delay * (self.connection_attempts)
                logger.info(f"Retrying Redis connection in {delay} seconds...")
                await asyncio.sleep(delay)

    async def ping(self) -> bool:
        """Check Redis connection status"""
        try:
            if self.redis_client:
                result = await self.redis_client.ping()
                return result == True or result == b'PONG'
            return False
        except Exception as e:
            logger.error(f"Redis ping failed: {e}")
            return False

    async def get_with_l1_fallback(self, key: str, cache_type: str = 'ohlcv') -> Optional[Any]:
        """Get data with L1 cache fallback to Redis"""
        # Try L1 cache first
        l1_cache = self._get_l1_cache(cache_type)
        l1_result = l1_cache.get(key)
        
        if l1_result is not None:
            logger.debug(f"L1 cache hit for {key}")
            return l1_result
        
        # Fallback to Redis (L2)
        try:
            redis_result = await self.redis_client.get(key)
            if redis_result:
                # Parse JSON or pickle data
                try:
                    data = json.loads(redis_result)
                except json.JSONDecodeError:
                    data = pickle.loads(redis_result.encode('latin-1'))
                
                # Store in L1 cache for next time
                l1_cache.set(key, data)
                logger.debug(f"L2 cache hit for {key}, promoted to L1")
                return data
        except Exception as e:
            logger.warning(f"Redis error for key {key}: {e}")
        
        return None

    async def set_multi_tier(self, key: str, value: Any, cache_type: str = 'ohlcv', ttl: Optional[int] = None) -> bool:
        """Set data in both L1 and L2 caches"""
        ttl = ttl or self._get_ttl_for_key(key)
        
        try:
            # Set in L1 cache
            l1_cache = self._get_l1_cache(cache_type)
            l1_cache.set(key, value, ttl)
            
            # Set in Redis (L2)
            serialized_value = self._serialize_value(value)
            await self.redis_client.setex(key, ttl, serialized_value)
            
            return True
        except Exception as e:
            logger.error(f"Failed to set multi-tier cache for {key}: {e}")
            return False

    def _get_l1_cache(self, cache_type: str) -> L1InMemoryCache:
        """Get appropriate L1 cache based on data type"""
        if cache_type == 'price':
            return self.l1_price_cache
        elif cache_type == 'ohlcv':
            return self.l1_ohlcv_cache
        elif cache_type == 'symbols':
            return self.l1_symbols_cache
        else:
            return self.l1_ohlcv_cache  # Default

    def _get_ttl_for_key(self, key: str) -> int:
        """Determine TTL based on key pattern"""
        for pattern, ttl in self.ttl_config.items():
            if pattern in key:
                return ttl
        return 300  # Default 5 minutes

    def _serialize_value(self, value: Any) -> str:
        """Serialize value for Redis storage"""
        if isinstance(value, pd.DataFrame):
            return value.to_json(orient='index', date_format='iso')
        elif isinstance(value, (dict, list)):
            return json.dumps(value, default=str)
        else:
            return str(value)

    async def invalidate_pattern(self, pattern: str):
        """Invalidate cache entries matching the given pattern in Redis."""
        try:
            if self.redis_cluster:
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
            elif self.redis_client:
                cursor = 0
                keys_to_delete = []
                while True:
                    cursor, keys = await self.redis_client.scan(cursor, match=pattern, count=1000)
                    keys_to_delete.extend(keys)
                    if cursor == 0:
                        break
                if keys_to_delete:
                    await self.redis_client.delete(*keys_to_delete)
                    logger.info(f"Invalidated {len(keys_to_delete)} cache entries for pattern: {pattern}")
            else:
                logger.warning("No Redis connection available for cache invalidation")
        except Exception as e:
            logger.error(f"Failed to invalidate cache pattern {pattern}: {e}")

    async def cleanup_expired_keys(self, pattern: str = "*"):
        """Cleanup expired keys (maintenance operation)"""
        try:
            cursor = 0
            cleaned_count = 0
            
            while True:
                cursor, keys = await self.redis_client.scan(cursor=cursor, match=pattern, count=1000)
                
                if isinstance(keys, list):
                    # Convert bytes to string if needed
                    keys = [k.decode() if isinstance(k, (bytes, bytearray)) else str(k) for k in keys]
                
                if keys:
                    # Check TTL for each key and delete expired ones
                    pipe = self.redis_client.pipeline()
                    for key in keys:
                        pipe.ttl(key)
                    
                    try:
                        ttls = await pipe.execute()
                        
                        # TTL == -2 → key does not exist; TTL == -1 → no expire set
                        expired_keys = [k for k, ttl in zip(keys, ttls) if ttl in (-2, None)]
                        if expired_keys:
                            await self.redis_client.delete(*expired_keys)
                            cleaned_count += len(expired_keys)
                    except Exception as e:
                        logger.warning(f"Pipeline operation failed during cleanup: {e}")
                
                if cursor == 0:
                    break
            
            logger.info(f"Cleaned up {cleaned_count} expired keys")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return 0

    async def set_ohlcv_cache(self, symbol: str, timeframe: str, df: pd.DataFrame, 
                            dataset: str = None) -> bool:
        """Cache OHLCV data with compression for large datasets"""
        try:
            cache_key = f"{self.key_prefixes['ohlcv']}{symbol}:{timeframe}"
            if dataset:
                cache_key += f":{dataset}"
            
            # Prepare data for caching
            cache_data = {
                'data': df.to_json(orient='index', date_format='iso'),
                'cached_at': datetime.now(timezone.utc).isoformat(),
                'record_count': len(df),
                'symbol': symbol,
                'timeframe': timeframe,
                'dataset': dataset
            }
            
            # Determine appropriate TTL
            ttl_key = f"ohlcv_{timeframe.replace('ohlcv-', '')}"
            ttl = self.ttl_config.get(ttl_key, self.ttl_config['ohlcv_1d'])
            
            # Use compression for large datasets
            if len(df) > 1000:
                serialized_data = pickle.dumps(cache_data)
                await self.redis_client.setex(cache_key, ttl, serialized_data)
            else:
                # Set in multi-tier cache for smaller datasets
                await self.set_multi_tier(cache_key, cache_data, 'ohlcv', ttl)
            
            logger.debug(f"Cached OHLCV data for {symbol}:{timeframe} ({len(df)} records)")
            return True
            
        except Exception as e:
            logger.error(f"Error caching OHLCV for {symbol}: {e}")
            return False

    async def get_ohlcv_cache(self, symbol: str, timeframe: str, 
                            dataset: str = None) -> Optional[pd.DataFrame]:
        """Retrieve cached OHLCV data with multi-tier lookup"""
        cache_key = f"{self.key_prefixes['ohlcv']}{symbol}:{timeframe}"
        if dataset:
            cache_key += f":{dataset}"
        
        # Try multi-tier cache
        cached_data = await self.get_with_l1_fallback(cache_key, 'ohlcv')
        
        if cached_data:
            try:
                if isinstance(cached_data, bytes):
                    # Decompress pickled data
                    data = pickle.loads(cached_data)
                else:
                    data = cached_data
                
                df = pd.read_json(data['data'], orient='index')
                df.index = pd.to_datetime(df.index)
                
                logger.debug(f"Cache hit for {symbol}:{timeframe} - {data['record_count']} records")
                return df
                
            except Exception as e:
                logger.warning(f"Error parsing cached OHLCV data for {symbol}: {e}")
        
        return None

    async def batch_cache_operations(self, operations: List[Dict]) -> List[Any]:
        """Execute multiple cache operations in parallel"""
        try:
            tasks = []
            
            for op in operations:
                if op['type'] == 'get':
                    task = self.get_with_l1_fallback(op['key'], op.get('cache_type', 'ohlcv'))
                elif op['type'] == 'set':
                    task = self.set_multi_tier(
                        op['key'], 
                        op['value'], 
                        op.get('cache_type', 'ohlcv'),
                        op.get('ttl')
                    )
                elif op['type'] == 'delete':
                    task = self.delete_from_all_tiers(op['key'])
                else:
                    continue
                
                tasks.append(task)
            
            return await asyncio.gather(*tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error(f"Batch cache operations failed: {e}")
            return []

    async def delete_from_all_tiers(self, key: str) -> bool:
        """Delete key from both L1 and L2 caches"""
        try:
            # Delete from L1 caches
            self.l1_price_cache.delete(key)
            self.l1_ohlcv_cache.delete(key)
            self.l1_symbols_cache.delete(key)
            
            # Delete from Redis
            await self.redis_client.delete(key)
            return True
            
        except Exception as e:
            logger.error(f"Error deleting key {key}: {e}")
            return False

    async def get_top_movers(self, limit: int = 20, by: str = 'change_pct') -> List[Dict[str, Any]]:
        """Get top price movers efficiently"""
        try:
            ranking_key = f"{self.key_prefixes['price']}ranking"
            if by == 'volume':
                ranking_key = f"{self.key_prefixes['volume']}ranking"
            
            # Get top symbols by ranking
            top_symbols = await self.redis_client.zrevrange(
                ranking_key, 0, limit - 1, withscores=True
            )
            
            if not top_symbols:
                return []
            
            # Get detailed price data for top symbols
            symbols = [symbol for symbol, _ in top_symbols]
            price_data = await self.get_multiple_prices(symbols)
            
            # Combine ranking with price data
            result = []
            for symbol, score in top_symbols:
                if symbol in price_data:
                    data = price_data[symbol].copy()
                    data['rank_score'] = float(score)
                    result.append(data)
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting top movers: {e}")
            return []

    async def warm_cache_for_symbols(self, symbols: List[str], timeframes: List[str] = None):
        """Pre-warm cache for frequently accessed symbols"""
        timeframes = timeframes or ['ohlcv-1m', 'ohlcv-5m', 'ohlcv-1h', 'ohlcv-1d']
        
        logger.info(f"Warming cache for {len(symbols)} symbols across {len(timeframes)} timeframes")
        
        # This would typically trigger background data loading
        warm_operations = []
        for symbol in symbols:
            for timeframe in timeframes:
                cache_key = f"{self.key_prefixes['ohlcv']}{symbol}:{timeframe}"
                warm_operations.append({
                    'type': 'get',
                    'key': cache_key,
                    'cache_type': 'ohlcv'
                })
        
        # Execute in batches to avoid overwhelming the system
        batch_size = 50
        for i in range(0, len(warm_operations), batch_size):
            batch = warm_operations[i:i + batch_size]
            await self.batch_cache_operations(batch)
            await asyncio.sleep(0.1)  # Small delay between batches

    def get_comprehensive_stats(self) -> Dict:
        """Get comprehensive cache statistics"""
        return {
            'l1_caches': {
                'price': self.l1_price_cache.get_stats(),
                'ohlcv': self.l1_ohlcv_cache.get_stats(),
                'symbols': self.l1_symbols_cache.get_stats()
            },
            'redis_connection': {
                'type': 'cluster' if self.redis_cluster else 'single',
                'connected': self.redis_client is not None
            }
        }

    async def get_cache_memory_usage(self) -> Dict:
        """Get Redis memory usage statistics"""
        try:
            info = await self.redis_client.info('memory')
            return {
                'used_memory': info.get('used_memory_human'),
                'used_memory_rss': info.get('used_memory_rss_human'),
                'used_memory_peak': info.get('used_memory_peak_human'),
                'memory_fragmentation_ratio': info.get('mem_fragmentation_ratio'),
                'total_system_memory': info.get('total_system_memory_human')
            }
        except Exception as e:
            logger.error(f"Error getting memory usage: {e}")
            return {}

    async def set_real_time_price(self, symbol: str, price_data: Dict[str, Any]) -> bool:
        """Set real-time price with ultra-low latency"""
        try:
            key = f"{self.key_prefixes['realtime']}{symbol}"
            
            # Enhanced price data with computed fields
            enhanced_data = {
                'symbol': symbol,
                'price': float(price_data.get('price', 0)),
                'bid': float(price_data.get('bid', 0)),
                'ask': float(price_data.get('ask', 0)),
                'volume': int(price_data.get('volume', 0)),
                'timestamp': price_data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'change': float(price_data.get('change', 0)),
                'change_pct': float(price_data.get('change_pct', 0)),
                'spread': float(price_data.get('ask', 0)) - float(price_data.get('bid', 0)),
                'mid_price': (float(price_data.get('ask', 0)) + float(price_data.get('bid', 0))) / 2
            }
            
            # Set in multi-tier cache
            await self.set_multi_tier(key, enhanced_data, 'price', self.ttl_config['realtime_price'])
            
            # Update price ranking for top movers
            await self.redis_client.zadd(
                f"{self.key_prefixes['price']}ranking",
                {symbol: enhanced_data['change_pct']}
            )
            
            # Update volume ranking
            await self.redis_client.zadd(
                f"{self.key_prefixes['volume']}ranking",
                {symbol: enhanced_data['volume']}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting real-time price for {symbol}: {e}")
            return False

    async def get_real_time_price(self, symbol: str) -> Optional[Dict[str, Any]]:
        """Get real-time price with multi-tier caching"""
        key = f"{self.key_prefixes['realtime']}{symbol}"
        return await self.get_with_l1_fallback(key, 'price')

    async def get_multiple_prices(self, symbols: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get multiple real-time prices efficiently"""
        keys = [f"{self.key_prefixes['realtime']}{symbol}" for symbol in symbols]
        
        # Try to get from L1 cache first
        results = {}
        missing_keys = []
        
        for symbol, key in zip(symbols, keys):
            l1_result = self.l1_price_cache.get(key)
            if l1_result:
                results[symbol] = l1_result
            else:
                missing_keys.append((symbol, key))
        
        # Batch fetch missing keys from Redis
        if missing_keys:
            try:
                pipe = self.redis_client.pipeline()
                for _, key in missing_keys:
                    pipe.get(key)
                
                redis_results = await pipe.execute()
                
                for (symbol, key), redis_result in zip(missing_keys, redis_results):
                    if redis_result:
                        try:
                            data = json.loads(redis_result)
                            results[symbol] = data
                            # Cache in L1 for next time
                            self.l1_price_cache.set(key, data)
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse price data for {symbol}")
                            
            except Exception as e:
                logger.error(f"Error fetching multiple prices: {e}")
        
        return results

# ----------------------- Singleton Instance -----------------------

_redis_service = None

async def get_redis_service() -> EnhancedTradingRedisService:
    """Get singleton Redis service instance"""
    global _redis_service
    if _redis_service is None:
        _redis_service = EnhancedTradingRedisService()
        await _redis_service.connect()
    return _redis_service

# ----------------------- Backward Compatibility -----------------------

class TradingRedisService:
    """Legacy class for backward compatibility"""
    def __init__(self, redis_url: str = 'redis://localhost:6379/0'):
        self.enhanced_service = EnhancedTradingRedisService(redis_url)
    
    async def connect(self):
        return await self.enhanced_service.connect()
    
    async def get_symbol_data(self, symbol: str, timeframe: str):
        return await self.enhanced_service.get_ohlcv_cache(symbol, timeframe)
    
    async def set_symbol_data(self, symbol: str, timeframe: str, data: Dict):
        # Convert dict to DataFrame for compatibility
        if isinstance(data, dict) and 'data' in data:
            df = pd.read_json(data['data'], orient='index')
            return await self.enhanced_service.set_ohlcv_cache(symbol, timeframe, df)
        return False