import redis.asyncio as redis
import json
import pickle
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
import logging
from decimal import Decimal

logger = logging.getLogger(__name__)

class TradingRedisService:
    """Optimized Redis service for high-frequency trading data"""
    
    def __init__(self, redis_url: str = 'redis://localhost:6379/0'):
        self.redis_url = redis_url
        
        self.key_prefixes = {
            'price': 'price:',
            'ohlcv': 'ohlcv:',
            'indicators': 'indicators:',
            'watchlist': 'watchlist:',
            'alerts': 'alerts:',
            'market_status': 'market:',
            'realtime': 'rt:',
            'volume': 'vol:',
            'news': 'news:'
        }
        self.ttl_config = {
            'realtime': 300,      # 5 minutes for real-time data
            'ohlcv_1m': 3600,     # 1 hour for minute data
            'ohlcv_1h': 14400,    # 4 hours for hourly data
            'ohlcv_1d': 86400,    # 24 hours for daily data
            'indicators': 1800,    # 30 minutes for indicators
            'market_status': 60,   # 1 minute for market status
            'news': 7200          # 2 hours for news
        }
    
    async def connect(self):
        self.redis_client = redis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_keepalive=True,
            socket_timeout=30,
            socket_connect_timeout=10,
            socket_keepalive_options={
                'keepalive': 1,
                'keepalive_probes': 6,
                'keepalive_intvl': 60,
                'keepalive_time': 60
            }
            
            
        )
    async def get_symbol_data(self, symbol: str, timeframe: str) -> Optional[Dict[str, Any]]:
        key = f"ohlcv:{symbol}:{timeframe}"
        try:
            data = await self.redis_client.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.error(f"Error getting symbol data for {symbol}: {e}")
            return None
        
    async def set_symbol_data(self, symbol: str, timeframe: str, data: Dict[str, Any]) -> bool:
        key = f"ohlcv:{symbol}:{timeframe}"
        try:
            await self.redis_client.setex(
                key,
                self.ttl_config.get(f"ohlcv_{timeframe.split('-')[1]}", 3600),
                json.dumps(data, default=str)
            )
            return True
        except Exception as e:
            logger.error(f"Error setting symbol data for {symbol}: {e}")
            return False
    async def invalidate_symbol_data(self, symbol: str, timeframe: str) -> bool:
        pattern = f"ohlcv:{symbol}:*"
        try:
            keys = await self.redis_client.keys(pattern)
            if keys:
                await self.redis_client.delete(*keys)
            return True
        except Exception as e:
            logger.error(f"Error invalidating symbol data for {symbol}: {e}")
            return False
    def set_real_time_price(self, symbol: str, price_data: Dict[str, Any]) -> bool:
        """Set real-time price with ultra-low latency"""
        try:
            key = f"{self.key_prefixes['realtime']}{symbol}"
            
            # Use Redis Hash for structured data
            pipe = self.redis_client.pipeline()
            pipe.hset(key, mapping={
                'price': str(price_data.get('price', 0)),
                'bid': str(price_data.get('bid', 0)),
                'ask': str(price_data.get('ask', 0)),
                'volume': str(price_data.get('volume', 0)),
                'timestamp': price_data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'change': str(price_data.get('change', 0)),
                'change_pct': str(price_data.get('change_pct', 0))
            })
            pipe.expire(key, self.ttl_config['realtime'])
            pipe.execute()
            
            # Also maintain a sorted set for price ranking
            self.redis_client.zadd(
                f"{self.key_prefixes['price']}ranking",
                {symbol: float(price_data.get('price', 0))}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting real-time price for {symbol}: {e}")
            return False
    
    def get_real_time_price(self, symbol: str) -> Optional[Dict[str, Any]]:
        """Get real-time price with microsecond latency"""
        try:
            key = f"{self.key_prefixes['realtime']}{symbol}"
            data = self.redis_client.hgetall(key)
            
            if data:
                return {
                    'symbol': symbol,
                    'price': float(data.get('price', 0)),
                    'bid': float(data.get('bid', 0)),
                    'ask': float(data.get('ask', 0)),
                    'volume': int(data.get('volume', 0)),
                    'timestamp': data.get('timestamp'),
                    'change': float(data.get('change', 0)),
                    'change_pct': float(data.get('change_pct', 0))
                }
            return None
            
        except Exception as e:
            logger.error(f"Error getting real-time price for {symbol}: {e}")
            return None
    
    def set_ohlcv_cache(self, symbol: str, timeframe: str, df: pd.DataFrame) -> bool:
        """Cache OHLCV data efficiently"""
        try:
            key = f"{self.key_prefixes['ohlcv']}{symbol}:{timeframe}"
            
            # Convert DataFrame to compressed JSON
            data = {
                'data': df.to_json(orient='index', date_format='iso'),
                'cached_at': datetime.now(timezone.utc).isoformat(),
                'record_count': len(df)
            }
            
            # Use compression for larger datasets
            if len(df) > 1000:
                compressed_data = pickle.dumps(data)
                self.redis_client.set(key, compressed_data)
            else:
                self.redis_client.set(key, json.dumps(data))
            
            # Set appropriate TTL based on timeframe
            ttl_key = f"ohlcv_{timeframe.split('-')[1]}" if '-' in timeframe else 'ohlcv_1d'
            ttl = self.ttl_config.get(ttl_key, 3600)
            self.redis_client.expire(key, ttl)
            
            return True
            
        except Exception as e:
            logger.error(f"Error caching OHLCV for {symbol}: {e}")
            return False
    
    def get_ohlcv_cache(self, symbol: str, timeframe: str) -> Optional[pd.DataFrame]:
        """Retrieve cached OHLCV data"""
        try:
            key = f"{self.key_prefixes['ohlcv']}{symbol}:{timeframe}"
            cached_data = self.redis_client.get(key)
            
            if cached_data:
                try:
                    # Try JSON first
                    data = json.loads(cached_data)
                except json.JSONDecodeError:
                    # Try pickle for compressed data
                    data = pickle.loads(cached_data)
                
                df = pd.read_json(data['data'], orient='index')
                df.index = pd.to_datetime(df.index)
                
                logger.info(f"Cache hit for {symbol}:{timeframe} - {data['record_count']} records")
                return df
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving OHLCV cache for {symbol}: {e}")
            return None
    
    def set_market_indicators(self, indicators: Dict[str, float]) -> bool:
        """Cache market-wide indicators"""
        try:
            key = f"{self.key_prefixes['indicators']}market"
            
            pipe = self.redis_client.pipeline()
            for indicator, value in indicators.items():
                pipe.hset(key, indicator, str(value))
            
            pipe.hset(key, 'updated_at', datetime.now(timezone.utc).isoformat())
            pipe.expire(key, self.ttl_config['indicators'])
            pipe.execute()
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting market indicators: {e}")
            return False
    
    def get_top_movers(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get top price movers from Redis"""
        try:
            # Get symbols with highest price changes
            top_gainers = self.redis_client.zrevrange(
                f"{self.key_prefixes['price']}ranking", 0, limit-1, withscores=True
            )
            
            result = []
            for symbol, price in top_gainers:
                symbol = symbol.decode('utf-8') if isinstance(symbol, bytes) else symbol
                price_data = self.get_real_time_price(symbol)
                if price_data:
                    result.append(price_data)
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting top movers: {e}")
            return []
    
    def add_to_watchlist(self, user_id: str, symbols: List[str]) -> bool:
        """Add symbols to user's watchlist"""
        try:
            key = f"{self.key_prefixes['watchlist']}{user_id}"
            self.redis_client.sadd(key, *symbols)
            return True
            
        except Exception as e:
            logger.error(f"Error adding to watchlist for user {user_id}: {e}")
            return False
    
    def get_watchlist_prices(self, user_id: str) -> List[Dict[str, Any]]:
        """Get real-time prices for user's watchlist"""
        try:
            key = f"{self.key_prefixes['watchlist']}{user_id}"
            symbols = self.redis_client.smembers(key)
            
            result = []
            for symbol in symbols:
                symbol = symbol.decode('utf-8') if isinstance(symbol, bytes) else symbol
                price_data = self.get_real_time_price(symbol)
                if price_data:
                    result.append(price_data)
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting watchlist prices for user {user_id}: {e}")
            return []
    
    def invalidate_symbol_cache(self, symbol: str):
        """Invalidate all cache entries for a symbol"""
        try:
            pattern = f"*{symbol}*"
            for key in self.redis_client.scan_iter(match=pattern):
                self.redis_client.delete(key)
            
            logger.info(f"Invalidated cache for symbol: {symbol}")
            
        except Exception as e:
            logger.error(f"Error invalidating cache for {symbol}: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get Redis cache statistics"""
        try:
            info = self.redis_client.info()
            return {
                'used_memory': info.get('used_memory_human'),
                'total_keys': self.redis_client.dbsize(),
                'hit_rate': info.get('keyspace_hits', 0) / max(1, info.get('keyspace_misses', 0) + info.get('keyspace_hits', 0)),
                'connected_clients': info.get('connected_clients'),
                'operations_per_sec': info.get('instantaneous_ops_per_sec')
            }
            
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {}
    
