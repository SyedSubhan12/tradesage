import redis
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from ..models.market_data import Symbol, OHLCVData, TradeData, NewsData
import logging

logger = logging.getLogger(__name__)

class DataStorageService:
    def __init__(self, db: Session, redis_client: redis.Redis):
        self.db = db
        self.redis_client = redis_client
        self.cache_ttl = {
            'ohlcv-1s': 60,      # 1 minute
            'ohlcv-1m': 300,     # 5 minutes
            'ohlcv-1h': 1800,    # 30 minutes
            'ohlcv-1d': 3600,    # 1 hour
            'symbols': 3600,     # 1 hour
            'news': 1800         # 30 minutes
        }
    
    def get_ohlcv_data(self, symbol: str, timeframe: str, start_date: datetime, 
                       end_date: datetime, dataset: Optional[str] = None) -> pd.DataFrame:
        """Get OHLCV data with Redis caching"""
        # Generate cache key
        cache_key = f"ohlcv:{symbol}:{timeframe}:{start_date.date()}:{end_date.date()}:{dataset or 'any'}"
        
        # Try Redis cache first
        try:
            cached_data = self.redis_client.get(cache_key)
            if cached_data:
                logger.info(f"Cache hit for {cache_key}")
                return pd.read_json(cached_data)
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")
        
        # Query database
        query = self.db.query(OHLCVData).filter(
            and_(
                OHLCVData.symbol == symbol,
                OHLCVData.timeframe == timeframe,
                OHLCVData.timestamp >= start_date,
                OHLCVData.timestamp <= end_date
            )
        )
        
        if dataset:
            query = query.filter(OHLCVData.dataset == dataset)
        
        query = query.order_by(OHLCVData.timestamp)
        results = query.all()
        
        # Convert to DataFrame
        if results:
            data = [{
                'timestamp': r.timestamp,
                'open': float(r.open) if r.open else None,
                'high': float(r.high) if r.high else None,
                'low': float(r.low) if r.low else None,
                'close': float(r.close) if r.close else None,
                'volume': r.volume,
                'vwap': float(r.vwap) if r.vwap else None,
                'trades_count': r.trades_count
            } for r in results]
            
            df = pd.DataFrame(data)
            df.set_index('timestamp', inplace=True)
            
            # Cache the result
            try:
                ttl = self.cache_ttl.get(timeframe, 300)
                self.redis_client.setex(cache_key, ttl, df.to_json())
            except Exception as e:
                logger.warning(f"Failed to cache data: {e}")
            
            return df
        
        return pd.DataFrame()
    
    def get_trade_data(self, symbol: str, start_date: datetime, end_date: datetime,
                       dataset: Optional[str] = None, limit: Optional[int] = None) -> pd.DataFrame:
        """Get trade data"""
        query = self.db.query(TradeData).filter(
            and_(
                TradeData.symbol == symbol,
                TradeData.timestamp >= start_date,
                TradeData.timestamp <= end_date
            )
        )
        
        if dataset:
            query = query.filter(TradeData.dataset == dataset)
        
        query = query.order_by(TradeData.timestamp.desc())
        
        if limit:
            query = query.limit(limit)
        
        results = query.all()
        
        if results:
            data = [{
                'timestamp': r.timestamp,
                'price': float(r.price),
                'size': r.size,
                'side': r.side,
                'trade_id': r.trade_id
            } for r in results]
            
            df = pd.DataFrame(data)
            df.set_index('timestamp', inplace=True)
            return df
        
        return pd.DataFrame()
    
    def get_symbols(self, dataset: Optional[str] = None) -> List[str]:
        """Get list of available symbols with caching"""
        cache_key = f"symbols:{dataset or 'all'}"
        
        # Try cache first
        try:
            cached_symbols = self.redis_client.get(cache_key)
            if cached_symbols:
                return json.loads(cached_symbols)
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")
        
        # Query database
        query = self.db.query(Symbol.symbol).distinct()
        
        if dataset:
            query = query.filter(Symbol.dataset == dataset)
        
        results = query.all()
        symbols = [r.symbol for r in results]
        
        # Cache the result
        try:
            self.redis_client.setex(cache_key, self.cache_ttl['symbols'], json.dumps(symbols))
        except Exception as e:
            logger.warning(f"Failed to cache symbols: {e}")
        
        return symbols
    
    def invalidate_cache(self, pattern: str):
        """Invalidate cache entries matching pattern"""
        try:
            for key in self.redis_client.scan_iter(match=pattern):
                self.redis_client.delete(key)
            logger.info(f"Invalidated cache pattern: {pattern}")
        except Exception as e:
            logger.error(f"Failed to invalidate cache: {e}")
