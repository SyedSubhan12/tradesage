from sqlalchemy import Column, Integer, String, DateTime, Numeric, BigInteger, Index, UniqueConstraint, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func
import uuid
import datetime

Base = declarative_base()

class Symbol(Base):
    __tablename__ = "symbols"
    
    id = Column(Integer, primary_key=True, index=True)
    symbol = Column(String(20), nullable=False, index=True)
    dataset = Column(String(50), nullable=False, index=True)
    instrument_id = Column(BigInteger, index=True)
    description = Column(String(500))
    sector = Column(String(100), index=True)
    industry = Column(String(100))
    market_cap = Column(BigInteger)
    currency = Column(String(3), default='USD')
    exchange = Column(String(50))
    is_active = Column(Boolean, default=True, index=True)
    meta = Column('metadata', JSONB)  # Additional flexible data
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    __table_args__ = (
        UniqueConstraint('symbol', 'dataset', name='uq_symbol_dataset'),
        Index('idx_symbol_active', 'symbol', 'is_active'),
        Index('idx_sector_active', 'sector', 'is_active'),
        # Composite index for fast filtering
        Index('idx_symbol_dataset_active', 'symbol', 'dataset', 'is_active'),
    )

class OHLCVData(Base):
    __tablename__ = "ohlcv_data"
    
    id = Column(Integer, primary_key=True)
    symbol = Column(String(20), nullable=False, index=True)
    dataset = Column(String(50), nullable=False, index=True)
    timeframe = Column(String(20), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    open = Column(Numeric(20, 8))
    high = Column(Numeric(20, 8))
    low = Column(Numeric(20, 8))
    close = Column(Numeric(20, 8))
    volume = Column(BigInteger)
    vwap = Column(Numeric(20, 8))  # Volume Weighted Average Price
    trades_count = Column(Integer)
    
    # Technical indicators (pre-calculated for speed)
    sma_20 = Column(Numeric(20, 8))  # 20-period Simple Moving Average
    ema_20 = Column(Numeric(20, 8))  # 20-period Exponential Moving Average
    rsi_14 = Column(Numeric(5, 2))   # 14-period RSI
    volatility = Column(Numeric(10, 6))  # Realized volatility
    
    # Quality flags
    is_market_hours = Column(Boolean, default=True)
    data_quality_score = Column(Numeric(3, 2))  # 0-1 quality score
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    __table_args__ = (
        UniqueConstraint('symbol', 'dataset', 'timeframe', 'timestamp', name='uq_ohlcv_record'),
        # Optimized indexes for trading queries
        Index('idx_ohlcv_symbol_timeframe_timestamp', 'symbol', 'timeframe', 'timestamp'),
        Index('idx_ohlcv_timestamp_desc', 'timestamp', postgresql_using='btree'),
        Index('idx_ohlcv_symbol_latest', 'symbol', 'timeframe', 'timestamp'),
        # Index for scanning latest data across symbols
        Index('idx_ohlcv_timeframe_timestamp', 'timeframe', 'timestamp'),
        # Partial index for active market hours
        Index('idx_ohlcv_market_hours', 'symbol', 'timestamp', 
              postgresql_where="is_market_hours = true"),
    )

class RealTimeTicks(Base):
    """Ultra-fast table for real-time price updates"""
    __tablename__ = "realtime_ticks"
    
    id = Column(BigInteger, primary_key=True)
    symbol = Column(String(20), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    price = Column(Numeric(20, 8), nullable=False)
    size = Column(BigInteger)
    bid = Column(Numeric(20, 8))
    ask = Column(Numeric(20, 8))
    bid_size = Column(BigInteger)
    ask_size = Column(BigInteger)
    spread = Column(Numeric(20, 8))
    
    # Microsecond precision for HFT
    microsecond = Column(Integer)
    exchange_timestamp = Column(DateTime(timezone=True))
    
    __table_args__ = (
        # Hyper-optimized for real-time queries
        Index('idx_realtime_symbol_timestamp', 'symbol', 'timestamp'),
        Index('idx_realtime_timestamp_desc', 'timestamp', postgresql_using='btree'),
        # Partial index for recent data (last hour)
        Index('idx_realtime_recent', 'symbol', 'timestamp', 
              postgresql_where="timestamp > (now() - interval '1 hour')"),
    )

class MarketIndicators(Base):
    """Pre-calculated market-wide indicators"""
    __tablename__ = "market_indicators"
    
    id = Column(Integer, primary_key=True)
    indicator_name = Column(String(50), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    value = Column(Numeric(20, 8))
    meta = Column('metadata', JSONB)
    
    __table_args__ = (
        UniqueConstraint('indicator_name', 'timestamp', name='uq_indicator_timestamp'),
        Index('idx_indicator_name_timestamp', 'indicator_name', 'timestamp'),
    )

class TradingSession(Base):
    """Track data ingestion and processing sessions"""
    __tablename__ = "trading_sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_date = Column(DateTime(timezone=True), nullable=False, index=True)
    market = Column(String(20), nullable=False)  # 'US', 'EU', 'ASIA'
    session_type = Column(String(20))  # 'regular', 'extended', 'pre_market'
    is_complete = Column(Boolean, default=False)
    symbols_processed = Column(Integer, default=0)
    records_ingested = Column(BigInteger, default=0)
    processing_start = Column(DateTime(timezone=True))
    processing_end = Column(DateTime(timezone=True))
    
    __table_args__ = (
        Index('idx_session_date_market', 'session_date', 'market'),
        Index('idx_session_complete', 'is_complete', 'session_date'),
    )

class TradeData(Base):
    __tablename__ = "trade_data"
    
    id = Column(Integer, primary_key=True, index=True)
    symbol = Column(String(20), nullable=False)
    dataset = Column(String(50), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    price = Column(Numeric(20, 8), nullable=False)
    size = Column(BigInteger, nullable=False)
    side = Column(String(10))  # 'buy', 'sell', 'unknown'
    trade_id = Column(String(50))
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    __table_args__ = (
        Index('idx_trade_symbol_timestamp', 'symbol', 'timestamp'),
        Index('idx_trade_timestamp', 'timestamp'),
    )

class NewsData(Base):
    __tablename__ = "news_data"
    
    id = Column(Integer, primary_key=True, index=True)
    symbol = Column(String(20))
    headline = Column(String(1000), nullable=False)
    content = Column(Text)
    source = Column(String(100))
    sentiment_score = Column(Numeric(5, 4))  # -1 to 1
    published_at = Column(DateTime(timezone=True), nullable=False)
    url = Column(String(1000))
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    __table_args__ = (
        Index('idx_news_symbol_published', 'symbol', 'published_at'),
        Index('idx_news_published', 'published_at'),
    )
