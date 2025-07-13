from pydantic import BaseModel, Field, field_validator, ConfigDict
from datetime import datetime
from typing import Optional, List, Dict, Any
from decimal import Decimal

class SymbolBase(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=20)
    dataset: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    sector: Optional[str] = None
    industry: Optional[str] = None
    market_cap: Optional[int] = None
    currency: Optional[str] = Field(default="USD", max_length=3)
    exchange: Optional[str] = None

class SymbolCreate(SymbolBase):
    # These fields are required for creation but optional in base
    currency: str = Field(default="USD", max_length=3)
    exchange: str = Field(..., min_length=1, max_length=50)
    industry: str = Field(default="Unknown", max_length=100)
    
    # Optional fields for creation
    instrument_id: Optional[int] = None
    is_active: bool = Field(default=True)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class SymbolResponse(SymbolBase):
    id: int
    instrument_id: Optional[int] = None
    is_active: bool = True
    metadata: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class OHLCVBase(BaseModel):
    timestamp: datetime
    timeframe: str = Field(..., pattern=r'^ohlcv-(1s|1m|5m|15m|30m|1h|4h|1d|1w|1M)$')
    open: Optional[Decimal] = Field(None, ge=0)
    high: Optional[Decimal] = Field(None, ge=0)
    low: Optional[Decimal] = Field(None, ge=0)
    close: Optional[Decimal] = Field(None, ge=0)
    volume: Optional[int] = Field(None, ge=0)
    vwap: Optional[Decimal] = Field(None, ge=0)
    # FIXED: Changed from trade_count to trades_count to match model
    trades_count: Optional[int] = Field(None, ge=0)

class OHLCVCreate(OHLCVBase):
    symbol_id: int  # Added missing field - this is the foreign key
    
    @field_validator('high', 'low', 'close')
    @classmethod
    def validate_prices(cls, v, info):
        if info.data.get('open') and v:
            open_price = info.data['open']
            # Basic validation: prices should be reasonable relative to open
            if v > open_price * 10 or v < open_price * 0.1:
                raise ValueError('Price seems unreasonable compared to open price')
        return v

class OHLCVResponse(OHLCVBase):
    id: int
    symbol_id: int
    symbol: Optional[str] = None  # Can be populated via join
    dataset: Optional[str] = None  # Can be populated via join
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

# Alternative OHLCV schema for input with symbol name instead of ID
class OHLCVCreateWithSymbol(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=20)
    dataset: str = Field(..., min_length=1, max_length=50)
    timestamp: datetime
    timeframe: str = Field(..., pattern=r'^ohlcv-(1s|1m|5m|15m|30m|1h|4h|1d|1w|1M)$')
    open: Optional[Decimal] = Field(None, ge=0)
    high: Optional[Decimal] = Field(None, ge=0)
    low: Optional[Decimal] = Field(None, ge=0)
    close: Optional[Decimal] = Field(None, ge=0)
    volume: Optional[int] = Field(None, ge=0)
    vwap: Optional[Decimal] = Field(None, ge=0)
    # FIXED: Changed from trade_count to trades_count to match model
    trades_count: Optional[int] = Field(None, ge=0)
    
    @field_validator('high', 'low', 'close')
    @classmethod
    def validate_prices(cls, v, info):
        if info.data.get('open') and v:
            open_price = info.data['open']
            if v > open_price * 10 or v < open_price * 0.1:
                raise ValueError('Price seems unreasonable compared to open price')
        return v

class TradeBase(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=20)
    dataset: str = Field(..., min_length=1, max_length=50)
    timestamp: datetime
    price: Decimal = Field(..., gt=0)
    size: int = Field(..., gt=0)
    side: Optional[str] = Field(None, pattern=r'^(buy|sell|unknown)$')
    trade_id: Optional[str] = None

class TradeCreate(TradeBase):
    pass

class TradeResponse(TradeBase):
    id: int
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class NewsBase(BaseModel):
    symbol: Optional[str] = None
    headline: str = Field(..., min_length=1, max_length=1000)
    content: Optional[str] = None
    source: Optional[str] = None
    sentiment_score: Optional[Decimal] = Field(None, ge=-1, le=1)
    published_at: datetime
    url: Optional[str] = None

class NewsCreate(NewsBase):
    pass

class NewsResponse(NewsBase):
    id: int
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

# Query Schemas
class OHLCVQuery(BaseModel):
    symbol: str
    timeframe: str = Field(default="ohlcv-1d", pattern=r'^ohlcv-(1s|1m|5m|15m|30m|1h|4h|1d|1w|1M)$')
    start_date: datetime
    end_date: datetime
    dataset: Optional[str] = None
    limit: Optional[int] = Field(None, gt=0, le=10000)

class TradeQuery(BaseModel):
    symbol: str
    start_date: datetime
    end_date: datetime
    dataset: Optional[str] = None
    limit: Optional[int] = Field(None, gt=0, le=50000)

class NewsQuery(BaseModel):
    symbol: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    source: Optional[str] = None
    min_sentiment: Optional[Decimal] = Field(None, ge=-1, le=1)
    max_sentiment: Optional[Decimal] = Field(None, ge=-1, le=1)
    limit: Optional[int] = Field(None, gt=0, le=1000)

# Response Models
class APIResponse(BaseModel):
    success: bool = True
    message: str = "Success"
    data: Optional[dict] = None
    count: Optional[int] = None

class ErrorResponse(BaseModel):
    success: bool = False
    message: str
    error_code: Optional[str] = None
    details: Optional[dict] = None

# Bulk operation schemas
class BulkSymbolCreate(BaseModel):
    symbols: List[SymbolCreate]

class BulkOHLCVCreate(BaseModel):
    ohlcv_data: List[OHLCVCreateWithSymbol]

class BulkResponse(BaseModel):
    success: bool = True
    message: str = "Success"
    total_items: int
    successful_items: int
    failed_items: int
    errors: Optional[List[str]] = None

# ============================================================================
# SQLAlchemy ORM Models (required for integration with database layer and for
# backward-compatibility with services expecting ORM classes).
# These lightweight models define only the columns that are referenced by the
# tests and service layer, avoiding any heavy dependencies on an actual running
# database. They are sufficient for import-time validation.
# ============================================================================

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Numeric,
    Boolean,
    Text,
)
from sqlalchemy.orm import declarative_base

# Create a single declarative base for the entire application if one does not
# already exist.  Placing it here ensures models can be imported from the
# `app.models.market_data` module without requiring another file.
Base = declarative_base()

class Symbol(Base):
    """ORM representation of a financial symbol/instrument."""

    __tablename__ = "symbols"

    id = Column(Integer, primary_key=True, index=True)
    symbol = Column(String(20), nullable=False, index=True)
    dataset = Column(String(50), nullable=False, index=True)

    # Optional descriptive fields
    description = Column(Text, nullable=True)
    sector = Column(String(100), nullable=True)
    industry = Column(String(100), nullable=True)
    market_cap = Column(Integer, nullable=True)
    currency = Column(String(3), nullable=True, default="USD")
    exchange = Column(String(50), nullable=True)

    # Metadata / bookkeeping
    instrument_id = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class OHLCVData(Base):
    """ORM representation of aggregated OHLCV bar data."""

    __tablename__ = "ohlcv_data"

    id = Column(Integer, primary_key=True, index=True)
    symbol_id = Column(Integer, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    timeframe = Column(String(20), nullable=False, index=True)

    open = Column(Numeric, nullable=True)
    high = Column(Numeric, nullable=True)
    low = Column(Numeric, nullable=True)
    close = Column(Numeric, nullable=True)
    volume = Column(Integer, nullable=True)
    vwap = Column(Numeric, nullable=True)

    # FIX: field must be `trades_count` to align with Pydantic schemas & tests
    trades_count = Column(Integer, nullable=True)

    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class TradeData(Base):
    """ORM representation of individual trade prints."""

    __tablename__ = "trade_data"

    id = Column(Integer, primary_key=True, index=True)
    symbol_id = Column(Integer, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    price = Column(Numeric, nullable=False)
    size = Column(Integer, nullable=False)
    side = Column(String(10), nullable=True)
    trade_id = Column(String(50), nullable=True)

    created_at = Column(DateTime, nullable=True)


class NewsData(Base):
    """ORM representation of news articles/headlines."""

    __tablename__ = "news_data"

    id = Column(Integer, primary_key=True, index=True)
    symbol = Column(String(20), nullable=True, index=True)
    headline = Column(Text, nullable=False)
    content = Column(Text, nullable=True)
    source = Column(String(100), nullable=True)
    sentiment_score = Column(Numeric, nullable=True)
    published_at = Column(DateTime, nullable=False, index=True)
    url = Column(String(500), nullable=True)

    created_at = Column(DateTime, nullable=True)