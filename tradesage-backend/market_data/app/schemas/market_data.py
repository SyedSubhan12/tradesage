from pydantic import BaseModel, Field, field_validator, ConfigDict
from datetime import datetime
from typing import Optional, List, Dict, Any
from decimal import Decimal

class SymbolBase(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=20)
    dataset: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    sector: Optional[str] = None
    industry: Optional[str] = None  # Added missing field
    market_cap: Optional[int] = None
    currency: Optional[str] = Field(default="USD", max_length=3)  # Added missing field
    exchange: Optional[str] = None  # Added missing field

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