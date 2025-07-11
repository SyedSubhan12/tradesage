from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional, List
from decimal import Decimal

class SymbolBase(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=20)
    dataset: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    sector: Optional[str] = None
    market_cap: Optional[int] = None

class SymbolCreate(SymbolBase):
    pass

class SymbolResponse(SymbolBase):
    id: int
    instrument_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class OHLCVBase(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=20)
    dataset: str = Field(..., min_length=1, max_length=50)
    timeframe: str = Field(..., regex=r'^ohlcv-(1s|1m|5m|15m|30m|1h|4h|1d|1w|1M)$')
    timestamp: datetime
    open: Optional[Decimal] = Field(None, ge=0)
    high: Optional[Decimal] = Field(None, ge=0)
    low: Optional[Decimal] = Field(None, ge=0)
    close: Optional[Decimal] = Field(None, ge=0)
    volume: Optional[int] = Field(None, ge=0)
    vwap: Optional[Decimal] = Field(None, ge=0)
    trades_count: Optional[int] = Field(None, ge=0)

class OHLCVCreate(OHLCVBase):
    @validator('high', 'low', 'close')
    def validate_prices(cls, v, values):
        if 'open' in values and values['open'] and v:
            # Basic validation: prices should be reasonable relative to open
            if v > values['open'] * 10 or v < values['open'] * 0.1:
                raise ValueError('Price seems unreasonable compared to open price')
        return v

class OHLCVResponse(OHLCVBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class TradeBase(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=20)
    dataset: str = Field(..., min_length=1, max_length=50)
    timestamp: datetime
    price: Decimal = Field(..., gt=0)
    size: int = Field(..., gt=0)
    side: Optional[str] = Field(None, regex=r'^(buy|sell|unknown)$')
    trade_id: Optional[str] = None

class TradeCreate(TradeBase):
    pass

class TradeResponse(TradeBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

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
    
    class Config:
        from_attributes = True

# Query Schemas
class OHLCVQuery(BaseModel):
    symbol: str
    timeframe: str = Field(default="ohlcv-1d", regex=r'^ohlcv-(1s|1m|5m|15m|30m|1h|4h|1d|1w|1M)$')
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