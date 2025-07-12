from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timedelta
import redis
import pandas as pd

from ...dependency import get_db, get_redis_client, validate_symbol, validate_timeframe
from ...services.data_storage import DataStorageService
from ...schemas.market_data import OHLCVQuery, OHLCVResponse, APIResponse, ErrorResponse
from ...utils.config import get_settings
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ohlcv", tags=["OHLCV Data"])

@router.get("/symbols", response_model=APIResponse)
async def get_available_symbols(
    dataset: Optional[str] = Query(None, description="Filter by dataset"),
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """Get list of available symbols"""
    try:
        storage_service = DataStorageService(db, redis_client)
        symbols = storage_service.get_symbols(dataset)
        
        return APIResponse(
            data={"symbols": symbols},
            count=len(symbols),
            message=f"Found {len(symbols)} symbols"
        )
        
    except Exception as e:
        logger.error(f"Error getting symbols: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve symbols"
        )

@router.get("/{symbol}", response_model=APIResponse)
async def get_ohlcv_data(
    symbol: str = Depends(validate_symbol),
    timeframe: str = Query("ohlcv-1d", description="Data timeframe"),
    start_date: datetime = Query(..., description="Start date (YYYY-MM-DD)"),
    end_date: datetime = Query(..., description="End date (YYYY-MM-DD)"),
    dataset: Optional[str] = Query(None, description="Specific dataset"),
    limit: Optional[int] = Query(None, ge=1, le=10000, description="Maximum records"),
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """Get OHLCV data for a specific symbol"""
    try:
        # Validate timeframe
        timeframe = validate_timeframe(timeframe)
        
        # Validate date range
        if start_date >= end_date:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Start date must be before end date"
            )
        
        if (end_date - start_date).days > 365:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Date range cannot exceed 365 days"
            )
        
        storage_service = DataStorageService(db, redis_client)
        df = storage_service.get_ohlcv_data(symbol, timeframe, start_date, end_date, dataset)
        
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No data found for {symbol} in {timeframe} timeframe"
            )
        
        # Apply limit if specified
        if limit:
            df = df.tail(limit)
        
        # Convert to records
        records = []
        for timestamp, row in df.iterrows():
            records.append({
                "timestamp": timestamp.isoformat(),
                "open": float(row['open']) if pd.notna(row['open']) else None,
                "high": float(row['high']) if pd.notna(row['high']) else None,
                "low": float(row['low']) if pd.notna(row['low']) else None,
                "close": float(row['close']) if pd.notna(row['close']) else None,
                "volume": int(row['volume']) if pd.notna(row['volume']) else None,
                "vwap": float(row['vwap']) if pd.notna(row['vwap']) else None,
                "trades_count": int(row['trades_count']) if pd.notna(row['trades_count']) else None
            })
        
        return APIResponse(
            data={
                "symbol": symbol,
                "timeframe": timeframe,
                "records": records
            },
            count=len(records),
            message=f"Retrieved {len(records)} records for {symbol}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting OHLCV data for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve OHLCV data"
        )

@router.get("/{symbol}/latest", response_model=APIResponse)
async def get_latest_ohlcv(
    symbol: str = Depends(validate_symbol),
    timeframe: str = Query("ohlcv-1d", description="Data timeframe"),
    days: int = Query(30, ge=1, le=365, description="Number of days back"),
    dataset: Optional[str] = Query(None, description="Specific dataset"),
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """Get latest OHLCV data for a symbol"""
    try:
        timeframe = validate_timeframe(timeframe)
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        storage_service = DataStorageService(db, redis_client)
        df = storage_service.get_ohlcv_data(symbol, timeframe, start_date, end_date, dataset)
        
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No recent data found for {symbol}"
            )
        
        # Get the latest record
        latest_record = df.iloc[-1]
        latest_timestamp = df.index[-1]
        
        latest_data = {
            "timestamp": latest_timestamp.isoformat(),
            "open": float(latest_record['open']) if pd.notna(latest_record['open']) else None,
            "high": float(latest_record['high']) if pd.notna(latest_record['high']) else None,
            "low": float(latest_record['low']) if pd.notna(latest_record['low']) else None,
            "close": float(latest_record['close']) if pd.notna(latest_record['close']) else None,
            "volume": int(latest_record['volume']) if pd.notna(latest_record['volume']) else None,
            "vwap": float(latest_record['vwap']) if pd.notna(latest_record['vwap']) else None
        }
        
        # Calculate some basic statistics
        if len(df) > 1:
            price_change = latest_record['close'] - df.iloc[-2]['close']
            price_change_pct = (price_change / df.iloc[-2]['close']) * 100 if df.iloc[-2]['close'] else 0
            
            latest_data.update({
                "price_change": float(price_change) if pd.notna(price_change) else None,
                "price_change_pct": float(price_change_pct) if pd.notna(price_change_pct) else None,
                "period_high": float(df['high'].max()),
                "period_low": float(df['low'].min()),
                "avg_volume": int(df['volume'].mean()) if not df['volume'].isna().all() else None
            })
        
        return APIResponse(
            data={
                "symbol": symbol,
                "timeframe": timeframe,
                "latest": latest_data,
                "total_records": len(df)
            },
            message=f"Latest data for {symbol}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting latest data for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve latest data"
        )

@router.get("/{symbol}/summary", response_model=APIResponse)
async def get_ohlcv_summary(
    symbol: str = Depends(validate_symbol),
    timeframe: str = Query("ohlcv-1d", description="Data timeframe"),
    days: int = Query(30, ge=1, le=365, description="Number of days back"),
    dataset: Optional[str] = Query(None, description="Specific dataset"),
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """Get statistical summary of OHLCV data"""
    try:
        timeframe = validate_timeframe(timeframe)
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        storage_service = DataStorageService(db, redis_client)
        df = storage_service.get_ohlcv_data(symbol, timeframe, start_date, end_date, dataset)
        
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No data found for {symbol}"
            )
        
        # Calculate summary statistics
        summary = {
            "symbol": symbol,
            "timeframe": timeframe,
            "period_start": df.index[0].isoformat(),
            "period_end": df.index[-1].isoformat(),
            "total_records": len(df),
            "price_statistics": {
                "highest": float(df['high'].max()) if not df['high'].isna().all() else None,
                "lowest": float(df['low'].min()) if not df['low'].isna().all() else None,
                "avg_close": float(df['close'].mean()) if not df['close'].isna().all() else None,
                "current_price": float(df['close'].iloc[-1]) if not df['close'].isna().all() else None,
                "price_volatility": float(df['close'].std()) if not df['close'].isna().all() else None
            },
            "volume_statistics": {
                "total_volume": int(df['volume'].sum()) if not df['volume'].isna().all() else None,
                "avg_volume": int(df['volume'].mean()) if not df['volume'].isna().all() else None,
                "max_volume": int(df['volume'].max()) if not df['volume'].isna().all() else None,
                "min_volume": int(df['volume'].min()) if not df['volume'].isna().all() else None
            }
        }
        
        # Calculate returns if we have enough data
        if len(df) > 1:
            returns = df['close'].pct_change().dropna()
            summary["returns_statistics"] = {
                "total_return": float((df['close'].iloc[-1] / df['close'].iloc[0] - 1) * 100),
                "avg_daily_return": float(returns.mean() * 100),
                "return_volatility": float(returns.std() * 100),
                "positive_days": int((returns > 0).sum()),
                "negative_days": int((returns < 0).sum())
            }
        
        return APIResponse(
            data=summary,
            message=f"Summary statistics for {symbol}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting summary for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve summary data"
        )
