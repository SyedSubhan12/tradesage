from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta
import redis

from ...dependencies import get_database, get_redis_client, validate_symbol
from ...services.data_storage import DataStorageService
from ...schemas.market_data import APIResponse
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/trades", tags=["Trade Data"])

@router.get("/{symbol}", response_model=APIResponse)
async def get_trade_data(
    symbol: str = Depends(validate_symbol),
    start_date: datetime = Query(..., description="Start date"),
    end_date: datetime = Query(..., description="End date"),
    dataset: Optional[str] = Query(None, description="Specific dataset"),
    limit: Optional[int] = Query(1000, ge=1, le=50000, description="Maximum records"),
    db: Session = Depends(get_database),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """Get trade data for a specific symbol"""
    try:
        if start_date >= end_date:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Start date must be before end date"
            )
        
        storage_service = DataStorageService(db, redis_client)
        df = storage_service.get_trade_data(symbol, start_date, end_date, dataset, limit)
        
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No trade data found for {symbol}"
            )
        
        # Convert to records
        records = []
        for timestamp, row in df.iterrows():
            records.append({
                "timestamp": timestamp.isoformat(),
                "price": float(row['price']),
                "size": int(row['size']),
                "side": row['side'],
                "trade_id": row['trade_id']
            })
        
        return APIResponse(
            data={
                "symbol": symbol,
                "trades": records
            },
            count=len(records),
            message=f"Retrieved {len(records)} trades for {symbol}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting trade data for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve trade data"
        )