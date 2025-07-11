from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta
import redis

from ...dependencies import get_database, get_redis_client, validate_symbol
from ...models.market_data import NewsData
from ...schemas.market_data import APIResponse, NewsQuery
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/news", tags=["News Data"])

@router.get("/", response_model=APIResponse)
async def get_news(
    symbol: Optional[str] = Query(None, description="Filter by symbol"),
    start_date: Optional[datetime] = Query(None, description="Start date"),
    end_date: Optional[datetime] = Query(None, description="End date"),
    source: Optional[str] = Query(None, description="Filter by source"),
    min_sentiment: Optional[float] = Query(None, ge=-1, le=1, description="Minimum sentiment score"),
    max_sentiment: Optional[float] = Query(None, ge=-1, le=1, description="Maximum sentiment score"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Maximum records"),
    db: Session = Depends(get_database)
):
    """Get news data with optional filters"""
    try:
        query = db.query(NewsData)
        
        # Apply filters
        if symbol:
            symbol = validate_symbol(symbol)
            query = query.filter(NewsData.symbol == symbol)
        
        if start_date:
            query = query.filter(NewsData.published_at >= start_date)
        
        if end_date:
            query = query.filter(NewsData.published_at <= end_date)
        
        if source:
            query = query.filter(NewsData.source == source)
        
        if min_sentiment is not None:
            query = query.filter(NewsData.sentiment_score >= min_sentiment)
        
        if max_sentiment is not None:
            query = query.filter(NewsData.sentiment_score <= max_sentiment)
        
        # Order by published date (newest first) and apply limit
        results = query.order_by(NewsData.published_at.desc()).limit(limit).all()
        
        # Convert to response format
        news_records = []
        for news in results:
            news_records.append({
                "id": news.id,
                "symbol": news.symbol,
                "headline": news.headline,
                "content": news.content,
                "source": news.source,
                "sentiment_score": float(news.sentiment_score) if news.sentiment_score else None,
                "published_at": news.published_at.isoformat(),
                "url": news.url
            })
        
        return APIResponse(
            data={
                "news": news_records,
                "filters": {
                    "symbol": symbol,
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None,
                    "source": source,
                    "sentiment_range": [min_sentiment, max_sentiment]
                }
            },
            count=len(news_records),
            message=f"Retrieved {len(news_records)} news articles"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting news data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve news data"
        )
