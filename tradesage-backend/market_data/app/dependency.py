from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import redis
from typing import Generator
import os
from .utils.config import get_settings
from .utils.database import get_db
import logging

logger = logging.getLogger(__name__)

# Database dependency
def get_database() -> Generator[Session, None, None]:
    """Dependency to get database session"""
    db = next(get_db())
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection error"
        )
    finally:
        db.close()

# Redis dependency
def get_redis_client():
    """Dependency to get Redis client"""
    try:
        settings = get_settings()
        client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            decode_responses=True
        )
        client.ping()  # Test connection
        return client
    except Exception as e:
        logger.error(f"Redis connection error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cache service unavailable"
        )

# Authentication dependency (placeholder for future implementation)
def get_current_user():
    """Dependency for user authentication"""
    # TODO: Implement JWT token validation
    return {"user_id": "demo_user", "permissions": ["read", "write"]}

# Rate limiting dependency
def rate_limit_check():
    """Dependency for API rate limiting"""
    # TODO: Implement rate limiting logic
    return True

# Data validation dependency
def validate_symbol(symbol: str) -> str:
    """Validate and normalize symbol"""
    if not symbol or len(symbol) > 20:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid symbol format"
        )
    return symbol.upper().strip()

def validate_timeframe(timeframe: str) -> str:
    """Validate timeframe parameter"""
    valid_timeframes = ['ohlcv-1s', 'ohlcv-1m', 'ohlcv-5m', 'ohlcv-15m', 
                       'ohlcv-30m', 'ohlcv-1h', 'ohlcv-4h', 'ohlcv-1d', 
                       'ohlcv-1w', 'ohlcv-1M']
    
    if timeframe not in valid_timeframes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid timeframe. Must be one of: {', '.join(valid_timeframes)}"
        )
    return timeframe