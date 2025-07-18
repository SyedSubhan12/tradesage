from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
import redis
import pandas as pd
import asyncio
import time
import logging
from contextlib import asynccontextmanager

from ...dependency import get_database, get_redis_client, validate_symbol, validate_timeframe
from ...services.data_storage import ProductionDataStorageService
from ...services.redis_optimizer import EnhancedTradingRedisService, get_redis_service
from ...routers.v1.websocket_handler import get_websocket_manager
from ...schemas.market_data import OHLCVQuery, OHLCVResponse, APIResponse, ErrorResponse
from ...utils.config import get_settings
from ...utils.database import get_db_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ohlcv", tags=["OHLCV Data"])
# Performance metrics
from prometheus_client import Counter, Histogram
OHLCV_REQUESTS = Counter('ohlcv_requests_total', 'Total OHLCV requests', ['endpoint', 'symbol', 'timeframe'])
OHLCV_DURATION = Histogram('ohlcv_request_duration_seconds', 'OHLCV request duration', ['endpoint'])
OHLCV_CACHE_HITS = Counter('ohlcv_cache_hits_total', 'OHLCV cache hits', ['cache_type'])

class TradingViewDataFormatter:
    """TradingView-compatible data formatting"""
    
    @staticmethod
    def format_ohlcv_for_tradingview(df: pd.DataFrame) -> Dict[str, Any]:
        """Convert OHLCV DataFrame to TradingView format"""
        try:
            if df.empty:
                return {'s': 'no_data'}
            
            # Ensure we have the required columns
            required_columns = ['open', 'high', 'low', 'close', 'volume']
            for col in required_columns:
                if col not in df.columns:
                    df[col] = 0
            
            return {
                's': 'ok',
                't': [int(ts.timestamp()) for ts in df.index],
                'o': df['open'].fillna(0).astype(float).tolist(),
                'h': df['high'].fillna(0).astype(float).tolist(),
                'l': df['low'].fillna(0).astype(float).tolist(),
                'c': df['close'].fillna(0).astype(float).tolist(),
                'v': df['volume'].fillna(0).astype(int).tolist()
            }
        except Exception as e:
            logger.error(f"Error formatting TradingView data: {e}")
            return {'s': 'error', 'errmsg': str(e)}
    
    @staticmethod
    def format_realtime_bar(latest_data: Dict) -> Dict[str, Any]:
        """Format real-time bar for TradingView"""
        try:
            return {
                'time': int(datetime.fromisoformat(latest_data['timestamp'].replace('Z', '+00:00')).timestamp()),
                'open': float(latest_data.get('open', 0)),
                'high': float(latest_data.get('high', 0)),
                'low': float(latest_data.get('low', 0)),
                'close': float(latest_data.get('close', 0)),
                'volume': int(latest_data.get('volume', 0))
            }
        except Exception as e:
            logger.error(f"Error formatting realtime bar: {e}")
            return {}
# Enhanced dependencies
# @asynccontextmanager
async def get_enhanced_storage_service():
    """Get enhanced storage service with comprehensive error handling and fallback"""
    db_session = None
    redis_client = None
    
    try:
        logger.debug("Starting storage service initialization...")
        
        # Try to get database session using dependency injection
        try:
            db_session = next(get_database())
            logger.debug("✅ Database session obtained via dependency injection")
        except Exception as e:
            logger.error(f"❌ Failed to get database session via dependency: {e}")
            # Fallback: try direct database manager
            try:
                db_manager = get_db_manager()
                db_session = db_manager.get_sync_session()
                logger.debug("✅ Database session obtained via db_manager fallback")
            except Exception as e2:
                logger.error(f"❌ Fallback database session failed: {e2}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Database connection failed: {str(e2)}"
                )
        
        # Try to get Redis client
        try:
            redis_client = get_redis_client()
            logger.debug("✅ Redis client obtained")
        except Exception as e:
            logger.error(f"❌ Failed to get Redis client: {e}")
            # Continue without Redis for basic functionality
            redis_client = None
            logger.warning("⚠️ Continuing without Redis - caching disabled")
        
        # Get configuration
        try:
            config = get_settings()
            logger.debug("✅ Configuration loaded")
        except Exception as e:
            logger.error(f"❌ Failed to load configuration: {e}")
            config = None
        
        # Create storage service with fallbacks
        try:
            # FIXED: Use basic DataStorageService if enhanced version fails
            try:
                from ...services.data_storage import ProductionDataStorageService
                
                storage_service = ProductionDataStorageService(
                    db=db_session,
                    redis_client=redis_client,
                    enhanced_redis_service=None,  # Set to None to avoid issues
                    config=config
                )
                logger.debug("✅ Enhanced storage service created")
                
            except Exception as e:
                logger.warning(f"⚠️ Enhanced storage service failed, using basic fallback: {e}")
                
                # Fallback to basic DataStorageService
                from ...services.data_storage import DataStorageService
                
                storage_service = DataStorageService(
                    db=db_session,
                    redis_client=redis_client or redis.Redis()  # Dummy Redis if none available
                )
                logger.debug("✅ Basic storage service created as fallback")
            
            return storage_service
            
        except Exception as e:
            logger.error(f"❌ Failed to create any storage service: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Storage service creation failed: {str(e)}"
            )
    
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error in storage service initialization: {e}")
        logger.exception("Full traceback:")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage service initialization failed: {str(e)}"
        )
    
    # we don't close session here; FastAPI dependency system will handle

@asynccontextmanager
async def get_enhanced_storage_service_async():
    """Async version with proper resource management"""
    db_session = None
    storage_service = None
    
    try:
        logger.debug("Starting async storage service initialization...")
        
        # Get database session
        db_session = next(get_database())
        
        # Get Redis client (optional)
        try:
            redis_client = get_redis_client()
        except Exception as e:
            logger.warning(f"Redis unavailable, continuing without caching: {e}")
            redis_client = None
        
        # Get configuration
        config = get_settings()
        
        # Create storage service
        try:
            from ...services.data_storage import ProductionDataStorageService
            
            storage_service = ProductionDataStorageService(
                db=db_session,
                redis_client=redis_client,
                enhanced_redis_service=None,
                config=config
            )
        except Exception as e:
            logger.warning(f"Using basic storage service: {e}")
            from ...services.data_storage import DataStorageService
            
            storage_service = DataStorageService(
                db=db_session,
                redis_client=redis_client or redis.Redis()
            )
        
        yield storage_service
        
    except Exception as e:
        logger.error(f"Async storage service error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage service initialization failed: {str(e)}"
        )
    finally:
        # Cleanup resources
        if db_session:
            try:
                db_session.close()
                logger.debug("✅ Database session closed")
            except Exception as e:
                logger.warning(f"Error closing database session: {e}")

# ==================== Symbol Discovery Endpoints ====================

@router.get("/symbols", response_model=APIResponse)
async def get_available_symbols(
    dataset: Optional[str] = Query(None, description="Filter by dataset"),
    sector: Optional[str] = Query(None, description="Filter by sector"),
    active_only: bool = Query(True, description="Only active symbols"),
    search: Optional[str] = Query(None, description="Search symbols by name"),
    limit: Optional[int] = Query(None, ge=1, le=1000, description="Limit results"),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Get comprehensive list of available symbols with advanced filtering"""
    
    start_time = time.time()
    
    try:
        # Get symbols with optimized caching
        symbols_data = await storage_service.get_symbols_optimized(
            dataset=dataset,
            sector=sector,
            active_only=active_only
        )
        
        logger.info(f"Retrieved {len(symbols_data)} symbols for dataset {dataset}, sector {sector}, active_only {active_only}")
        
        # Apply search filter if provided
        if search:
            search_term = search.upper()
            logger.info(f"Applying search filter for term: {search_term}")
            symbols_data = [
                s for s in symbols_data 
                if (search_term in s['symbol'].upper()) or 
                   (s.get('description') and search_term in s['description'].upper()) or
                   (s.get('name') and search_term in s['name'].upper())
            ]
            logger.info(f"After search filter, found {len(symbols_data)} matching symbols")
        
        # Apply limit
        if limit:
            symbols_data = symbols_data[:limit]
            logger.info(f"Applied limit of {limit}, returning {len(symbols_data)} symbols")
        
        # Update metrics
        OHLCV_REQUESTS.labels(endpoint='symbols', symbol='all', timeframe='none').inc()
        OHLCV_DURATION.labels(endpoint='symbols').observe(time.time() - start_time)
        
        return APIResponse(
            data={
                "symbols": symbols_data,
                "filters": {
                    "dataset": dataset,
                    "sector": sector,
                    "active_only": active_only,
                    "search": search
                },
                "total_count": len(symbols_data)
            },
            count=len(symbols_data),
            message=f"Found {len(symbols_data)} symbols"
        )
        
    except Exception as e:
        logger.error(f"Error getting symbols: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve symbols"
        )

@router.get("/symbols/{symbol}/info")
async def get_symbol_info(
    symbol: str = Depends(validate_symbol),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Get detailed information about a specific symbol"""
    
    try:
        # Get symbol details
        symbols_data = await storage_service.get_symbols_optimized()
        symbol_info = next((s for s in symbols_data if s['symbol'] == symbol), None)
        
        if not symbol_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Symbol {symbol} not found"
            )
        
        # Get recent trading statistics
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        
        df = await storage_service.get_ohlcv_data_optimized(
            symbol=symbol,
            timeframe='ohlcv-1d',
            start_date=start_date,
            end_date=end_date,
            limit=30
        )
        
        # Calculate statistics
        stats = {}
        if not df.empty:
            stats = {
                'avg_volume': int(df['volume'].mean()) if 'volume' in df.columns else None,
                'avg_price': float(df['close'].mean()) if 'close' in df.columns else None,
                'price_range': {
                    'high': float(df['high'].max()) if 'high' in df.columns else None,
                    'low': float(df['low'].min()) if 'low' in df.columns else None
                },
                'volatility': float(df['close'].std()) if 'close' in df.columns else None,
                'trading_days': len(df)
            }
        
        return APIResponse(
            data={
                "symbol_info": symbol_info,
                "trading_stats": stats,
                "period": "30_days"
            },
            message=f"Symbol information for {symbol}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting symbol info for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve symbol information"
        )

# ==================== Enhanced OHLCV Data Endpoints ====================

@router.get("/{symbol}", response_model=APIResponse)
async def get_ohlcv_data(
    symbol: str = Depends(validate_symbol),
    timeframe: str = Query("ohlcv-1d", description="Data timeframe"),
    start_date: datetime = Query(..., description="Start date (ISO format)"),
    end_date: datetime = Query(..., description="End date (ISO format)"),
    dataset: Optional[str] = Query(None, description="Specific dataset"),
    limit: Optional[int] = Query(None, ge=1, le=10000, description="Maximum records"),
    format: str = Query("standard", description="Response format (standard|tradingview)"),
    compression: bool = Query(True, description="Use data compression"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    storage_service = Depends(get_enhanced_storage_service)
):
    """Enhanced OHLCV data retrieval with multiple format support"""
    
    start_time = time.time()
    
    try:
        logger.debug(f"Getting OHLCV data for {symbol}, timeframe: {timeframe}")
        
        # Validate timeframe
        timeframe = validate_timeframe(timeframe)
        
        # Validate date range
        if start_date >= end_date:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Start date must be before end date"
            )
        # Get data using storage service with fallback
        try:
            # Try enhanced method first
            if hasattr(storage_service, 'get_ohlcv_data_optimized'):
                df = await storage_service.get_ohlcv_data_optimized(
                    symbol=symbol,
                    timeframe=timeframe,
                    start_date=start_date,
                    end_date=end_date,
                    dataset=dataset,
                    limit=limit,
                    use_compression=compression
                )
            else:
                raise AttributeError("Enhanced method not available")
                
        except Exception as e:
            logger.warning(f"Enhanced OHLCV method failed, using basic fallback: {e}")
            
            # Fallback to basic method
            df = storage_service.get_ohlcv_data(
                symbol=symbol,
                timeframe=timeframe,
                start_date=start_date,
                end_date=end_date,
                dataset=dataset
            )
            
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No data found for {symbol} in {timeframe} timeframe"
            )
        
        # Format response based on requested format
        if format.lower() == "tradingview":
            # TradingView-compatible format
            formatted_data = TradingViewDataFormatter.format_ohlcv_for_tradingview(df)
            
            # Update metrics
            OHLCV_REQUESTS.labels(endpoint='data', symbol=symbol, timeframe=timeframe).inc()
            OHLCV_DURATION.labels(endpoint='data').observe(time.time() - start_time)
            
            return JSONResponse(content=formatted_data)
        
        else:
            # Standard format
            records = []
            for timestamp, row in df.iterrows():
                record = {
                    "timestamp": timestamp.isoformat(),
                    "open": float(row['open']) if pd.notna(row['open']) else None,
                    "high": float(row['high']) if pd.notna(row['high']) else None,
                    "low": float(row['low']) if pd.notna(row['low']) else None,
                    "close": float(row['close']) if pd.notna(row['close']) else None,
                    "volume": int(row['volume']) if pd.notna(row['volume']) else None,
                    "vwap": float(row['vwap']) if pd.notna(row['vwap']) and 'vwap' in row else None,
                    "trades_count": int(row['trades_count']) if pd.notna(row.get('trades_count')) else None
                }
                records.append(record)
            
            # Update metrics
            OHLCV_REQUESTS.labels(endpoint='data', symbol=symbol, timeframe=timeframe).inc()
            OHLCV_DURATION.labels(endpoint='data').observe(time.time() - start_time)
            
            return APIResponse(
                data={
                    "symbol": symbol,
                    "timeframe": timeframe,
                    "records": records,
                    "metadata": {
                        "total_records": len(records),
                        "date_range": {
                            "start": start_date.isoformat(),
                            "end": end_date.isoformat()
                        },
                        "dataset": dataset,
                        "compression_used": compression
                    }
                },
                count=len(records),
                message=f"Retrieved {len(records)} records for {symbol}"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting OHLCV data for {symbol}: {e}")
        logger.exception("Full traceback:")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve OHLCV data: {str(e)}"
        )
@router.get("/test")
async def test_endpoint():
    """Simple test endpoint to verify router is working"""
    try:
        storage_service = get_enhanced_storage_service()
        
        return APIResponse(
            data={
                "status": "working",
                "storage_service_type": type(storage_service).__name__,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            message="OHLCV router test successful"
        )
    except Exception as e:
        logger.error(f"Test endpoint error: {e}")
        return APIResponse(
            success=False,
            data={"error": str(e)},
            message="Test endpoint failed"
        )

# ==================== Real-time and Latest Data Endpoints ====================

@router.get("/{symbol}/latest", response_model=APIResponse)
async def get_latest_ohlcv(
    symbol: str = Depends(validate_symbol),
    timeframe: str = Query("ohlcv-1d", description="Data timeframe"),
    days: int = Query(30, ge=1, le=365, description="Number of days back"),
    dataset: Optional[str] = Query(None, description="Specific dataset"),
    include_realtime: bool = Query(True, description="Include real-time price data"),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Get latest OHLCV data with real-time price integration"""
    
    start_time = time.time()
    
    try:
        timeframe = validate_timeframe(timeframe)
        
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        # Get OHLCV data
        df = await storage_service.get_ohlcv_data_optimized(
            symbol=symbol,
            timeframe=timeframe,
            start_date=start_date,
            end_date=end_date,
            dataset=dataset
        )
        
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
        
        # Add real-time data if available and requested
        realtime_data = {}
        if include_realtime:
            try:
                redis_service = await get_redis_service()
                realtime_price = await redis_service.get_real_time_price(symbol)
                if realtime_price:
                    realtime_data = {
                        "realtime_price": realtime_price.get('price'),
                        "bid": realtime_price.get('bid'),
                        "ask": realtime_price.get('ask'),
                        "spread": realtime_price.get('spread'),
                        "realtime_timestamp": realtime_price.get('timestamp'),
                        "change": realtime_price.get('change'),
                        "change_pct": realtime_price.get('change_pct')
                    }
            except Exception as e:
                logger.warning(f"Could not get real-time data for {symbol}: {e}")
        
        # Calculate period statistics
        period_stats = {}
        if len(df) > 1:
            price_change = latest_record['close'] - df.iloc[-2]['close']
            price_change_pct = (price_change / df.iloc[-2]['close']) * 100 if df.iloc[-2]['close'] else 0
            
            period_stats = {
                "price_change": float(price_change) if pd.notna(price_change) else None,
                "price_change_pct": float(price_change_pct) if pd.notna(price_change_pct) else None,
                "period_high": float(df['high'].max()),
                "period_low": float(df['low'].min()),
                "avg_volume": int(df['volume'].mean()) if not df['volume'].isna().all() else None,
                "trading_days": len(df)
            }
        
        # Update metrics
        OHLCV_REQUESTS.labels(endpoint='latest', symbol=symbol, timeframe=timeframe).inc()
        OHLCV_DURATION.labels(endpoint='latest').observe(time.time() - start_time)
        
        return APIResponse(
            data={
                "symbol": symbol,
                "timeframe": timeframe,
                "latest": latest_data,
                "realtime": realtime_data,
                "period_stats": period_stats,
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
    finally:
        if hasattr(storage_service, 'close'):
            storage_service.close()

@router.get("/{symbol}/realtime")
async def get_realtime_price(
    symbol: str = Depends(validate_symbol),
    format: str = Query("standard", description="Response format (standard|tradingview)")
):
    """Get real-time price data for a symbol"""
    
    try:
        redis_service = await get_redis_service()
        price_data = await redis_service.get_real_time_price(symbol)
        
        if not price_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No real-time data available for {symbol}"
            )
        
        if format.lower() == "tradingview":
            # Format as TradingView real-time bar
            formatted_data = TradingViewDataFormatter.format_realtime_bar(price_data)
            return JSONResponse(content=formatted_data)
        else:
            return APIResponse(
                data=price_data,
                message=f"Real-time data for {symbol}"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting realtime data for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve real-time data"
        )

# ==================== TradingView Specific Endpoints ====================

@router.get("/tradingview/{symbol}/history")
async def tradingview_history(
    symbol: str = Depends(validate_symbol),
    resolution: str = Query(..., description="TradingView resolution"),
    from_timestamp: int = Query(..., description="Start timestamp"),
    to_timestamp: int = Query(..., description="End timestamp"),
    countback: Optional[int] = Query(None, description="Number of bars"),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """TradingView-compatible historical data endpoint"""
    
    start_time = time.time()
    
    try:
        # Convert TradingView resolution to our timeframe format
        resolution_map = {
            "1D": "ohlcv-1d",        
        }
        
        timeframe = resolution_map.get(resolution)
        if not timeframe:
            return JSONResponse(
                content={"s": "error", "errmsg": f"Unsupported resolution: {resolution}"}
            )
        
        # Convert timestamps to datetime
        start_date = datetime.fromtimestamp(from_timestamp, tz=timezone.utc)
        end_date = datetime.fromtimestamp(to_timestamp, tz=timezone.utc)
        
        # Get data from optimized storage
        df = await storage_service.get_ohlcv_data_optimized(
            symbol=symbol,
            timeframe=timeframe,
            start_date=start_date,
            end_date=end_date,
            limit=countback
        )
        
        # Format for TradingView
        formatted_data = TradingViewDataFormatter.format_ohlcv_for_tradingview(df)
        
        # Update metrics
        OHLCV_REQUESTS.labels(endpoint='tradingview_history', symbol=symbol, timeframe=timeframe).inc()
        OHLCV_DURATION.labels(endpoint='tradingview_history').observe(time.time() - start_time)
        
        return JSONResponse(content=formatted_data)
        
    except Exception as e:
        logger.error(f"TradingView history error for {symbol}: {e}")
        return JSONResponse(
            content={"s": "error", "errmsg": str(e)}
        )
    finally:
        if hasattr(storage_service, 'close'):
            storage_service.close()

# ==================== Analytics and Summary Endpoints ====================

@router.get("/{symbol}/summary", response_model=APIResponse)
async def get_ohlcv_summary(
    symbol: str = Depends(validate_symbol),
    timeframe: str = Query("ohlcv-1d", description="Data timeframe"),
    days: int = Query(30, ge=1, le=365, description="Number of days back"),
    dataset: Optional[str] = Query(None, description="Specific dataset"),
    include_technical_indicators: bool = Query(False, description="Include technical indicators"),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Enhanced statistical summary with optional technical indicators"""
    
    start_time = time.time()
    
    try:
        timeframe = validate_timeframe(timeframe)
        
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        df = await storage_service.get_ohlcv_data_optimized(
            symbol=symbol,
            timeframe=timeframe,
            start_date=start_date,
            end_date=end_date,
            dataset=dataset
        )
        
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No data found for {symbol}"
            )
        
        # Calculate comprehensive summary statistics
        summary = {
            "symbol": symbol,
            "timeframe": timeframe,
            "period": {
                "start": df.index[0].isoformat(),
                "end": df.index[-1].isoformat(),
                "days": len(df),
                "total_records": len(df)
            },
            "price_statistics": {},
            "volume_statistics": {},
            "performance_metrics": {}
        }
        
        # Price statistics
        if not df['close'].isna().all():
            summary["price_statistics"] = {
                "current_price": float(df['close'].iloc[-1]),
                "highest": float(df['high'].max()),
                "lowest": float(df['low'].min()),
                "average_price": float(df['close'].mean()),
                "median_price": float(df['close'].median()),
                "price_volatility": float(df['close'].std()),
                "price_range": float(df['high'].max() - df['low'].min())
            }
        
        # Volume statistics
        if not df['volume'].isna().all():
            summary["volume_statistics"] = {
                "total_volume": int(df['volume'].sum()),
                "average_volume": int(df['volume'].mean()),
                "median_volume": int(df['volume'].median()),
                "max_volume": int(df['volume'].max()),
                "min_volume": int(df['volume'].min()),
                "volume_volatility": float(df['volume'].std())
            }
        
        # Performance metrics
        if len(df) > 1 and not df['close'].isna().all():
            returns = df['close'].pct_change().dropna()
            
            summary["performance_metrics"] = {
                "total_return_pct": float((df['close'].iloc[-1] / df['close'].iloc[0] - 1) * 100),
                "average_daily_return_pct": float(returns.mean() * 100),
                "return_volatility_pct": float(returns.std() * 100),
                "positive_days": int((returns > 0).sum()),
                "negative_days": int((returns < 0).sum()),
                "max_daily_gain_pct": float(returns.max() * 100) if len(returns) > 0 else 0,
                "max_daily_loss_pct": float(returns.min() * 100) if len(returns) > 0 else 0
            }
        
        # Technical indicators (if requested)
        if include_technical_indicators and len(df) >= 20:
            try:
                technical_indicators = await calculate_technical_indicators(df)
                summary["technical_indicators"] = technical_indicators
            except Exception as e:
                logger.warning(f"Technical indicators calculation failed: {e}")
                summary["technical_indicators"] = {"error": "Calculation failed"}
        
        # Update metrics
        OHLCV_REQUESTS.labels(endpoint='summary', symbol=symbol, timeframe=timeframe).inc()
        OHLCV_DURATION.labels(endpoint='summary').observe(time.time() - start_time)
        
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
    finally:
        if hasattr(storage_service, 'close'):
            storage_service.close()

@router.get("/market/summary")
async def get_market_summary(
    symbols: str = Query(..., description="Comma-separated list of symbols"),
    timeframe: str = Query("ohlcv-1d", description="Data timeframe"),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Get market summary for multiple symbols"""
    
    try:
        symbol_list = [s.strip().upper() for s in symbols.split(',')][:50]  # Limit to 50 symbols
        
        if not symbol_list:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one symbol must be provided"
            )
        
        # Get market summary using enhanced storage service
        market_summary = await storage_service.get_market_summary(symbol_list, timeframe)
        
        return APIResponse(
            data=market_summary,
            count=len(symbol_list),
            message=f"Market summary for {len(symbol_list)} symbols"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting market summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve market summary"
        )
    finally:
        if hasattr(storage_service, 'close'):
            storage_service.close()

# ==================== Background Tasks ====================

async def warm_related_timeframes(symbol: str, requested_timeframe: str, 
                                start_date: datetime, end_date: datetime):
    """Background task to warm cache for related timeframes"""
    try:
        # Define related timeframes to warm
        timeframe_groups = {
            'ohlcv-1d': ['ohlcv-4h', 'ohlcv-1w']
        }
        
        related_timeframes = timeframe_groups.get(requested_timeframe, [])
        
        if related_timeframes:
            redis_service = await get_redis_service()
            await redis_service.warm_cache_for_symbols([symbol], related_timeframes)
            
    except Exception as e:
        logger.warning(f"Cache warming failed for {symbol}: {e}")

async def calculate_technical_indicators(df: pd.DataFrame) -> Dict[str, Any]:
    """Calculate basic technical indicators"""
    try:
        indicators = {}
        
        # Simple Moving Averages
        if len(df) >= 20:
            indicators['sma_20'] = float(df['close'].rolling(20).mean().iloc[-1])
        if len(df) >= 50:
            indicators['sma_50'] = float(df['close'].rolling(50).mean().iloc[-1])
        
        # Exponential Moving Averages
        if len(df) >= 12:
            indicators['ema_12'] = float(df['close'].ewm(span=12).mean().iloc[-1])
        if len(df) >= 26:
            indicators['ema_26'] = float(df['close'].ewm(span=26).mean().iloc[-1])
        
        # RSI (simple approximation)
        if len(df) >= 14:
            delta = df['close'].diff()
            gain = (delta.where(delta > 0, 0)).rolling(window=14).mean()
            loss = (-delta.where(delta < 0, 0)).rolling(window=14).mean()
            rs = gain / loss
            rsi = 100 - (100 / (1 + rs))
            indicators['rsi_14'] = float(rsi.iloc[-1])
        
        # Bollinger Bands
        if len(df) >= 20:
            sma_20 = df['close'].rolling(20).mean()
            std_20 = df['close'].rolling(20).std()
            indicators['bollinger_upper'] = float((sma_20 + (std_20 * 2)).iloc[-1])
            indicators['bollinger_lower'] = float((sma_20 - (std_20 * 2)).iloc[-1])
            indicators['bollinger_middle'] = float(sma_20.iloc[-1])
        
        return indicators
        
    except Exception as e:
        logger.error(f"Technical indicators calculation error: {e}")
        return {"error": str(e)}

# ==================== Performance Monitoring Endpoint ====================

@router.get("/performance/stats")
async def get_performance_stats(
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Get OHLCV endpoint performance statistics"""
    
    try:
        # Get storage service performance stats
        storage_stats = storage_service.get_performance_stats()
        
        # Get Redis service stats
        redis_service = await get_redis_service()
        redis_stats = redis_service.get_comprehensive_stats()
        
        return APIResponse(
            data={
                "storage_performance": storage_stats,
                "cache_performance": redis_stats,
                "endpoint_metrics": {
                    "total_requests": "See Prometheus metrics",
                    "average_response_time": "See Prometheus metrics"
                }
            },
            message="Performance statistics retrieved"
        )
        
    except Exception as e:
        logger.error(f"Error getting performance stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve performance statistics"
        )
    finally:
        if hasattr(storage_service, 'close'):
            storage_service.close()