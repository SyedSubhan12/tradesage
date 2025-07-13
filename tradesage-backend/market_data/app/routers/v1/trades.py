from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any, AsyncGenerator
from datetime import datetime, timedelta, timezone
import pandas as pd
import asyncio
import time
import logging
import json
import io

from ...dependency import get_db, get_redis_client, validate_symbol
from ...services.data_storage import ProductionDataStorageService
from ...services.redis_optimizer import EnhancedTradingRedisService, get_redis_service
from ...routers.v1.websocket_handler import get_websocket_manager
from ...schemas.market_data import APIResponse
from ...utils.config import get_settings
from ...utils.database import get_db_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/trades", tags=["Trade Data"])

# Performance metrics
from prometheus_client import Counter, Histogram
TRADES_REQUESTS = Counter('trades_requests_total', 'Total trade requests', ['endpoint', 'symbol'])
TRADES_DURATION = Histogram('trades_request_duration_seconds', 'Trade request duration', ['endpoint'])
TRADES_VOLUME_PROCESSED = Counter('trades_volume_processed_total', 'Total trade volume processed')

class TradeDataAnalyzer:
    """Advanced trade data analysis and aggregation"""
    
    @staticmethod
    def calculate_vwap(trades_df: pd.DataFrame) -> float:
        """Calculate Volume Weighted Average Price"""
        try:
            if trades_df.empty or 'price' not in trades_df.columns or 'size' not in trades_df.columns:
                return 0.0
            
            total_volume = trades_df['size'].sum()
            if total_volume == 0:
                return 0.0
            
            weighted_prices = (trades_df['price'] * trades_df['size']).sum()
            return float(weighted_prices / total_volume)
            
        except Exception as e:
            logger.error(f"VWAP calculation error: {e}")
            return 0.0
    
    @staticmethod
    def calculate_trade_distribution(trades_df: pd.DataFrame) -> Dict[str, Any]:
        """Calculate trade size and time distribution"""
        try:
            if trades_df.empty:
                return {}
            
            distribution = {
                'size_stats': {
                    'min_trade_size': int(trades_df['size'].min()),
                    'max_trade_size': int(trades_df['size'].max()),
                    'avg_trade_size': float(trades_df['size'].mean()),
                    'median_trade_size': float(trades_df['size'].median()),
                    'total_volume': int(trades_df['size'].sum()),
                    'trade_count': len(trades_df)
                },
                'price_impact': {
                    'price_range': float(trades_df['price'].max() - trades_df['price'].min()),
                    'price_volatility': float(trades_df['price'].std()),
                    'avg_price': float(trades_df['price'].mean())
                }
            }
            
            # Side distribution if available
            if 'side' in trades_df.columns:
                side_counts = trades_df['side'].value_counts()
                distribution['side_distribution'] = side_counts.to_dict()
                
                # Calculate buy/sell pressure
                buy_volume = trades_df[trades_df['side'] == 'buy']['size'].sum() if 'buy' in side_counts else 0
                sell_volume = trades_df[trades_df['side'] == 'sell']['size'].sum() if 'sell' in side_counts else 0
                total_volume = buy_volume + sell_volume
                
                if total_volume > 0:
                    distribution['market_pressure'] = {
                        'buy_pressure': float(buy_volume / total_volume),
                        'sell_pressure': float(sell_volume / total_volume),
                        'net_pressure': float((buy_volume - sell_volume) / total_volume)
                    }
            
            return distribution
            
        except Exception as e:
            logger.error(f"Trade distribution calculation error: {e}")
            return {}
    
    @staticmethod
    def detect_large_trades(trades_df: pd.DataFrame, percentile: float = 95.0) -> List[Dict[str, Any]]:
        """Detect unusually large trades (block trades)"""
        try:
            if trades_df.empty or 'size' not in trades_df.columns:
                return []
            
            threshold = trades_df['size'].quantile(percentile / 100.0)
            large_trades = trades_df[trades_df['size'] >= threshold]
            
            result = []
            for timestamp, trade in large_trades.iterrows():
                result.append({
                    'timestamp': timestamp.isoformat(),
                    'price': float(trade['price']),
                    'size': int(trade['size']),
                    'side': trade.get('side', 'unknown'),
                    'trade_id': trade.get('trade_id'),
                    'percentile_rank': float((trades_df['size'] <= trade['size']).mean() * 100)
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Large trades detection error: {e}")
            return []

# Enhanced dependencies
async def get_enhanced_storage_service():
    """Get enhanced storage service for trades"""
    try:
        db_manager = get_db_manager()
        redis_service = await get_redis_service()
        
        db_session = db_manager.get_sync_session()
        
        storage_service = ProductionDataStorageService(
            db=db_session,
            redis_client=redis_service.redis_client,
            enhanced_redis_service=redis_service,
            config=get_settings()
        )
        
        return storage_service
        
    except Exception as e:
        logger.error(f"Error creating enhanced storage service: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Storage service initialization failed"
        )

# ==================== Core Trade Data Endpoints ====================
@router.get("/{symbol}", response_model=APIResponse)
async def get_trade_data(
    symbol: str = Depends(validate_symbol),
    start_date: datetime = Query(..., description="Start date (ISO format)"),
    end_date: datetime = Query(..., description="End date (ISO format)"),
    dataset: Optional[str] = Query(None, description="Specific dataset"),
    limit: Optional[int] = Query(1000, ge=1, le=50000, description="Maximum records"),
    trade_side: Optional[str] = Query(None, regex="^(buy|sell|unknown)$", description="Filter by trade side"),
    min_size: Optional[int] = Query(None, ge=1, description="Minimum trade size filter"),
    max_size: Optional[int] = Query(None, ge=1, description="Maximum trade size filter"),
    format: str = Query("standard", regex="^(standard|csv|streaming)$", description="Response format"),
    include_analysis: bool = Query(False, description="Include trade analysis"),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Enhanced trade data retrieval with filtering and analysis"""
    
    start_time = time.time()
    
    # FIXED: Use async context manager for proper resource cleanup
    async with get_enhanced_storage_service() as storage_service:
        try:
            # Validate date range
            if start_date >= end_date:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Start date must be before end date"
                )
            
            # Limit date range for performance (trades are high-frequency)
            max_days = 7  # 1 week max for trade data
            if (end_date - start_date).days > max_days:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Date range cannot exceed {max_days} days for trade data"
                )
            
            # Validate size filters
            if min_size and max_size and min_size > max_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Minimum size cannot be greater than maximum size"
                )
            
            # Get trade data using optimized storage service
            df = await storage_service.get_trade_data_optimized(
                symbol=symbol,
                start_date=start_date,
                end_date=end_date,
                dataset=dataset,
                limit=limit,
                trade_side=trade_side
            )
            
            if df.empty:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No trade data found for {symbol}"
                )
            
            # Apply size filters
            if min_size:
                df = df[df['size'] >= min_size]
            if max_size:
                df = df[df['size'] <= max_size]
            
            # Handle different response formats
            if format == "csv":
                # Return CSV format
                csv_buffer = io.StringIO()
                df.to_csv(csv_buffer, index=True)
                csv_content = csv_buffer.getvalue()
                
                return StreamingResponse(
                    io.StringIO(csv_content),
                    media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={symbol}_trades.csv"}
                )
            
            elif format == "streaming":
                # Return streaming JSON for large datasets
                return StreamingResponse(
                    stream_trade_data(df),
                    media_type="application/json"
                )
            
            else:
                # FIXED: Standard JSON format with proper NaN handling
                records = []
                for timestamp, row in df.iterrows():
                    record = {
                        "timestamp": timestamp.isoformat(),
                        "price": float(row['price']) if pd.notna(row['price']) else 0.0,
                        "size": int(row['size']) if pd.notna(row['size']) else 0,
                        "side": row.get('side', 'unknown') if pd.notna(row.get('side')) else 'unknown',
                        "trade_id": row.get('trade_id') if pd.notna(row.get('trade_id')) else None
                    }
                    records.append(record)
                
                # Calculate basic statistics with NaN handling
                stats = {
                    "total_trades": len(records),
                    "total_volume": int(df['size'].fillna(0).sum()),
                    "vwap": TradeDataAnalyzer.calculate_vwap(df),
                    "price_range": {
                        "min": float(df['price'].fillna(0).min()),
                        "max": float(df['price'].fillna(0).max())
                    }
                }
                
                # Add detailed analysis if requested
                analysis = {}
                if include_analysis:
                    analysis = {
                        "distribution": TradeDataAnalyzer.calculate_trade_distribution(df),
                        "large_trades": TradeDataAnalyzer.detect_large_trades(df),
                        "time_analysis": await analyze_trade_timing(df)
                    }
                
                # Schedule background cache warming
                background_tasks.add_task(
                    cache_related_trade_data, symbol, start_date, end_date
                )
                
                # Update metrics
                TRADES_REQUESTS.labels(endpoint='data', symbol=symbol).inc()
                TRADES_DURATION.labels(endpoint='data').observe(time.time() - start_time)
                TRADES_VOLUME_PROCESSED.inc(stats['total_volume'])
                
                response_data = {
                    "symbol": symbol,
                    "trades": records,
                    "statistics": stats,
                    "filters": {
                        "start_date": start_date.isoformat(),
                        "end_date": end_date.isoformat(),
                        "trade_side": trade_side,
                        "size_range": [min_size, max_size] if min_size or max_size else None,
                        "dataset": dataset
                    }
                }
                
                if include_analysis:
                    response_data["analysis"] = analysis
                
                return APIResponse(
                    data=response_data,
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
# ==================== Real-time Trade Endpoints ====================

@router.get("/{symbol}/latest", response_model=APIResponse)
async def get_latest_trades(
    symbol: str = Depends(validate_symbol),
    count: int = Query(100, ge=1, le=1000, description="Number of latest trades"),
    include_analysis: bool = Query(True, description="Include real-time analysis"),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Get latest trades with real-time analysis"""
    
    start_time = time.time()
    
    try:
        # Get recent trades (last hour)
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(hours=1)
        
        df = await storage_service.get_trade_data_optimized(
            symbol=symbol,
            start_date=start_date,
            end_date=end_date,
            limit=count
        )
        
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No recent trades found for {symbol}"
            )
        
        # Sort by timestamp (most recent first)
        df = df.sort_index(ascending=False)
        
        # Convert to records
        latest_trades = []
        for timestamp, row in df.head(count).iterrows():
            trade = {
                "timestamp": timestamp.isoformat(),
                "price": float(row['price']),
                "size": int(row['size']),
                "side": row.get('side', 'unknown'),
                "trade_id": row.get('trade_id')
            }
            latest_trades.append(trade)
        
        # Real-time statistics
        stats = {
            "latest_price": float(df.iloc[0]['price']),
            "total_volume_1h": int(df['size'].sum()),
            "trade_count_1h": len(df),
            "vwap_1h": TradeDataAnalyzer.calculate_vwap(df),
            "largest_trade_1h": {
                "size": int(df['size'].max()),
                "price": float(df.loc[df['size'].idxmax(), 'price'])
            }
        }
        
        # Price movement analysis
        if len(df) > 1:
            price_change = df.iloc[0]['price'] - df.iloc[-1]['price']
            stats['price_change_1h'] = float(price_change)
            stats['price_change_pct_1h'] = float((price_change / df.iloc[-1]['price']) * 100)
        
        # Advanced analysis if requested
        analysis = {}
        if include_analysis:
            analysis = {
                "distribution": TradeDataAnalyzer.calculate_trade_distribution(df),
                "momentum": await analyze_trade_momentum(df),
                "liquidity": await analyze_liquidity_metrics(df)
            }
        
        # Try to get real-time price data
        try:
            redis_service = await get_redis_service()
            realtime_price = await redis_service.get_real_time_price(symbol)
            if realtime_price:
                stats['realtime_price'] = realtime_price.get('price')
                stats['bid_ask_spread'] = realtime_price.get('spread')
        except Exception as e:
            logger.warning(f"Could not get realtime price for {symbol}: {e}")
        
        # Update metrics
        TRADES_REQUESTS.labels(endpoint='latest', symbol=symbol).inc()
        TRADES_DURATION.labels(endpoint='latest').observe(time.time() - start_time)
        
        response_data = {
            "symbol": symbol,
            "latest_trades": latest_trades,
            "statistics": stats,
            "period": "1_hour"
        }
        
        if include_analysis:
            response_data["analysis"] = analysis
        
        return APIResponse(
            data=response_data,
            count=len(latest_trades),
            message=f"Latest {len(latest_trades)} trades for {symbol}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting latest trades for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve latest trades"
        )
    finally:
        if hasattr(storage_service, 'close'):
            storage_service.close()

# ==================== Trade Analytics Endpoints ====================

@router.get("/{symbol}/analytics", response_model=APIResponse)
async def get_trade_analytics(
    symbol: str = Depends(validate_symbol),
    start_date: datetime = Query(..., description="Start date"),
    end_date: datetime = Query(..., description="End date"),
    analysis_type: str = Query("comprehensive", regex="^(basic|comprehensive|institutional)$"),
    include_microstructure: bool = Query(False, description="Include market microstructure analysis"),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Advanced trade analytics with institutional-grade insights"""
    
    start_time = time.time()
    
    try:
        # Validate date range (analytics limited to 3 days for performance)
        if (end_date - start_date).days > 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Analytics date range cannot exceed 3 days"
            )
        
        # Get trade data
        df = await storage_service.get_trade_data_optimized(
            symbol=symbol,
            start_date=start_date,
            end_date=end_date,
            limit=None  # No limit for analytics
        )
        
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No trade data found for {symbol} in specified period"
            )
        
        analytics = {
            "symbol": symbol,
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "total_trades": len(df)
            }
        }
        
        # Basic analytics
        analytics["basic_metrics"] = {
            "vwap": TradeDataAnalyzer.calculate_vwap(df),
            "total_volume": int(df['size'].sum()),
            "average_trade_size": float(df['size'].mean()),
            "price_range": {
                "min": float(df['price'].min()),
                "max": float(df['price'].max()),
                "volatility": float(df['price'].std())
            }
        }
        
        # Comprehensive analytics
        if analysis_type in ["comprehensive", "institutional"]:
            analytics["distribution_analysis"] = TradeDataAnalyzer.calculate_trade_distribution(df)
            analytics["large_trades"] = TradeDataAnalyzer.detect_large_trades(df)
            analytics["time_analysis"] = await analyze_trade_timing(df)
            analytics["liquidity_metrics"] = await analyze_liquidity_metrics(df)
            
        # Institutional-grade analytics
        if analysis_type == "institutional":
            analytics["execution_quality"] = await analyze_execution_quality(df)
            analytics["market_impact"] = await analyze_market_impact(df)
            analytics["flow_toxicity"] = await analyze_order_flow_toxicity(df)
            
        # Market microstructure (advanced)
        if include_microstructure:
            analytics["microstructure"] = await analyze_market_microstructure(df)
        
        # Update metrics
        TRADES_REQUESTS.labels(endpoint='analytics', symbol=symbol).inc()
        TRADES_DURATION.labels(endpoint='analytics').observe(time.time() - start_time)
        
        return APIResponse(
            data=analytics,
            message=f"Trade analytics for {symbol} ({analysis_type} analysis)"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in trade analytics for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate trade analytics"
        )
    finally:
        if hasattr(storage_service, 'close'):
            storage_service.close()

@router.get("/{symbol}/flow")
async def get_order_flow(
    symbol: str = Depends(validate_symbol),
    timeframe: str = Query("1m", regex="^(30s|1m|5m|15m)$", description="Aggregation timeframe"),
    periods: int = Query(20, ge=1, le=100, description="Number of periods"),
    storage_service: ProductionDataStorageService = Depends(get_enhanced_storage_service)
):
    """Get aggregated order flow data"""
    
    try:
        # Calculate time range
        end_date = datetime.now(timezone.utc)
        
        # Convert timeframe to timedelta
        timeframe_deltas = {
            "30s": timedelta(seconds=30),
            "1m": timedelta(minutes=1),
            "5m": timedelta(minutes=5),
            "15m": timedelta(minutes=15)
        }
        
        period_delta = timeframe_deltas[timeframe]
        start_date = end_date - (period_delta * periods)
        
        # Get trade data
        df = await storage_service.get_trade_data_optimized(
            symbol=symbol,
            start_date=start_date,
            end_date=end_date
        )
        
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No trade data found for {symbol}"
            )
        
        # Aggregate trades into timeframe buckets
        flow_data = await aggregate_order_flow(df, timeframe)
        
        return APIResponse(
            data={
                "symbol": symbol,
                "timeframe": timeframe,
                "flow_data": flow_data,
                "period_count": len(flow_data)
            },
            count=len(flow_data),
            message=f"Order flow data for {symbol}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting order flow for {symbol}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve order flow data"
        )
    finally:
        if hasattr(storage_service, 'close'):
            storage_service.close()

# ==================== Utility Functions ====================

async def stream_trade_data(df: pd.DataFrame) -> AsyncGenerator[str, None]:
    """Stream trade data for large datasets - FIXED NaN handling"""
    try:
        yield '{"trades": ['
        
        first = True
        for timestamp, row in df.iterrows():
            if not first:
                yield ","
            
            # FIXED: Proper NaN handling for all fields
            trade = {
                "timestamp": timestamp.isoformat(),
                "price": float(row['price']) if pd.notna(row['price']) else 0.0,
                "size": int(row['size']) if pd.notna(row['size']) else 0,
                "side": row.get('side', 'unknown') if pd.notna(row.get('side')) else 'unknown',
                "trade_id": row.get('trade_id') if pd.notna(row.get('trade_id')) else None
            }
            
            yield json.dumps(trade)
            first = False
            
            # Small delay to prevent overwhelming the client
            await asyncio.sleep(0.001)
        
        yield ']}'
        
    except Exception as e:
        logger.error(f"Error streaming trade data: {e}")
        yield f'{{"error": "{str(e)}"}}'
    
async def analyze_trade_timing(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze trade timing patterns"""
    try:
        timing_analysis = {}
        
        if len(df) > 10:
            # Calculate inter-trade intervals
            intervals = df.index.to_series().diff().dt.total_seconds().dropna()
            
            timing_analysis = {
                "avg_interval_seconds": float(intervals.mean()),
                "median_interval_seconds": float(intervals.median()),
                "min_interval_seconds": float(intervals.min()),
                "max_interval_seconds": float(intervals.max()),
                "trades_per_minute": float(len(df) / ((df.index[-1] - df.index[0]).total_seconds() / 60))
            }
            
            # Detect clustering
            if len(intervals) > 5:
                short_intervals = (intervals < intervals.quantile(0.1)).sum()
                timing_analysis["trade_clustering_pct"] = float(short_intervals / len(intervals) * 100)
        
        return timing_analysis
        
    except Exception as e:
        logger.error(f"Trade timing analysis error: {e}")
        return {}

async def analyze_trade_momentum(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze trade momentum and direction"""
    try:
        if len(df) < 10:
            return {}
        
        # Price momentum
        recent_trades = df.head(10)  # Last 10 trades
        older_trades = df.tail(10)   # First 10 trades
        
        recent_avg_price = recent_trades['price'].mean()
        older_avg_price = older_trades['price'].mean()
        
        price_momentum = (recent_avg_price - older_avg_price) / older_avg_price * 100
        
        momentum_analysis = {
            "price_momentum_pct": float(price_momentum),
            "momentum_direction": "bullish" if price_momentum > 0 else "bearish",
            "momentum_strength": "strong" if abs(price_momentum) > 0.5 else "weak"
        }
        
        # Volume momentum
        recent_volume = recent_trades['size'].sum()
        older_volume = older_trades['size'].sum()
        
        if older_volume > 0:
            volume_momentum = (recent_volume - older_volume) / older_volume * 100
            momentum_analysis["volume_momentum_pct"] = float(volume_momentum)
        
        return momentum_analysis
        
    except Exception as e:
        logger.error(f"Trade momentum analysis error: {e}")
        return {}

async def analyze_liquidity_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze liquidity metrics"""
    try:
        if df.empty:
            return {}
        
        liquidity_metrics = {
            "trade_frequency": len(df) / ((df.index[-1] - df.index[0]).total_seconds() / 3600),  # trades per hour
            "average_trade_size": float(df['size'].mean()),
            "size_volatility": float(df['size'].std()),
            "turnover": int(df['size'].sum())
        }
        
        # Calculate Amihud illiquidity measure (approximation)
        if len(df) > 1:
            returns = df['price'].pct_change().abs().dropna()
            dollar_volume = (df['price'] * df['size']).rolling(window=min(10, len(df))).mean()
            
            if not returns.empty and not dollar_volume.empty:
                illiquidity = (returns / dollar_volume).mean()
                liquidity_metrics["amihud_illiquidity"] = float(illiquidity)
        
        return liquidity_metrics
        
    except Exception as e:
        logger.error(f"Liquidity metrics analysis error: {e}")
        return {}

async def analyze_execution_quality(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze execution quality metrics (institutional-grade)"""
    try:
        if df.empty:
            return {}
        
        execution_metrics = {
            "total_trades": len(df),
            "execution_efficiency": {
                "avg_trade_size": float(df['size'].mean()),
                "size_consistency": float(1 - (df['size'].std() / df['size'].mean()))
            }
        }
        
        # Price improvement analysis
        if len(df) > 1:
            vwap = TradeDataAnalyzer.calculate_vwap(df)
            price_deviations = abs(df['price'] - vwap)
            
            execution_metrics["price_performance"] = {
                "vwap_deviation_avg": float(price_deviations.mean()),
                "vwap_deviation_max": float(price_deviations.max()),
                "trades_within_1pct_vwap": int((price_deviations / vwap < 0.01).sum())
            }
        
        return execution_metrics
        
    except Exception as e:
        logger.error(f"Execution quality analysis error: {e}")
        return {}

async def analyze_market_impact(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze market impact of trades"""
    try:
        if len(df) < 5:
            return {}
        
        # Simple market impact analysis
        large_trades = df[df['size'] > df['size'].quantile(0.9)]
        
        impact_analysis = {
            "large_trade_count": len(large_trades),
            "large_trade_percentage": float(len(large_trades) / len(df) * 100)
        }
        
        # Analyze price movements after large trades
        if len(large_trades) > 0:
            # This is a simplified analysis - in production, you'd need tick-by-tick data
            avg_large_trade_size = large_trades['size'].mean()
            avg_normal_trade_size = df[df['size'] <= df['size'].quantile(0.9)]['size'].mean()
            
            impact_analysis["size_impact_ratio"] = float(avg_large_trade_size / avg_normal_trade_size)
        
        return impact_analysis
        
    except Exception as e:
        logger.error(f"Market impact analysis error: {e}")
        return {}

async def analyze_order_flow_toxicity(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze order flow toxicity (VPIN-style measure)"""
    try:
        if len(df) < 20:
            return {}
        
        # Simplified toxicity measure based on trade imbalance
        toxicity_metrics = {
            "sample_size": len(df)
        }
        
        if 'side' in df.columns:
            buy_volume = df[df['side'] == 'buy']['size'].sum()
            sell_volume = df[df['side'] == 'sell']['size'].sum()
            total_volume = buy_volume + sell_volume
            
            if total_volume > 0:
                imbalance = abs(buy_volume - sell_volume) / total_volume
                toxicity_metrics["volume_imbalance"] = float(imbalance)
                toxicity_metrics["flow_toxicity_level"] = "high" if imbalance > 0.3 else "low"
        
        return toxicity_metrics
        
    except Exception as e:
        logger.error(f"Order flow toxicity analysis error: {e}")
        return {}

async def analyze_market_microstructure(df: pd.DataFrame) -> Dict[str, Any]:
    """Advanced market microstructure analysis"""
    try:
        if len(df) < 50:
            return {"error": "Insufficient data for microstructure analysis"}
        
        microstructure = {
            "sample_characteristics": {
                "total_observations": len(df),
                "time_span_minutes": float((df.index[-1] - df.index[0]).total_seconds() / 60)
            }
        }
        
        # Tick size analysis
        price_increments = df['price'].diff().dropna()
        non_zero_increments = price_increments[price_increments != 0]
        
        if len(non_zero_increments) > 0:
            microstructure["tick_analysis"] = {
                "min_increment": float(non_zero_increments.abs().min()),
                "median_increment": float(non_zero_increments.abs().median()),
                "zero_increment_ratio": float((price_increments == 0).mean())
            }
        
        # Trade size clustering
        size_counts = df['size'].value_counts()
        if len(size_counts) > 0:
            microstructure["size_clustering"] = {
                "most_common_size": int(size_counts.index[0]),
                "size_concentration": float(size_counts.iloc[0] / len(df))
            }
        
        return microstructure
        
    except Exception as e:
        logger.error(f"Microstructure analysis error: {e}")
        return {"error": str(e)}

async def aggregate_order_flow(df: pd.DataFrame, timeframe: str) -> List[Dict[str, Any]]:
    """Aggregate trades into order flow buckets"""
    try:
        # Define resampling rule
        resample_rules = {
            "30s": "30S",
            "1m": "1T",
            "5m": "5T",
            "15m": "15T"
        }
        
        rule = resample_rules.get(timeframe, "1T")
        
        # Resample and aggregate
        agg_data = df.resample(rule).agg({
            'price': ['first', 'last', 'min', 'max', 'mean'],
            'size': ['sum', 'count', 'mean']
        }).round(8)
        
        # Flatten column names
        agg_data.columns = ['_'.join(col).strip() for col in agg_data.columns]
        
        # Convert to list of dictionaries
        flow_data = []
        for timestamp, row in agg_data.iterrows():
            if pd.notna(row['price_first']):  # Only include periods with trades
                period_data = {
                    "timestamp": timestamp.isoformat(),
                    "open": float(row['price_first']),
                    "close": float(row['price_last']),
                    "high": float(row['price_max']),
                    "low": float(row['price_min']),
                    "vwap": float(row['price_mean']),
                    "volume": int(row['size_sum']),
                    "trade_count": int(row['size_count']),
                    "avg_trade_size": float(row['size_mean'])
                }
                flow_data.append(period_data)
        
        return flow_data
        
    except Exception as e:
        logger.error(f"Order flow aggregation error: {e}")
        return []

# ==================== Background Tasks ====================

async def cache_related_trade_data(symbol: str, start_date: datetime, end_date: datetime):
    """Background task to cache related trade data"""
    try:
        # Cache common time periods for this symbol
        cache_periods = [
            timedelta(hours=1),
            timedelta(hours=4),
            timedelta(days=1)
        ]
        
        redis_service = await get_redis_service()
        
        for period in cache_periods:
            period_start = max(start_date, end_date - period)
            cache_key = f"trades:{symbol}:{period_start.isoformat()}:{end_date.isoformat()}"
            
            # Check if already cached
            cached = await redis_service.get_with_l1_fallback(cache_key, 'trades')
            if not cached:
                # This would trigger caching in the storage service
                pass
                
    except Exception as e:
        logger.warning(f"Trade data cache warming failed for {symbol}: {e}")

# ==================== Performance Monitoring ====================

@router.get("/performance/stats")
async def get_trades_performance_stats():
    """Get trade endpoint performance statistics"""
    
    try:
        return APIResponse(
            data={
                "message": "Trade performance metrics available via Prometheus /metrics endpoint",
                "metrics_available": [
                    "trades_requests_total",
                    "trades_request_duration_seconds", 
                    "trades_volume_processed_total"
                ]
            },
            message="Performance statistics endpoint"
        )
        
    except Exception as e:
        logger.error(f"Error getting trade performance stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve performance statistics"
        )
class TradeDataAnalyzer:
    """Advanced trade data analysis and aggregation"""
    
    @staticmethod
    def calculate_vwap(trades_df: pd.DataFrame) -> float:
        """Calculate Volume Weighted Average Price - FIXED NaN handling"""
        try:
            if trades_df.empty or 'price' not in trades_df.columns or 'size' not in trades_df.columns:
                return 0.0
            
            # FIXED: Handle NaN values before calculation
            clean_df = trades_df.dropna(subset=['price', 'size'])
            if clean_df.empty:
                return 0.0
            
            total_volume = clean_df['size'].sum()
            if total_volume == 0:
                return 0.0
            
            weighted_prices = (clean_df['price'] * clean_df['size']).sum()
            return float(weighted_prices / total_volume)
            
        except Exception as e:
            logger.error(f"VWAP calculation error: {e}")
            return 0.0
    
    @staticmethod
    def calculate_trade_distribution(trades_df: pd.DataFrame) -> Dict[str, Any]:
        """Calculate trade size and time distribution - FIXED NaN handling"""
        try:
            if trades_df.empty:
                return {}
            
            # FIXED: Clean data before analysis
            clean_df = trades_df.dropna(subset=['price', 'size'])
            if clean_df.empty:
                return {"error": "No valid data after cleaning"}
            
            distribution = {
                'size_stats': {
                    'min_trade_size': int(clean_df['size'].min()),
                    'max_trade_size': int(clean_df['size'].max()),
                    'avg_trade_size': float(clean_df['size'].mean()),
                    'median_trade_size': float(clean_df['size'].median()),
                    'total_volume': int(clean_df['size'].sum()),
                    'trade_count': len(clean_df)
                },
                'price_impact': {
                    'price_range': float(clean_df['price'].max() - clean_df['price'].min()),
                    'price_volatility': float(clean_df['price'].std()),
                    'avg_price': float(clean_df['price'].mean())
                }
            }
            
            # Side distribution if available
            if 'side' in clean_df.columns:
                side_counts = clean_df['side'].value_counts()
                distribution['side_distribution'] = side_counts.to_dict()
                
                # Calculate buy/sell pressure
                buy_volume = clean_df[clean_df['side'] == 'buy']['size'].sum() if 'buy' in side_counts else 0
                sell_volume = clean_df[clean_df['side'] == 'sell']['size'].sum() if 'sell' in side_counts else 0
                total_volume = buy_volume + sell_volume
                
                if total_volume > 0:
                    distribution['market_pressure'] = {
                        'buy_pressure': float(buy_volume / total_volume),
                        'sell_pressure': float(sell_volume / total_volume),
                        'net_pressure': float((buy_volume - sell_volume) / total_volume)
                    }
            
            return distribution
            
        except Exception as e:
            logger.error(f"Trade distribution calculation error: {e}")
            return {"error": str(e)}