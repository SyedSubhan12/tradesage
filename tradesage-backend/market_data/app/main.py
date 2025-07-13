from fastapi import FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import time
import logging
from contextlib import asynccontextmanager
import asyncio
from typing import Dict, Any
import uvicorn
import signal
import sys

from .utils.config import get_settings
from .utils.database import OptimizedDatabaseManager, get_db_manager
from .routers.v1 import ohlcv, trades, news, websocket_handler as ws_router
from .schemas.market_data import ErrorResponse
from .services.redis_optimizer import EnhancedTradingRedisService, get_redis_service
from .routers.v1.websocket_handler import TradingViewWebSocketManager, get_websocket_manager
from .services.data_ingestion import ProductionDataIngestionService
from .services.data_storage import DataStorageService
from .utils.databento_client import DatabentoClient
from .utils.database import get_db

from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from contextlib import asynccontextmanager
import structlog
import traceback

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Enhanced Prometheus Metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status_code'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration', ['method', 'endpoint'])
WEBSOCKET_CONNECTIONS = Gauge('websocket_connections_active', 'Active WebSocket connections')
CACHE_HIT_RATE = Gauge('cache_hit_rate', 'Cache hit rate percentage')
DATABASE_CONNECTIONS = Gauge('database_connections_active', 'Active database connections')
INGESTION_RATE = Gauge('data_ingestion_records_per_second', 'Data ingestion rate')
ERROR_RATE = Counter('errors_total', 'Total errors', ['error_type'])

# Global service instances
settings = get_settings()
db_manager: OptimizedDatabaseManager = None
redis_service: EnhancedTradingRedisService = None
websocket_manager: TradingViewWebSocketManager = None
data_storage_service: DataStorageService = None
ingestion_service: ProductionDataIngestionService = None

class HealthCheckManager:
    """Centralized health check management"""
    
    def __init__(self):
        self.checks = {}
        self.overall_status = "healthy"
    
    async def register_check(self, name: str, check_func, critical: bool = True):
        """Register a health check"""
        self.checks[name] = {
            'func': check_func,
            'critical': critical,
            'last_result': None,
            'last_check': 0
        }
    
    async def run_checks(self) -> Dict[str, Any]:
        """Run all health checks"""
        results = {}
        overall_healthy = True
        
        for name, check in self.checks.items():
            try:
                result = await check['func']()
                results[name] = {
                    'status': 'healthy' if result.get('status') == 'ok' else 'unhealthy',
                    'details': result,
                    'critical': check['critical']
                }
                
                if check['critical'] and results[name]['status'] != 'healthy':
                    overall_healthy = False
                    
            except Exception as e:
                results[name] = {
                    'status': 'unhealthy',
                    'error': str(e),
                    'critical': check['critical']
                }
                
                if check['critical']:
                    overall_healthy = False
        
        self.overall_status = "healthy" if overall_healthy else "unhealthy"
        
        return {
            'status': self.overall_status,
            'checks': results,
            'timestamp': time.time()
        }

health_manager = HealthCheckManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Enhanced application lifespan with comprehensive initialization"""
    logger.info("🚀 Starting TradeSage Market Data API (Production Mode)...")
    
    global db_manager, redis_service, websocket_manager, data_storage_service, ingestion_service
    
    try:
        # ----------------------- Initialize Core Services -----------------------
        
        # 1. Initialize optimized database manager
        logger.info("📊 Initializing optimized database manager...")
        db_manager = OptimizedDatabaseManager(settings)
        await db_manager.initialize()
        logger.info("✅ Database manager initialized")
        
        # 2. Initialize enhanced Redis service
        logger.info("🔄 Initializing enhanced Redis service...")
        redis_service = EnhancedTradingRedisService(settings.REDIS_URL)
        await redis_service.connect()
        logger.info("✅ Redis service initialized")
        
        # 3. Initialize data storage service
        logger.info("💾 Initializing data storage service...")
        db_session = db_manager.get_sync_session()
        data_storage_service = DataStorageService(db_session, redis_service.redis_client)
        logger.info("✅ Data storage service initialized")
        
        # 4. Initialize WebSocket manager
        logger.info("🌐 Initializing WebSocket manager...")
        websocket_manager = TradingViewWebSocketManager(redis_service, data_storage_service)
        logger.info("✅ WebSocket manager initialized")
        
        # 5. Initialize production data ingestion service
        logger.info("⚡ Initializing production data ingestion service...")
        databento_client = DatabentoClient()
        ingestion_service = ProductionDataIngestionService(
            databento_client=databento_client,
            db_manager=db_manager,
            redis_service=redis_service,
            websocket_manager=websocket_manager
        )
        await ingestion_service.start_background_processing()
        logger.info("✅ Production data ingestion service initialized")
        
        # ----------------------- Register Health Checks -----------------------
        
        await health_manager.register_check("database", db_manager.health_check, critical=True)
        await health_manager.register_check("redis", lambda: {"status": "ok"}, critical=True)
        await health_manager.register_check("websocket", lambda: {"status": "ok", "connections": len(websocket_manager.clients)}, critical=False)
        
        # ----------------------- Initial Data Loading -----------------------
        
        if settings.ENABLE_STARTUP_INGESTION:
            logger.info("🔄 Starting initial data ingestion...")
            try:
                # Ingest symbols for all datasets
                symbol_results = await ingestion_service.ingest_symbols_parallel(settings.DATASETS)
                total_symbols = sum(symbol_results.values())
                logger.info(f"✅ Initial symbol ingestion completed: {total_symbols} symbols")
                
                # Warm cache for popular symbols
                if total_symbols > 0:
                    popular_symbols = ['AAPL', 'MSFT', 'GOOGL', 'AMZN', 'TSLA']  # Can be made configurable
                    await redis_service.warm_cache_for_symbols(popular_symbols)
                    logger.info("✅ Cache warmed for popular symbols")
                
            except Exception as e:
                logger.error(f"❌ Initial data ingestion failed: {e}")
                # Don't fail startup for ingestion errors
        
        # ----------------------- Background Tasks -----------------------
        
        # Start background metrics collection
        asyncio.create_task(update_metrics_periodically())
        
        # Start background cache cleanup
        asyncio.create_task(periodic_cache_cleanup())
        
        logger.info("🎉 TradeSage Market Data API started successfully!")
        logger.info(f"📊 Database pools: Read={db_manager.read_pool.get_size()}, Write={db_manager.write_pool.get_size()}")
        logger.info(f"🔄 Redis connections: {redis_service.redis_client}")
        logger.info(f"🌐 WebSocket manager ready for connections")
        
    except Exception as e:
        logger.error(f"💥 Startup failed: {e}")
        logger.error(traceback.format_exc())
        raise
    
    # App is running
    yield
    
    # ----------------------- Shutdown Sequence -----------------------
    
    logger.info("🛑 Shutting down TradeSage Market Data API...")
    
    try:
        # Stop background processing
        if ingestion_service:
            await ingestion_service.stop_background_processing()
            logger.info("✅ Data ingestion service stopped")
        
        # Disconnect WebSocket clients
        if websocket_manager:
            await websocket_manager.shutdown()
            logger.info("✅ WebSocket manager shutdown")
        
        # Close database connections
        if db_manager:
            await db_manager.close()
            logger.info("✅ Database connections closed")
        
        # Close Redis connections
        if redis_service:
            await redis_service.redis_client.aclose()
            logger.info("✅ Redis connections closed")
        
    except Exception as e:
        logger.error(f"❌ Shutdown error: {e}")
    
    logger.info("👋 TradeSage Market Data API shutdown complete")

# Create FastAPI app with enhanced configuration
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Production-grade market data API for institutional trading platforms",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None
)

# ----------------------- Middleware Configuration -----------------------

# CORS middleware with production settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS.split(",") if hasattr(settings, 'CORS_ORIGINS') else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Process-Time", "X-Request-ID"]
)

# Gzip compression for responses > 1KB
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Enhanced request processing middleware
@app.middleware("http")
async def enhanced_request_middleware(request, call_next):
    """Enhanced middleware with metrics, tracing, and performance monitoring"""
    start_time = time.time()
    request_id = f"req_{int(start_time * 1000000)}"
    
    # Add request ID to headers
    request.state.request_id = request_id
    
    try:
        # Process request
        response = await call_next(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Add performance headers
        response.headers["X-Process-Time"] = f"{process_time:.4f}"
        response.headers["X-Request-ID"] = request_id
        
        # Update metrics
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code
        ).inc()
        
        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(process_time)
        
        # Log slow requests
        if process_time > 1.0:
            logger.warning(
                "Slow request detected",
                method=request.method,
                path=request.url.path,
                duration=process_time,
                request_id=request_id
            )
        
        return response
        
    except Exception as e:
        process_time = time.time() - start_time
        
        # Update error metrics
        ERROR_RATE.labels(error_type=type(e).__name__).inc()
        
        # Log error with context
        logger.error(
            "Request processing failed",
            method=request.method,
            path=request.url.path,
            duration=process_time,
            request_id=request_id,
            error=str(e),
            exc_info=True
        )
        
        raise

# ----------------------- WebSocket Endpoint -----------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Enhanced WebSocket endpoint for real-time data"""
    client_id = None
    
    try:
        # Connect client
        client_id = await websocket_manager.connect_client(websocket)
        WEBSOCKET_CONNECTIONS.inc()
        
        logger.info(f"WebSocket client connected: {client_id}")
        
        # Handle messages
        while True:
            try:
                message = await websocket.receive_text()
                await websocket_manager.handle_message(client_id, message)
                
            except WebSocketDisconnect:
                logger.info(f"WebSocket client disconnected: {client_id}")
                break
                
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {e}")
        
    finally:
        if client_id:
            await websocket_manager.disconnect_client(client_id)
            WEBSOCKET_CONNECTIONS.dec()

# ----------------------- Include Enhanced Routers -----------------------

app.include_router(ohlcv.router, prefix=settings.API_V1_STR, tags=["OHLCV Data"])
app.include_router(trades.router, prefix=settings.API_V1_STR, tags=["Trade Data"])
app.include_router(news.router, prefix=settings.API_V1_STR, tags=["News Data"])

# ----------------------- TradingView Compatible Endpoints -----------------------

@app.get("/api/v1/tradingview/config")
async def tradingview_config():
    """TradingView configuration endpoint"""
    return {
        "supported_resolutions": ["1", "5", "15", "30", "60", "240", "1D", "1W"],
        "supports_group_request": False,
        "supports_marks": False,
        "supports_search": True,
        "supports_timescale_marks": False,
        "exchanges": [
            {"value": "NASDAQ", "name": "NASDAQ", "desc": "NASDAQ"},
            {"value": "NYSE", "name": "NYSE", "desc": "New York Stock Exchange"}
        ],
        "symbols_types": [
            {"name": "Stock", "value": "stock"}
        ],
        "supported_features": ["side_toolbar_series_style"]
    }

@app.get("/api/v1/tradingview/symbols")
async def tradingview_symbol_search(symbol: str):
    """TradingView symbol search endpoint"""
    try:
        # Search for symbols matching the query
        symbols = await data_storage_service.get_symbols()
        
        matching_symbols = [s for s in symbols if symbol.upper() in s.upper()][:10]
        
        results = []
        for sym in matching_symbols:
            results.append({
                "symbol": sym,
                "full_name": f"NASDAQ:{sym}",
                "description": f"{sym} Stock",
                "exchange": "NASDAQ",
                "ticker": sym,
                "type": "stock"
            })
        
        return results
        
    except Exception as e:
        logger.error(f"Symbol search error: {e}")
        return []

@app.get("/api/v1/tradingview/{symbol}/history")
async def tradingview_history(
    symbol: str,
    resolution: str,
    from_timestamp: int,
    to_timestamp: int,
    db_session = Depends(get_db)
):
    """TradingView compatible history endpoint"""
    try:
        # Convert TradingView resolution to our timeframe format
        resolution_map = {
            "1": "ohlcv-1m",
            "5": "ohlcv-5m", 
            "15": "ohlcv-15m",
            "30": "ohlcv-30m",
            "60": "ohlcv-1h",
            "240": "ohlcv-4h",
            "1D": "ohlcv-1d",
            "1W": "ohlcv-1w"
        }
        
        timeframe = resolution_map.get(resolution)
        if not timeframe:
            return {"s": "error", "errmsg": f"Unsupported resolution: {resolution}"}
        
        # Convert timestamps to datetime
        from datetime import datetime, timezone
        start_date = datetime.fromtimestamp(from_timestamp, tz=timezone.utc)
        end_date = datetime.fromtimestamp(to_timestamp, tz=timezone.utc)
        
        # Get data from storage service
        df = data_storage_service.get_ohlcv_data(symbol, timeframe, start_date, end_date)
        
        if df.empty:
            return {"s": "no_data"}
        
        # Format for TradingView
        return {
            "s": "ok",
            "t": [int(ts.timestamp()) for ts in df.index],
            "o": df['open'].fillna(0).tolist(),
            "h": df['high'].fillna(0).tolist(),
            "l": df['low'].fillna(0).tolist(),
            "c": df['close'].fillna(0).tolist(),
            "v": df['volume'].fillna(0).astype(int).tolist()
        }
        
    except Exception as e:
        logger.error(f"TradingView history error: {e}")
        return {"s": "error", "errmsg": str(e)}

# ----------------------- Enhanced Health and Monitoring Endpoints -----------------------

@app.get("/health")
async def enhanced_health_check():
    """Comprehensive health check endpoint"""
    try:
        health_result = await health_manager.run_checks()
        
        status_code = 200 if health_result['status'] == 'healthy' else 503
        
        return JSONResponse(
            status_code=status_code,
            content={
                **health_result,
                "version": settings.APP_VERSION,
                "uptime": time.time() - app.state.start_time if hasattr(app.state, 'start_time') else 0
            }
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )

@app.get("/health/ready")
async def readiness_check():
    """Kubernetes readiness probe"""
    try:
        # Quick check of critical services
        if not db_manager or not redis_service:
            return JSONResponse(
                status_code=503,
                content={"ready": False, "reason": "Services not initialized"}
            )
        
        # Test database connection
        health_result = await db_manager.health_check()
        if health_result['status'] != 'healthy':
            return JSONResponse(
                status_code=503,
                content={"ready": False, "reason": "Database unhealthy"}
            )
        
        return {"ready": True, "timestamp": time.time()}
        
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"ready": False, "reason": str(e)}
        )

@app.get("/health/live")
async def liveness_check():
    """Kubernetes liveness probe"""
    return {"alive": True, "timestamp": time.time()}

@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus metrics endpoint"""
    try:
        # Update dynamic metrics
        if db_manager:
            stats = db_manager.get_connection_stats()
            if 'read_pool' in stats:
                DATABASE_CONNECTIONS.set(stats['read_pool'].get('size', 0))
        
        if redis_service:
            cache_stats = redis_service.get_comprehensive_stats()
            l1_stats = cache_stats.get('l1_caches', {})
            
            # Calculate overall hit rate
            total_hits = sum(cache.get('stats', {}).get('hits', 0) for cache in l1_stats.values())
            total_requests = sum(
                cache.get('stats', {}).get('hits', 0) + cache.get('stats', {}).get('misses', 0)
                for cache in l1_stats.values()
            )
            
            if total_requests > 0:
                hit_rate = (total_hits / total_requests) * 100
                CACHE_HIT_RATE.set(hit_rate)
        
        if websocket_manager:
            ws_stats = websocket_manager.get_stats()
            WEBSOCKET_CONNECTIONS.set(ws_stats.get('active_clients', 0))
        
        if ingestion_service:
            ingestion_stats = ingestion_service.get_ingestion_stats()
            throughput = ingestion_stats.get('metrics', {}).get('throughput_rps', 0)
            INGESTION_RATE.set(throughput)
        
        return PlainTextResponse(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST
        )
        
    except Exception as e:
        logger.error(f"Metrics endpoint error: {e}")
        return PlainTextResponse(content="# Metrics temporarily unavailable\n")

# ----------------------- Admin and Debug Endpoints -----------------------

@app.get("/admin/stats")
async def admin_stats():
    """Administrative statistics endpoint"""
    if not settings.DEBUG:
        raise HTTPException(status_code=404, detail="Not found")
    
    try:
        stats = {
            "timestamp": time.time(),
            "version": settings.APP_VERSION,
            "services": {}
        }
        
        if db_manager:
            stats["services"]["database"] = db_manager.get_connection_stats()
        
        if redis_service:
            stats["services"]["redis"] = redis_service.get_comprehensive_stats()
        
        if websocket_manager:
            stats["services"]["websocket"] = websocket_manager.get_stats()
        
        if ingestion_service:
            stats["services"]["ingestion"] = ingestion_service.get_ingestion_stats()
        
        return stats
        
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve stats")

@app.post("/admin/cache/invalidate")
async def admin_invalidate_cache(pattern: str = "*"):
    """Administrative cache invalidation endpoint"""
    if not settings.DEBUG:
        raise HTTPException(status_code=404, detail="Not found")
    
    try:
        await redis_service.invalidate_pattern(pattern)
        return {"message": f"Cache invalidated for pattern: {pattern}"}
        
    except Exception as e:
        logger.error(f"Cache invalidation error: {e}")
        raise HTTPException(status_code=500, detail="Cache invalidation failed")

# ----------------------- Global Exception Handlers -----------------------

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Enhanced global exception handler with structured logging"""
    request_id = getattr(request.state, 'request_id', 'unknown')
    
    logger.error(
        "Unhandled exception",
        request_id=request_id,
        method=request.method,
        url=str(request.url),
        error_type=type(exc).__name__,
        error_message=str(exc),
        exc_info=True
    )
    
    ERROR_RATE.labels(error_type=type(exc).__name__).inc()
    
    # Return different responses based on environment
    if settings.DEBUG:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                message="Internal server error",
                details={"error": str(exc), "type": type(exc).__name__}
            ).dict()
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                message="Internal server error occurred"
            ).dict()
        )

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """HTTP exception handler with logging"""
    request_id = getattr(request.state, 'request_id', 'unknown')
    
    if exc.status_code >= 500:
        logger.error(
            "HTTP error",
            request_id=request_id,
            status_code=exc.status_code,
            detail=exc.detail
        )
        ERROR_RATE.labels(error_type="http_error").inc()
    
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail, "status_code": exc.status_code}
    )

# ----------------------- Background Tasks -----------------------

async def update_metrics_periodically():
    """Background task to update metrics periodically"""
    while True:
        try:
            # Update metrics every 30 seconds
            await asyncio.sleep(30)
            
            # This function body would be populated with actual metric updates
            # The individual metrics are updated in the /metrics endpoint
            
        except Exception as e:
            logger.error(f"Metrics update error: {e}")
            await asyncio.sleep(60)

async def periodic_cache_cleanup():
    """Background task for periodic cache cleanup"""
    while True:
        try:
            # Clean up every 5 minutes
            await asyncio.sleep(300)
            
            if redis_service:
                await redis_service.cleanup_expired_keys()
                logger.debug("Periodic cache cleanup completed")
                
        except Exception as e:
            logger.error(f"Cache cleanup error: {e}")
            await asyncio.sleep(300)

# ----------------------- Root Endpoint -----------------------

@app.get("/")
async def root():
    """Enhanced root endpoint with service information"""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "timestamp": time.time(),
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "docs": "/docs" if settings.DEBUG else None,
            "websocket": "/ws",
            "api": settings.API_V1_STR
        },
        "features": [
            "Real-time WebSocket feeds",
            "TradingView integration", 
            "Multi-tier caching",
            "Prometheus metrics",
            "Production-grade performance"
        ]
    }

# ----------------------- Graceful Shutdown -----------------------

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    # The lifespan context manager will handle the actual cleanup
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Store startup time for uptime calculation
@app.on_event("startup")
async def store_startup_time():
    app.state.start_time = time.time()

# ----------------------- Main Entry Point -----------------------

if __name__ == "__main__":
    # Production-grade server configuration
    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "root": {
            "level": "INFO",
            "handlers": ["default"],
        },
    }
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT if hasattr(settings, 'PORT') else 8005,
        reload=settings.DEBUG,
        log_config=log_config,
        access_log=True,
        loop="uvloop",  # High-performance event loop
        http="httptools",  # High-performance HTTP parser
        workers=1,  # Single worker for WebSocket support
        timeout_keep_alive=30,
        timeout_graceful_shutdown=30
    )