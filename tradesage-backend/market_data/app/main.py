from fastapi import FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import time
import logging
from contextlib import asynccontextmanager
import asyncio
from typing import Dict, Any, Set, Optional
import uvicorn
import signal
import sys
import os
from dataclasses import dataclass

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

# Import the continuous ingestion orchestrator
from .services.continuous_orchestrator import (
    ContinuousDataOrchestrator,
    DatasetConfig,
    IngestionSchedule
)

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import structlog
import traceback
import inspect

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
CONTINUOUS_INGESTION_STATUS = Gauge('continuous_ingestion_active', 'Continuous ingestion process status')
BACKFILL_PROGRESS = Gauge('historical_backfill_progress', 'Historical backfill progress percentage', ['dataset'])

@dataclass
class ServiceContainer:
    """Container for all application services"""
    db_manager: Optional[OptimizedDatabaseManager] = None
    redis_service: Optional[EnhancedTradingRedisService] = None
    websocket_manager: Optional[TradingViewWebSocketManager] = None
    data_storage_service: Optional[DataStorageService] = None
    ingestion_service: Optional[ProductionDataIngestionService] = None
    continuous_orchestrator: Optional[ContinuousDataOrchestrator] = None
    background_tasks: Set[asyncio.Task] = None
    
    def __post_init__(self):
        if self.background_tasks is None:
            self.background_tasks = set()

# Global service container
services = ServiceContainer()
settings = get_settings()

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
                func = check['func']
                # Support both sync and async health-check callables
                if inspect.iscoroutinefunction(func):
                    result = await func()
                else:
                    result = func()
                    
                results[name] = {
                    'status': 'healthy' if result.get('status') in ('ok', 'healthy') else 'unhealthy',
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

class ServiceInitializer:
    """Handles service initialization and cleanup"""
    
    @staticmethod
    async def initialize_core_services() -> list:
        """Initialize core services and return list of initialized services"""
        initialized_services = []
        
        try:
            # 1. Initialize optimized database manager
            logger.info("📊 Initializing optimized database manager...")
            services.db_manager = OptimizedDatabaseManager(settings)
            await services.db_manager.initialize()
            
            # Ensure global singleton is set for other modules
            import app.utils.database as _db_mod
            _db_mod._db_manager = services.db_manager
            initialized_services.append('db_manager')
            logger.info("✅ Database manager initialized")
            
            # 2. Initialize enhanced Redis service
            logger.info("🔄 Initializing enhanced Redis service...")
            services.redis_service = EnhancedTradingRedisService(settings.REDIS_URL)
            await services.redis_service.connect()
            initialized_services.append('redis_service')
            logger.info("✅ Redis service initialized")
            
            # 3. Initialize data storage service
            logger.info("💾 Initializing data storage service...")
            db_session = services.db_manager.get_sync_session()
            services.data_storage_service = DataStorageService(db_session, services.redis_service.redis_client)
            initialized_services.append('data_storage_service')
            logger.info("✅ Data storage service initialized")
            
            # 4. Initialize WebSocket manager
            logger.info("🌐 Initializing WebSocket manager...")
            services.websocket_manager = TradingViewWebSocketManager(services.redis_service, services.data_storage_service)
            initialized_services.append('websocket_manager')
            logger.info("✅ WebSocket manager initialized")
            
            # 5. Initialize production data ingestion service
            logger.info("⚡ Initializing production data ingestion service...")
            databento_client = DatabentoClient()
            services.ingestion_service = ProductionDataIngestionService(
                databento_client=databento_client,
                db_manager=services.db_manager,
                redis_service=services.redis_service,
                websocket_manager=services.websocket_manager
            )
            await services.ingestion_service.start_background_processing()
            initialized_services.append('ingestion_service')
            logger.info("✅ Production data ingestion service initialized")
            
            # 6. Initialize continuous data orchestrator
            if getattr(settings, 'ENABLE_CONTINUOUS_INGESTION', True):
                logger.info("🔄 Initializing continuous data orchestrator...")
                # Build dataset configurations from central settings to avoid duplication
                datasets = [
                    DatasetConfig(
                        dataset_code=ds,
                        timeframes=settings.TIMEFRAMES,
                        priority=1 if idx < 2 else 2,
                        update_frequency_minutes=60,
                        max_symbols_per_batch=settings.BATCH_SIZE_SYMBOLS,
                        backfill_chunk_days=30,
                        is_active=True
                    )
                    for idx, ds in enumerate(settings.DATASETS)
                ]
                schedule_config = IngestionSchedule(
                    historical_start_date="2010-01-01",
                    incremental_update_cron="0 */1 * * *",
                    symbol_refresh_cron="0 6 * * *",
                    maintenance_cron="0 2 * * 0",
                    max_concurrent_datasets=3,
                    pause_between_datasets_seconds=30
                )
                
                services.continuous_orchestrator = ContinuousDataOrchestrator(
                    ingestion_service=services.ingestion_service,
                    datasets_config=datasets,
                    schedule_config=schedule_config
                )
                
                # Start continuous ingestion
                await services.continuous_orchestrator.start_continuous_ingestion()
                initialized_services.append('continuous_orchestrator')
                logger.info("✅ Continuous data orchestrator initialized and started")
                CONTINUOUS_INGESTION_STATUS.set(1)
            
            return initialized_services
            
        except Exception as e:
            logger.error(f"Service initialization failed: {e}")
            await ServiceInitializer.cleanup_services(initialized_services)
            raise
    
    @staticmethod
    async def register_health_checks():
        """Register all health checks"""
        await health_manager.register_check("database", services.db_manager.health_check, critical=True)
        await health_manager.register_check("redis", lambda: {"status": "ok"}, critical=True)
        await health_manager.register_check("websocket", 
            lambda: {"status": "ok", "connections": len(services.websocket_manager.clients)}, 
            critical=False)
        
        if services.continuous_orchestrator:
            await health_manager.register_check("continuous_ingestion",
                lambda: {"status": "ok" if services.continuous_orchestrator.state.is_running else "stopped",
                        "mode": services.continuous_orchestrator.state.mode.value},
                critical=False)
    
    @staticmethod
    async def perform_initial_data_loading():
        """Perform initial data loading if enabled"""
        if not getattr(settings, 'ENABLE_STARTUP_INGESTION', True):
            return
            
        logger.info("🔄 Starting initial data ingestion...")
        try:
            # Ingest symbols for all datasets
            datasets = settings.DATASETS
            symbol_results = await services.ingestion_service.ingest_symbols_parallel(datasets)
            total_symbols = sum(symbol_results.values())
            logger.info(f"✅ Initial symbol ingestion completed: {total_symbols} symbols")
            
            # Warm cache for popular symbols
            if total_symbols > 0:
                popular_symbols = getattr(settings, 'CACHE_WARM_SYMBOLS', ['AAPL', 'TSLA', 'MSFT'])
                await services.redis_service.warm_cache_for_symbols(popular_symbols)
                logger.info("✅ Cache warmed for popular symbols")
                
        except Exception as e:
            logger.error(f"❌ Initial data ingestion failed: {e}")
            # Don't fail startup for ingestion errors
    
    @staticmethod
    async def start_background_tasks():
        """Start background tasks"""
        # Start background metrics collection
        task1 = asyncio.create_task(BackgroundTasks.update_metrics_periodically())
        services.background_tasks.add(task1)
        
        # Start background cache cleanup
        task2 = asyncio.create_task(BackgroundTasks.periodic_cache_cleanup())
        services.background_tasks.add(task2)
        
        # Start continuous ingestion monitoring
        if services.continuous_orchestrator:
            task3 = asyncio.create_task(BackgroundTasks.monitor_continuous_ingestion())
            services.background_tasks.add(task3)
        
        logger.info(f"✅ Started {len(services.background_tasks)} background tasks")
    
    @staticmethod
    async def cleanup_services(initialized_services: list):
        """Cleanup services in reverse order of initialization"""
        try:
            # Cancel background tasks first
            logger.info("🔄 Cancelling background tasks...")
            for task in services.background_tasks:
                task.cancel()
            
            if services.background_tasks:
                await asyncio.gather(*services.background_tasks, return_exceptions=True)
                services.background_tasks.clear()
                logger.info("✅ Background tasks cancelled")
            
            # Stop services in reverse order
            if 'continuous_orchestrator' in initialized_services and services.continuous_orchestrator:
                await services.continuous_orchestrator.stop_continuous_ingestion()
                logger.info("✅ Continuous data orchestrator stopped")
                CONTINUOUS_INGESTION_STATUS.set(0)
            
            if 'ingestion_service' in initialized_services and services.ingestion_service:
                await services.ingestion_service.close()
                logger.info("✅ Data ingestion service shutdown complete")
            
            if 'websocket_manager' in initialized_services and services.websocket_manager:
                await services.websocket_manager.shutdown()
                logger.info("✅ WebSocket manager shutdown")
            
            if 'data_storage_service' in initialized_services and services.data_storage_service:
                if hasattr(services.data_storage_service, 'close'):
                    services.data_storage_service.close()
                logger.info("✅ Data storage service closed")
            
            if 'redis_service' in initialized_services and services.redis_service:
                await services.redis_service.redis_client.aclose()
                logger.info("✅ Redis connections closed")
            
            if 'db_manager' in initialized_services and services.db_manager:
                await services.db_manager.close()
                logger.info("✅ Database connections closed")
            
        except Exception as e:
            logger.error(f"❌ Shutdown error: {e}")

class BackgroundTasks:
    """Container for background task functions"""
    
    @staticmethod
    async def update_metrics_periodically():
        """Background task to update metrics periodically"""
        while True:
            try:
                await asyncio.sleep(30)  # Update every 30 seconds
                
                # Update continuous ingestion metrics
                if services.continuous_orchestrator:
                    status = services.continuous_orchestrator.get_orchestrator_status()
                    
                    # Update progress metrics for each dataset
                    progress = status.get('progress', {})
                    for dataset, info in progress.items():
                        backfill_progress = info.get('backfill_progress', 0)
                        BACKFILL_PROGRESS.labels(dataset=dataset).set(backfill_progress)

                # Update DB pool utilisation metric
                if services.db_manager:
                    try:
                        pool_stats = services.db_manager.get_connection_stats()
                        if 'read_pool' in pool_stats and 'used' in pool_stats['read_pool']:
                            used_connections = pool_stats['read_pool']['used']
                            if isinstance(used_connections, (int, float)):
                                DATABASE_CONNECTIONS.set(used_connections)
                            else:
                                logger.debug(f"Invalid connection count type: {type(used_connections)}")
                        else:
                            logger.debug("Pool stats missing expected keys")
                    except Exception as pool_exc:
                        logger.debug(f"Failed to update DB pool metrics: {pool_exc}")
                    

                
            except asyncio.CancelledError:
                logger.info("Metrics update task cancelled")
                break
            except Exception as e:
                logger.error(f"Metrics update error: {e}")
                await asyncio.sleep(60)
    
    @staticmethod
    async def periodic_cache_cleanup():
        """Background task for periodic cache cleanup"""
        while True:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                
                if services.redis_service:
                    await services.redis_service.cleanup_expired_keys()
                    logger.debug("Periodic cache cleanup completed")
                    
            except asyncio.CancelledError:
                logger.info("Cache cleanup task cancelled")
                break
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")
                await asyncio.sleep(300)
    
    @staticmethod
    async def monitor_continuous_ingestion():
        """Monitor continuous ingestion process"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                if services.continuous_orchestrator:
                    status = services.continuous_orchestrator.get_orchestrator_status()
                    
                    # Log status periodically
                    if hasattr(BackgroundTasks, '_last_status_log'):
                        time_since_last = time.time() - BackgroundTasks._last_status_log
                        if time_since_last > 300:  # Log every 5 minutes
                            logger.info(f"Continuous ingestion status: {status['state']['mode']}")
                            BackgroundTasks._last_status_log = time.time()
                    else:
                        BackgroundTasks._last_status_log = time.time()
                    
                    # Update metrics
                    CONTINUOUS_INGESTION_STATUS.set(1 if status['state']['is_running'] else 0)
                    
            except asyncio.CancelledError:
                logger.info("Continuous ingestion monitor cancelled")
                break
            except Exception as e:
                logger.error(f"Continuous ingestion monitor error: {e}")
                await asyncio.sleep(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Enhanced application lifespan with better organization"""
    logger.info("🚀 Starting TradeSage Market Data API (Production Mode)...")
    
    initialized_services = []
    
    try:
        # Initialize core services
        initialized_services = await ServiceInitializer.initialize_core_services()
        
        # Register health checks
        await ServiceInitializer.register_health_checks()
        
        # Perform initial data loading
        await ServiceInitializer.perform_initial_data_loading()
        
        # Start background tasks
        await ServiceInitializer.start_background_tasks()
        
        logger.info("🎉 TradeSage Market Data API started successfully!")
        logger.info(f"📊 Database pools: Read={services.db_manager.read_pool.get_size()}, Write={services.db_manager.write_pool.get_size()}")
        logger.info(f"🔄 Redis connections: {services.redis_service.redis_client}")
        logger.info(f"🌐 WebSocket manager ready for connections")
        
        if services.continuous_orchestrator:
            logger.info("🔄 Continuous data ingestion is running (2010 → present)")
        
    except Exception as e:
        logger.error(f"💥 Startup failed: {e}")
        logger.error(traceback.format_exc())
        await ServiceInitializer.cleanup_services(initialized_services)
        raise
    
    # App is running
    yield
    
    # Shutdown sequence
    logger.info("🛑 Shutting down TradeSage Market Data API...")
    await ServiceInitializer.cleanup_services(initialized_services)
    logger.info("👋 TradeSage Market Data API shutdown complete")

# Create FastAPI app with enhanced configuration
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Production-grade market data API with continuous data ingestion from 2010 to present",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# ----------------------- Middleware Configuration -----------------------

# CORS middleware with production settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],#getattr(settings, 'CORS_ORIGINS', "*").split(",") if hasattr(settings, 'CORS_ORIGINS') else ["*"],
    allow_credentials=True,
    allow_methods=["*"],#["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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
        client_id = await services.websocket_manager.connect_client(websocket)
        WEBSOCKET_CONNECTIONS.inc()
        
        logger.info(f"WebSocket client connected: {client_id}")
        
        # Handle messages
        while True:
            try:
                message = await websocket.receive_text()
                await services.websocket_manager.handle_message(client_id, message)
                
            except WebSocketDisconnect:
                logger.info(f"WebSocket client disconnected: {client_id}")
                break
                
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {e}")
        
    finally:
        if client_id:
            await services.websocket_manager.disconnect_client(client_id)
            WEBSOCKET_CONNECTIONS.dec()

# ----------------------- Include Enhanced Routers -----------------------

app.include_router(ohlcv.router, prefix=settings.API_V1_STR, tags=["OHLCV Data"])
app.include_router(trades.router, prefix=settings.API_V1_STR, tags=["Trade Data"])
app.include_router(news.router, prefix=settings.API_V1_STR, tags=["News Data"])

# ----------------------- Continuous Ingestion Control Endpoints -----------------------

@app.get("/api/v1/ingestion/status")
async def get_ingestion_status():
    """Get comprehensive ingestion status including continuous orchestrator"""
    try:
        base_stats = services.ingestion_service.get_ingestion_stats()
        
        if services.continuous_orchestrator:
            orchestrator_status = services.continuous_orchestrator.get_orchestrator_status()
            return {
                "ingestion_service": base_stats,
                "continuous_orchestrator": orchestrator_status,
                "combined_status": {
                    "is_running": orchestrator_status['state']['is_running'],
                    "mode": orchestrator_status['state']['mode'],
                    "total_records_ingested": base_stats['metrics']['ohlcv_records_ingested'],
                    "datasets_processed": len(orchestrator_status['state']['active_datasets']),
                    "historical_backfill_progress": orchestrator_status['progress']
                }
            }
        else:
            return {"ingestion_service": base_stats}
            
    except Exception as e:
        logger.error(f"Error getting ingestion status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve ingestion status")

@app.post("/api/v1/ingestion/start")
async def start_ingestion():
    """Start continuous data ingestion (if not already running)"""
    try:
        if services.continuous_orchestrator and not services.continuous_orchestrator.state.is_running:
            await services.continuous_orchestrator.start_continuous_ingestion()
            CONTINUOUS_INGESTION_STATUS.set(1)
            return {"message": "Continuous data ingestion started", "status": "running"}
        else:
            return {"message": "Continuous data ingestion is already running", "status": "running"}
            
    except Exception as e:
        logger.error(f"Error starting ingestion: {e}")
        raise HTTPException(status_code=500, detail="Failed to start ingestion")

@app.post("/api/v1/ingestion/stop")
async def stop_ingestion():
    """Stop continuous data ingestion"""
    try:
        if services.continuous_orchestrator and services.continuous_orchestrator.state.is_running:
            await services.continuous_orchestrator.stop_continuous_ingestion()
            CONTINUOUS_INGESTION_STATUS.set(0)
            return {"message": "Continuous data ingestion stopped", "status": "stopped"}
        else:
            return {"message": "Continuous data ingestion is not running", "status": "stopped"}
            
    except Exception as e:
        logger.error(f"Error stopping ingestion: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop ingestion")

# ----------------------- TradingView Compatible Endpoints -----------------------

@app.get("/api/v1/tradingview/config")
async def tradingview_config():
    """TradingView configuration endpoint"""
    return {
        "supported_resolutions": getattr(settings, 'TRADINGVIEW_SUPPORTED_RESOLUTIONS', ["1", "5", "15", "30", "60", "240", "1D"]),
        "supports_group_request": False,
        "supports_marks": False,
        "supports_search": True,
        "supports_timescale_marks": False,
        "exchanges": getattr(settings, 'TRADINGVIEW_EXCHANGES', ["NASDAQ", "NYSE"]),
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
        symbols = await services.data_storage_service.get_symbols()
        
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
        df = services.data_storage_service.get_ohlcv_data(symbol, timeframe, start_date, end_date)
        
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
        if not services.db_manager or not services.redis_service:
            return JSONResponse(
                status_code=503,
                content={"ready": False, "reason": "Services not initialized"}
            )
        
        # Test database connection
        health_result = await services.db_manager.health_check()
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
    """Enhanced Prometheus metrics endpoint"""
    try:
        # Update dynamic metrics
        if services.db_manager:
            stats = services.db_manager.get_connection_stats()
            if 'read_pool' in stats:
                DATABASE_CONNECTIONS.set(stats['read_pool'].get('size', 0))
        
        if services.redis_service:
            cache_stats = services.redis_service.get_comprehensive_stats()
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
        
        if services.websocket_manager:
            ws_stats = services.websocket_manager.get_stats()
            WEBSOCKET_CONNECTIONS.set(ws_stats.get('active_clients', 0))
        
        if services.ingestion_service:
            ingestion_stats = services.ingestion_service.get_ingestion_stats()
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
    if not getattr(settings, 'DEBUG', False):
        raise HTTPException(status_code=404, detail="Not found")
    
    try:
        stats = {
            "timestamp": time.time(),
            "version": settings.APP_VERSION,
            "services": {}
        }
        
        if services.db_manager:
            stats["services"]["database"] = services.db_manager.get_connection_stats()
        
        if services.redis_service:
            stats["services"]["redis"] = services.redis_service.get_comprehensive_stats()
        
        if services.websocket_manager:
            stats["services"]["websocket"] = services.websocket_manager.get_stats()
        
        if services.ingestion_service:
            stats["services"]["ingestion"] = services.ingestion_service.get_ingestion_stats()
        
        if services.continuous_orchestrator:
            stats["services"]["continuous_orchestrator"] = services.continuous_orchestrator.get_orchestrator_status()
        
        return stats
        
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve stats")

@app.post("/admin/cache/invalidate")
async def admin_invalidate_cache(pattern: str = "*"):
    """Administrative cache invalidation endpoint"""
    if not getattr(settings, 'DEBUG', False):
        raise HTTPException(status_code=404, detail="Not found")
    
    try:
        await services.redis_service.invalidate_pattern(pattern)
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
    if getattr(settings, 'DEBUG', False):
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

# ----------------------- Root Endpoint -----------------------

@app.get("/")
async def root():
    """Enhanced root endpoint with service information"""
    continuous_status = None
    if services.continuous_orchestrator:
        orchestrator_status = services.continuous_orchestrator.get_orchestrator_status()
        continuous_status = {
            "is_running": orchestrator_status['state']['is_running'],
            "mode": orchestrator_status['state']['mode'],
            "datasets_processing": len(orchestrator_status['state']['active_datasets'])
        }
    
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "timestamp": time.time(),
        "continuous_ingestion": continuous_status,
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "docs": "/docs",
            "websocket": "/ws",
            "api": settings.API_V1_STR,
            "ingestion_status": "/api/v1/ingestion/status",
            "ingestion_control": {
                "start": "/api/v1/ingestion/start",
                "stop": "/api/v1/ingestion/stop"
            }
        },
        "features": [
            "Real-time WebSocket feeds",
            "TradingView integration", 
            "Multi-tier caching",
            "Prometheus metrics",
            "Continuous data ingestion (2010-present)",
            "Production-grade performance"
        ]
    }

# ----------------------- Graceful Shutdown -----------------------

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
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
        port=getattr(settings, 'PORT', 8005),
        reload=getattr(settings, 'DEBUG', False),
        log_config=log_config,
        access_log=True,
        loop="uvloop",  # High-performance event loop
        http="httptools",  # High-performance HTTP parser
        workers=1,  # Single worker for WebSocket support
        timeout_keep_alive=30,
        timeout_graceful_shutdown=30
    )