from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import time
import logging
from contextlib import asynccontextmanager

from .utils.config import get_settings
from .utils.database import DatabaseManager
from .routers.v1 import ohlcv, trades, news
from .schemas.market_data import ErrorResponse
from .services.redis_optimizer import TradingRedisService
from .utils.databento_client import DatabentoClient
from .services.data_ingestion import DataIngestionService
from .utils.database import get_db
from sqlalchemy import text


from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, generate_latest
from contextlib import asynccontextmanager
import structlog

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
# Metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')

# Initialize services
settings = get_settings()
redis_service = TradingRedisService()
# Database manager instance
db_manager = DatabaseManager(settings)

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting TradeSage Market Data API...")
    
    try:
        # Initialize database and Redis
        await db_manager.initialize()
        logger.info("Database tables created successfully")
        await redis_service.connect()
        logger.info("Redis connection established")

        # Run initial data ingestion
        logger.info("Starting initial data ingestion...")
        db_session = next(get_db())

        # TEMPORARY: Clear old incorrect symbol data before ingestion
        logger.info("Clearing existing symbols table to ensure fresh data...")
        db_session.execute(text("TRUNCATE TABLE symbols RESTART IDENTITY CASCADE;"))
        db_session.commit()
        logger.info("Symbols table cleared.")

        databento_client = DatabentoClient(api_key=settings.DATABENTO_API_KEY)
        ingestion_service = DataIngestionService(databento_client=databento_client, db=db_session)
        
        # Ingest symbols for a default dataset
        dataset = "GLBX.MDP3" # Example dataset
        ingested_count = await ingestion_service.ingest_symbols(dataset)
        logger.info(f"Initial symbol ingestion complete. Ingested {ingested_count} new symbols for {dataset}.")
        db_session.close()

    except Exception as e:
        logger.error(f"An error occurred during startup: {e}")
        # Depending on the severity, you might want to re-raise the exception
        # to prevent the application from starting in a broken state.
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down TradeSage Market Data API...")

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Advanced market data API for TradeSage trading platform",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for your frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    REQUEST_COUNT.labels(request.method, request.url.path).inc()
    REQUEST_DURATION.observe(process_time)
    
    return response

# Include routers
app.include_router(ohlcv.router, prefix=settings.API_V1_STR)
app.include_router(trades.router, prefix=settings.API_V1_STR)
app.include_router(news.router, prefix=settings.API_V1_STR)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            message="Internal server error",
            details={"error": str(exc)} if settings.DEBUG else None
        ).dict()
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.VERSION,
        "app": settings.APP_NAME
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.VERSION,
        "docs_url": "/docs",
        "health_check": "/health",
        "api_base": settings.API_V1_STR
    }

@app.get("/metrics")
def metrics():
    return generate_latest()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8002,
        reload=settings.DEBUG,
        log_level="info"
    )
    