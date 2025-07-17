from typing import Dict, Any, Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator  # FIXED: Updated import for Pydantic v2
import structlog
import asyncio
from datetime import datetime, timezone, timedelta
import os
import multiprocessing
from pathlib import Path

class ProductionSettings(BaseSettings):
    """Production-grade configuration with comprehensive settings"""
    
    # ==================== Application Settings ====================
    APP_NAME: str = "TradeSage Market Data API"
    APP_VERSION: str = "2.0.0"
    APP_DESCRIPTION: str = "Production-grade market data API for institutional trading platforms"
    DEBUG: bool = Field(default=False, description="Enable debug mode")
    
    # Environment
    ENVIRONMENT: str = Field(default="production", description="Runtime environment")
    
    # API Configuration
    API_V1_STR: str = "/api/v1"
    PORT: int = Field(default=8002, description="Server port")
    
    # ==================== Database Configuration ====================
    # FIXED: Changed to DATABASE_URL to match database.py expectations
    DATABASE_URL: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/postgres",
        description="Primary PostgreSQL connection string"
    )
    
    # Read replica (optional, falls back to primary)
    READ_REPLICA_URL: Optional[str] = Field(
        default=None, 
        description="Read replica PostgreSQL connection string"
    )
    
    # Database pool settings
    DB_POOL_SIZE: int = Field(default=20, description="Database connection pool size")
    DB_MAX_OVERFLOW: int = Field(default=40, description="Database max overflow connections")
    DB_POOL_TIMEOUT: int = Field(default=30, description="Database pool timeout in seconds")
    DB_POOL_RECYCLE: int = Field(default=3600, description="Database pool recycle time in seconds")
    
    # Query settings
    DB_QUERY_TIMEOUT: int = Field(default=30, description="Database query timeout in seconds")
    DB_STATEMENT_TIMEOUT: int = Field(default=60, description="Database statement timeout in seconds")
    
    # ==================== Redis Configuration ====================
    # Single Redis instance
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string"
    )
    
    # FIXED: No default value to properly detect cluster mode
    REDIS_CLUSTER_NODES: Optional[str] = Field(
        default=None, 
        description="Redis cluster nodes (host:port,host:port)"
    )
    
    # Redis connection settings
    REDIS_MAX_CONNECTIONS: int = Field(default=50, description="Redis max connections")
    REDIS_SOCKET_TIMEOUT: int = Field(default=10, description="Redis socket timeout")
    REDIS_SOCKET_CONNECT_TIMEOUT: int = Field(default=5, description="Redis socket connect timeout")
    REDIS_HEALTH_CHECK_INTERVAL: int = Field(default=30, description="Redis health check interval")
    
    # ==================== Data Source Configuration ====================
    # Databento API key (imported from .env)
    DATABENTO_API_KEY: Optional[str] = None
    
    # Datasets to process
    DATASETS: List[str] = Field(
        default=["XNAS.ITCH", "XNYS.PILLAR", "XASE.PILLAR", "BATS.PITCH"],
    )
    
    # Dataset start dates (earliest data availability)
    DATASET_START_DATES: Dict[str, str] = Field(
        default={
            "XNAS.ITCH": "2018-05-01",
            "OPRA.PILLAR": "2020-01-01",
            "XNYS.PILLAR": "2018-05-01",
            "GLBX.MDP3": "2010-01-01",
            "BATS.PITCH": "2018-05-01",
            "XASE.PILLAR": "2018-05-01",
        },
        description="Earliest available date per dataset"
    )
    
    # Timeframes to collect
    TIMEFRAMES: List[str] = Field(
         default=["ohlcv-1d"],
     )
    
    # ==================== Performance Configuration ====================
    # Ingestion settings
    BATCH_SIZE_SYMBOLS: int = Field(default=100, description="Symbol ingestion batch size")
    BATCH_SIZE_OHLCV: int = Field(default=10000, description="OHLCV ingestion batch size")
    BATCH_SIZE_TRADES: int = Field(default=5000, description="Trade ingestion batch size")
    
    # Concurrency limits
    MAX_CONCURRENT_REQUESTS: int = Field(default=10, description="Max concurrent API requests")
    MAX_CONCURRENT_DB_OPERATIONS: int = Field(default=20, description="Max concurrent DB operations")
    
    # Processing threads
    CPU_WORKER_THREADS: int = Field(default=4, description="CPU-bound worker threads")
    IO_WORKER_THREADS: int = Field(default=8, description="I/O-bound worker threads")
    
    # ==================== Caching Configuration ====================
    # L1 Cache (in-memory)
    L1_CACHE_PRICE_SIZE: int = Field(default=5000, description="L1 price cache size")
    L1_CACHE_OHLCV_SIZE: int = Field(default=2000, description="L1 OHLCV cache size")
    L1_CACHE_SYMBOLS_SIZE: int = Field(default=100, description="L1 symbols cache size")
    
    # FIXED: Centralized TTL calculation with consistent logic
    CACHE_TTL_REALTIME: int = Field(default=30, description="Real-time data cache TTL")
    CACHE_TTL_MINUTE: int = Field(default=300, description="Minute data cache TTL")
    CACHE_TTL_HOUR: int = Field(default=3600, description="Hour data cache TTL")
    CACHE_TTL_DAILY: int = Field(default=86400, description="Daily data cache TTL")
    CACHE_TTL_SYMBOLS: int = Field(default=3600, description="Symbols cache TTL")
    
    # Cache cleanup settings
    CACHE_CLEANUP_INTERVAL: int = Field(default=300, description="Cache cleanup interval in seconds")
    CACHE_EXPIRE_CHECK_INTERVAL: int = Field(default=60, description="Cache expiration check interval")
    
    # ==================== WebSocket Configuration ====================
    # Connection limits
    WS_MAX_CONNECTIONS: int = Field(default=10000, description="Max WebSocket connections")
    WS_MAX_SUBSCRIPTIONS_PER_CLIENT: int = Field(default=50, description="Max subscriptions per client")
    
    # Rate limiting
    WS_RATE_LIMIT_CONNECTIONS_PER_MINUTE: int = Field(default=60, description="WebSocket connection rate limit")
    WS_RATE_LIMIT_MESSAGES_PER_MINUTE: int = Field(default=1000, description="WebSocket message rate limit")
    
    # Timeouts
    WS_HEARTBEAT_TIMEOUT: int = Field(default=60, description="WebSocket heartbeat timeout")
    WS_CONNECTION_TIMEOUT: int = Field(default=300, description="WebSocket connection timeout")
    
    # Message queue settings
    WS_MESSAGE_QUEUE_SIZE: int = Field(default=10000, description="WebSocket message queue size")
    WS_BROADCAST_BATCH_SIZE: int = Field(default=100, description="WebSocket broadcast batch size")
    
    # ==================== Circuit Breaker Configuration ====================
    # Databento API circuit breaker
    DATABENTO_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(default=3, description="Databento circuit breaker failure threshold")
    DATABENTO_CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = Field(default=120, description="Databento circuit breaker recovery timeout")
    
    # Database circuit breaker
    DATABASE_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(default=5, description="Database circuit breaker failure threshold")
    DATABASE_CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = Field(default=60, description="Database circuit breaker recovery timeout")
    
    # Redis circuit breaker
    REDIS_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(default=3, description="Redis circuit breaker failure threshold")
    REDIS_CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = Field(default=30, description="Redis circuit breaker recovery timeout")
    
    # ==================== Security Configuration ====================
    # CORS settings
    CORS_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:8080,https://tradesage.com",
    )
    
    # API Keys and authentication
    API_KEY_HEADER: str = Field(default="X-API-Key", description="API key header name")
    JWT_SECRET_KEY: Optional[str] = Field(default=None, description="JWT secret key")
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT algorithm")
    JWT_EXPIRATION_HOURS: int = Field(default=24, description="JWT expiration in hours")
    
    # Rate limiting (requests per minute)
    RATE_LIMIT_PER_MINUTE: int = Field(default=1000, description="API rate limit per minute")
    RATE_LIMIT_BURST: int = Field(default=100, description="API rate limit burst")
    
    # ==================== Monitoring Configuration ====================
    # Metrics collection
    ENABLE_METRICS: bool = Field(default=True, description="Enable Prometheus metrics")
    METRICS_PATH: str = Field(default="/metrics", description="Metrics endpoint path")
    
    # Logging configuration
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FORMAT: str = Field(default="json", description="Log format (json/text)")
    LOG_FILE: Optional[str] = Field(default=None, description="Log file path (optional)")
    
    # Health check settings
    HEALTH_CHECK_TIMEOUT: int = Field(default=10, description="Health check timeout")
    HEALTH_CHECK_INTERVAL: int = Field(default=30, description="Health check interval")
    
    # ==================== Data Retention Configuration ====================
    # Database retention
    DATA_RETENTION_DAYS: int = Field(default=365, description="Data retention in days")
    ARCHIVE_AFTER_DAYS: int = Field(default=90, description="Archive data after days")
    
    # Cache retention
    CACHE_MAX_MEMORY_MB: int = Field(default=1024, description="Max cache memory in MB")
    CACHE_EVICTION_POLICY: str = Field(default="allkeys-lru", description="Cache eviction policy")
    
    # ==================== Startup Configuration ====================
    # Initial data loading
    ENABLE_STARTUP_INGESTION: bool = Field(default=True, description="Enable startup data ingestion")
    STARTUP_INGESTION_DAYS: int = Field(default=7, description="Days of data to ingest on startup")
    
    # Cache warming
    ENABLE_CACHE_WARMING: bool = Field(default=True, description="Enable cache warming on startup")
    CACHE_WARM_SYMBOLS: List[str] = Field(
        default=["AAPL", "MSFT", "GOOGL", "AMZN", "TSLA", "META", "NVDA", "NFLX"],
        description="Symbols to warm in cache on startup"
    )
    
    # Background tasks
    ENABLE_BACKGROUND_TASKS: bool = Field(default=True, description="Enable background processing tasks")
    BACKGROUND_TASK_INTERVAL: int = Field(default=300, description="Background task interval in seconds")

    # ==================== Ingestion Schedule Configuration ====================
    HISTORICAL_START_DATE: str = Field(default="2010-01-01", description="Global historical start date for backfill")
    INCREMENTAL_UPDATE_CRON: str = Field(default="0 */1 * * *", description="Cron string for incremental updates")
    SYMBOL_REFRESH_CRON: str = Field(default="0 6 * * *", description="Cron string for symbol refresh")
    MAINTENANCE_CRON: str = Field(default="0 2 * * 0", description="Cron string for maintenance tasks")
    MAX_CONCURRENT_DATASETS: int = Field(default=3, description="Max datasets processed concurrently")
    PAUSE_BETWEEN_DATASETS_SECONDS: int = Field(default=30, description="Pause between dataset ingestion batches")
    
    # ==================== TradingView Configuration ====================
    # TradingView compatibility settings
    TRADINGVIEW_SUPPORTED_RESOLUTIONS: List[str] = Field(
        default=["1", "5", "15", "30", "60", "240", "1D", "1W"],
        description="TradingView supported resolutions"
    )
    
    TRADINGVIEW_MAX_BARS: int = Field(default=5000, description="Max bars per TradingView request")
    TRADINGVIEW_EXCHANGES: List[Dict[str, str]] = Field(
        default=[
            {"value": "NASDAQ", "name": "NASDAQ", "desc": "NASDAQ"},
            {"value": "NYSE", "name": "NYSE", "desc": "New York Stock Exchange"}
        ],
        description="TradingView exchanges configuration"
    )
    
    # ==================== Advanced Configuration ====================
    # Feature flags
    ENABLE_REAL_TIME_PROCESSING: bool = Field(default=True, description="Enable real-time data processing")
    ENABLE_TRADE_DATA_INGESTION: bool = Field(default=True, description="Enable trade data ingestion")
    ENABLE_NEWS_DATA_INGESTION: bool = Field(default=False, description="Enable news data ingestion")
    ENABLE_TECHNICAL_INDICATORS: bool = Field(default=True, description="Enable technical indicators calculation")
    
    # Experimental features
    ENABLE_MACHINE_LEARNING: bool = Field(default=False, description="Enable ML-based features")
    ENABLE_PREDICTIVE_CACHING: bool = Field(default=False, description="Enable predictive caching")
    ENABLE_AUTO_SCALING: bool = Field(default=False, description="Enable auto-scaling features")
    
    # ==================== Deployment Configuration ====================
    # Container settings
    CONTAINER_NAME: str = Field(default="tradesage-market-data", description="Container name")
    NAMESPACE: str = Field(default="default", description="Kubernetes namespace")
    
    # Service mesh
    ENABLE_SERVICE_MESH: bool = Field(default=False, description="Enable service mesh integration")
    ISTIO_ENABLED: bool = Field(default=False, description="Enable Istio service mesh")
    
    # Observability
    JAEGER_ENDPOINT: Optional[str] = Field(default=None, description="Jaeger tracing endpoint")
    ENABLE_DISTRIBUTED_TRACING: bool = Field(default=False, description="Enable distributed tracing")
    
    # ==================== Validators (FIXED for Pydantic v2) ====================
    @field_validator('LOG_LEVEL')
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'LOG_LEVEL must be one of {valid_levels}')
        return v.upper()
    
    @field_validator('ENVIRONMENT')
    @classmethod
    def validate_environment(cls, v: str) -> str:
        valid_envs = ['development', 'staging', 'production']
        if v.lower() not in valid_envs:
            raise ValueError(f'ENVIRONMENT must be one of {valid_envs}')
        return v.lower()
    
    @field_validator('CACHE_EVICTION_POLICY')
    @classmethod
    def validate_cache_policy(cls, v: str) -> str:
        valid_policies = ['allkeys-lru', 'volatile-lru', 'allkeys-random', 'volatile-random', 'volatile-ttl', 'noeviction']
        if v not in valid_policies:
            raise ValueError(f'CACHE_EVICTION_POLICY must be one of {valid_policies}')
        return v
    
    # ==================== Computed Properties ====================
    @property
    def VERSION(self) -> str:
        """Backward compatibility property"""
        return self.APP_VERSION
    
    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.ENVIRONMENT == 'production'
    
    @property
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.ENVIRONMENT == 'development'
    
    @property
    def redis_cluster_enabled(self) -> bool:
        """Check if Redis cluster is enabled"""
        return bool(self.REDIS_CLUSTER_NODES)
    
    @property
    def database_read_replica_enabled(self) -> bool:
        """Check if read replica is configured"""
        return bool(self.READ_REPLICA_URL)
    
    # ==================== Cache TTL Mapping (FIXED: Consistent logic) ====================
    def get_cache_ttl(self, timeframe: str) -> int:
        """Get appropriate cache TTL for timeframe with consistent logic"""
        base_ttl_mapping = {
            'ohlcv-1s': self.CACHE_TTL_REALTIME,
            'ohlcv-1m': self.CACHE_TTL_MINUTE,
            'ohlcv-5m': self.CACHE_TTL_MINUTE,
            'ohlcv-15m': self.CACHE_TTL_MINUTE * 2,
            'ohlcv-30m': self.CACHE_TTL_MINUTE * 3,
            'ohlcv-1h': self.CACHE_TTL_HOUR,
            'ohlcv-4h': self.CACHE_TTL_HOUR * 2,
            'ohlcv-1d': self.CACHE_TTL_DAILY,
            'ohlcv-1w': self.CACHE_TTL_DAILY * 2,
            'symbols': self.CACHE_TTL_SYMBOLS,
            'price': self.CACHE_TTL_REALTIME,
            'trades': self.CACHE_TTL_MINUTE
        }
        return base_ttl_mapping.get(timeframe, self.CACHE_TTL_MINUTE)
    
    # ==================== Database URL Processing (FIXED) ====================
    def get_database_urls(self) -> Dict[str, str]:
        """Get processed database URLs"""
        urls = {
            'primary': self.DATABASE_URL,
            'read_replica': self.READ_REPLICA_URL or self.DATABASE_URL
        }
        
        # Add asyncpg support if not present
        for key, url in urls.items():
            if url and 'postgresql://' in url and '+asyncpg' not in url:
                urls[f'{key}_async'] = url.replace('postgresql://', 'postgresql+asyncpg://')
            else:
                urls[f'{key}_async'] = url
        
        return urls
    
    # ==================== Configuration Validation ====================
    def validate_configuration(self) -> List[str]:
        """Validate configuration and return warnings"""
        warnings = []
        
        # Production checks
        if self.is_production:
            if self.DEBUG:
                warnings.append("DEBUG mode is enabled in production")
            
            if self.JWT_SECRET_KEY is None:
                warnings.append("JWT_SECRET_KEY is not set in production")
            
            if not self.redis_cluster_enabled:
                warnings.append("Redis cluster is not configured for production")
            
            if not self.database_read_replica_enabled:
                warnings.append("Database read replica is not configured for production")
        
        # Performance checks
        if self.DB_POOL_SIZE < 10:
            warnings.append("Database pool size might be too small for production load")
        
        if self.REDIS_MAX_CONNECTIONS < 20:
            warnings.append("Redis max connections might be too small for production load")
        
        # Security checks
        if self.CORS_ORIGINS == "*":
            warnings.append("CORS is configured to allow all origins")
        
        return warnings
    
    # ==================== Environment-Specific Defaults ====================
    def apply_environment_defaults(self):
        """Apply environment-specific defaults"""
        if self.is_production:
            # Production optimizations
            self.DEBUG = False
            self.LOG_LEVEL = "INFO"
            self.ENABLE_STARTUP_INGESTION = True
            self.ENABLE_CACHE_WARMING = True
            
        elif self.is_development:
            # Development conveniences
            self.LOG_LEVEL = "DEBUG"
            self.ENABLE_STARTUP_INGESTION = False
            self.CACHE_TTL_MINUTE = 60  # Shorter cache for development
        
        # -------- Dynamic DB pool tuning (CPU aware) --------
        cpu = multiprocessing.cpu_count()
        default_pool = max(5, cpu * 2)
        if self.DB_POOL_SIZE == 20:  # unchanged from default
            self.DB_POOL_SIZE = default_pool
        if self.DB_MAX_OVERFLOW == 40:  # unchanged from default
            self.DB_MAX_OVERFLOW = default_pool
    
    class Config:
        # Always load the .env that sits in the root of the market_data package
        env_file = str((Path(__file__).resolve().parents[2] / ".env"))
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"
        
        # Allow field validation
        validate_assignment = True
        
        # JSON schema
        schema_extra = {
            "example": {
                "APP_NAME": "TradeSage Market Data API",
                "ENVIRONMENT": "production",
                "DEBUG": False,
                "DATABASE_URL": "postgresql://user:pass@localhost:5432/tradesage",
                "REDIS_URL": "redis://localhost:6379/0",
                "DATABENTO_API_KEY": "<your-api-key>"
            }
        }

# ==================== Singleton Pattern ====================

_settings_instance: Optional[ProductionSettings] = None

def get_settings() -> ProductionSettings:
    """Get singleton settings instance"""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = ProductionSettings()
        _settings_instance.apply_environment_defaults()
        
        # Log configuration warnings
        warnings = _settings_instance.validate_configuration()
        if warnings:
            logger = structlog.get_logger(__name__)
            for warning in warnings:
                logger.warning("Configuration warning", warning=warning)
    
    return _settings_instance

def reload_settings() -> ProductionSettings:
    """Reload settings (useful for testing)"""
    global _settings_instance
    _settings_instance = None
    return get_settings()

# ==================== Configuration Export ====================

# Backward compatibility aliases
settings = get_settings()

# Environment-specific configurations
def get_development_settings() -> ProductionSettings:
    """Get development-specific settings"""
    os.environ['ENVIRONMENT'] = 'development'
    return reload_settings()

def get_production_settings() -> ProductionSettings:
    """Get production-specific settings"""
    os.environ['ENVIRONMENT'] = 'production'
    return reload_settings()

def get_testing_settings() -> ProductionSettings:
    """Get testing-specific settings"""
    os.environ['ENVIRONMENT'] = 'testing'
    os.environ['DEBUG'] = 'true'
    return reload_settings()

# ==================== Configuration Utilities ====================

def print_configuration_summary():
    """Print a summary of current configuration"""
    config = get_settings()
    
    print("=" * 60)
    print(f"TradeSage Market Data API Configuration")
    print("=" * 60)
    print(f"Environment: {config.ENVIRONMENT}")
    print(f"Version: {config.APP_VERSION}")
    print(f"Debug Mode: {config.DEBUG}")
    print(f"Database Pool Size: {config.DB_POOL_SIZE}")
    print(f"Redis Cluster: {'Enabled' if config.redis_cluster_enabled else 'Disabled'}")
    print(f"Read Replica: {'Enabled' if config.database_read_replica_enabled else 'Disabled'}")
    print(f"Max Concurrent Requests: {config.MAX_CONCURRENT_REQUESTS}")
    print(f"Cache TTL (Minute): {config.CACHE_TTL_MINUTE}s")
    print(f"WebSocket Max Connections: {config.WS_MAX_CONNECTIONS}")
    print("=" * 60)

def export_configuration_to_file(filepath: str):
    """Export current configuration to a file"""
    config = get_settings()
    
    config_dict = {}
    for field_name, field in config.__fields__.items():
        value = getattr(config, field_name)
        config_dict[field_name] = {
            'value': value,
            'description': field.field_info.description,
            'default': field.default
        }
    
    import json
    with open(filepath, 'w') as f:
        json.dump(config_dict, f, indent=2, default=str)

if __name__ == "__main__":
    # Configuration validation script
    print_configuration_summary()
    
    # Validate configuration
    config = get_settings()
    warnings = config.validate_configuration()
    
    if warnings:
        print("\nConfiguration Warnings:")
        for warning in warnings:
            print(f"⚠️  {warning}")
    else:
        print("\n✅ Configuration validation passed")