from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import structlog
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List
from dataclasses import dataclass

@dataclass
class settings(BaseSettings):
    # App settings
    APP_NAME:str = "Tradesage Market Data API"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Tradesage Market Data API"

    API_V1_STR: str = "/api/v1"
    DATABENTO_API_KEY: str = os.getenv('DATABENTO_API_KEY', 'db-Jn7AnuuRLtWXAKBFp59Y4hbAvXKta')
    
    # PostgreSQL
    POSTGRES_HOST: str = os.getenv('POSTGRES_HOST', 'localhost')
    POSTGRES_PORT: int = int(os.getenv('POSTGRES_PORT', '5432'))
    POSTGRES_DB: str = os.getenv('POSTGRES_DB', 'market_data')
    POSTGRES_USER: str = os.getenv('POSTGRES_USER', 'postgres')
    POSTGRES_PASSWORD: str = os.getenv('POSTGRES_PASSWORD', 'password')
    
    # Data settings
    DATASETS: List[str] = ['XNAS.ITCH', 'XNYS.PILLAR', 'XASE.PILLAR', 'BATS.PITCH']
    TIMEFRAMES: List[str] = ['ohlcv-1s', 'ohlcv-1m', 'ohlcv-1h', 'ohlcv-1d']
    BATCH_SIZE: int = 1000
    MAX_RETRIES: int = 3

    # Redis
    REDIS_HOST: str = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT: int = int(os.getenv('REDIS_PORT', '6379'))
    REDIS_DB: int = int(os.getenv('REDIS_DB', '0'))
    REDIS_PASSWORD: str = os.getenv('REDIS_PASSWORD', None)
    
    # Data settings
    DATASETS: List[str] = ['XNAS.ITCH', 'XNYS.PILLAR', 'XASE.PILLAR', 'BATS.PITCH']
    TIMEFRAMES: List[str] = ['ohlcv-1s', 'ohlcv-1m', 'ohlcv-1h', 'ohlcv-1d']
    BATCH_SIZE: int = 1000
    MAX_RETRIES: int = 3
    
    # Cache settings
    CACHE_TTL: int = 300  # 5 minutes for real-time data
    DAILY_CACHE_TTL: int = 3600  # 1 hour for daily data
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    
    # Data processing settings
    ENABLE_FILE_BACKUP: bool = False  # Only for disaster recovery
    BACKUP_DIR: str = "/app/backups"  # Only if backup enabled
    DATA_RETENTION_DAYS: int = 365    # How long to keep data in DB
    
    class Config:
        env_file = ".env"
        case_sensitive = True

_settings = None

def get_settings() -> settings:
    global _settings
    if _settings is None:
        _settings = settings()
    return _settings


