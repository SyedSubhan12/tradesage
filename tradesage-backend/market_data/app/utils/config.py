from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import structlog
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List

import os
class Settings(BaseSettings):
    # App settings
    APP_NAME:str = "Tradesage Market Data API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = bool(os.getenv('DEBUG', 'false').lower() == 'true')

    # Backwards-compat convenience attribute
    @property
    def VERSION(self) -> str:  # noqa: N802 (keep uppercase for compat)
        return self.APP_VERSION
    APP_DESCRIPTION: str = "Tradesage Market Data API"
    DATABENTO_API_KEY: Optional[str] = os.getenv('DATABENTO_API_KEY', 'db-Jn7AnuuRLtWXAKBFp59Y4hbAvXKta')
    API_V1_STR: str = "/api/v1"
    
    # PostgreSQL
    POSTGRES_URL: str = os.getenv('POSTGRES_URL', 'postgresql+asyncpg://postgres:postgres@localhost:5432/postgres')
    
    # Redis
    REDIS_URL: str = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
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

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings

# Backward-compat alias so existing imports `from .config import settings` continue to work
settings = get_settings()


