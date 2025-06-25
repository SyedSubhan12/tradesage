import uuid
from common.config import settings
import asyncio
import json
import zlib
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict, field
from contextlib import asynccontextmanager
import logging
from enum import Enum

import redis.asyncio as redis
from sqlalchemy import create_engine, Column, String, DateTime, Text, Integer, Boolean, Index, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from cryptography.fernet import Fernet

@dataclass
class TradingPosition:
    """Individual trading position"""
    position_id : str
    symbol : str
    quantity : float
    entry_price : float
    current_price : float
    exit_price : float
    unrealized_pnl : float
    timestamp : datetime
    metadata : Dict[str, Any] = field(default_factory=dict)

@dataclass
class TradingConfiguration:
    """Trading configuration"""
    risk_toleance : str
    max_position_size : float
    stop_loss_percentage : float
    take_profit_percentage : float
    trading_strategies : List[str] = field(default_factory=list)
    watchlist : List[str] = field(default_factory=list)
    custom_indicators : Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        self.position_id = str(uuid.uuid4())
        self.timestamp = datetime.now()
        self.metadata = {}




       