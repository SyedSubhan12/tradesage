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
from app.models.tradingposition import TradingPosition
from app.models.tradingposition import TradingConfiguration
from app.models.base import Base
from sqlalchemy import create_engine, Column, String, DateTime, Text, Integer, Boolean, Index, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from cryptography.fernet import Fernet

@dataclass
class SessionData:
    """ Complete session state structure"""
    user_id: str
    session_id : str

    # Trading state
    open_positions : List[TradingPosition] = field(default_factory=list)
    trading_config : Optional[TradingConfiguration] = None

    # UI state
    active_charts : List[Dict[str, Any]] = field(default_factory=list)
    workspace_layout : Dict[str, Any] = field(default_factory=dict)
    
    # Interaction History
    recent_searches: List[str] = field(default_factory=list)
    command_history: List[Dict[str, Any]] = field(default_factory=list)

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)

    # Session lifecycle
    is_active: bool = True
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(minutes=settings.session_token_expire_minutes))

    # Auth state
    refresh_token_hash: Optional[str] = None
    previous_refresh_token_hash: Optional[str] = None
    previous_refresh_token_expires_at: Optional[datetime] = None

    #Metadata
    version: int = 1
    checksum: Optional[str] = None
    