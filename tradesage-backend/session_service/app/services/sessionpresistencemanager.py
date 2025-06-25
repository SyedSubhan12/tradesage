import uuid
from common.config import settings
import asyncio
import json
import zlib
import hashlib
import time
import traceback
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
from ..config.session_config import SessionConfig

class SessionPresistenceManager:
    """High-Performance Session presistence manager with Multi-layer Caching"""
    
    def __init__(self, config: SessionConfig):
        self.config = config
        self.fernet = Fernet(config.encryption_key)
        self.circuit_breaker = CircuitBreaker(config.circuit_breaker_threshold, 60)
        self.async_engine = create_async_engine(config.postgres_url,
        pool_size=20, 
        max_overflow=30,
        pool_timeout=30,
        pool_recycle=1800,
        echo=True,
        future=True,
        )
        self.async_session_factory = async_sessionmaker(self.async_engine, class_=AsyncSession, expire_on_commit=False)
        self.redis_pool = None
        self.logger = logging.getLogger(__name__)

        self._auto_save_task: Dict[str, asyncio.Task] = {}

    async def initialize(self):
        """Initialize the connectiosn and create tables"""
        # initiate redis
        self.redis_pool = redis.ConnectionPool.from_url(self.config.redis_url,
        max_connections=100, 
        retry_on_commit=True,
        decode_responses=True,
        socket_keepalive = True,
        socket_keepalive_options={}) 

        # Create tables
        async with self.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        # Start auto save task
        self._auto_save_task = asyncio.create_task(self._auto_save_loop())
        self.logger.info("Session presistence manager initialized")

    async def close(self):
        """Close the connections"""
        for task in self._auto_save_task.values():
            task.cancel()
        await self.async_engine.dispose()
        if self.redis_pool:
            await self.redis_pool.disconnect()
        self.logger.info("Session presistence manager closed")
    
    def _generate_session_token(self) -> str:
        """Generate a secure session token"""
        return hashlib.sha256(
            f"{uuid.uuid4()}{time.time()}{uuid.uuid4()}".encode()
        ).hexdigest()
    def _compress_data(self, data: bytes) -> bytes:
        """Compress session data"""
        if self.config.state_compression:
            return zlib.compress(data, level=6)
        return data
    
    def _decompress_data(self, data:bytes) -> bytes:
        """Decomrpess session data"""
        if self.config.state_compression:
            return zlib.decompress(data)
        return data
    
    def _encrypt_data(self, data: str)-> str:
        """Encrypt session data"""
        compressed = self._compress_data(data.encode())
        encrypted = self.fernet.encrypt(compressed)
        return encrypted.decode()
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt session data"""
        decrypted = self.fernet.decrypt(encrypted_data.encode())
        decompressed = self._decompress_data(decrypted)
        return decompressed.decode()
    
    def _caculate_checksum(self, data: SessionData) -> str:
        """Calculate checksum for session data"""
        json_str = json.dumps(asdict(data), default=str, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def _serialize_session_data(self, session_data: SessionData) -> str:
        """Serialize session data to JSON with custom handling"""
        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, TradingPosition):
                return asdict(obj)
            elif isinstance(obj, TradingConfiguration):
                return asdict(obj)
            elif isinstance(obj, UUID):
                return str(obj)
            elif isinstance(obj, Decimal):
                return float(obj)
            elif isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, bytes):
                return obj.decode("utf-8")
            elif isinstance(obj, Exception):
                return {
                    "name": obj.__class__.__name__,
                    "message": str(obj),
                    "args": obj.args,
                    "traceback": traceback.format_exc()
                }
            else:
                return str(obj)
        #update checksum before serializing
        session_data.checksum = self._calculate_checksum(session_data)
        session_data.last_updated = datetime.utcnow()
        return json.dumps(asdict(session_data), default=json_serializer)

    def _deserialize_session_data(self, json_str :str) -> SessionData:
        """Deserialize session data from JSON with custom handling"""
        try:
            data_dict = json.loads(json_str)

            # convert datetime strings to datetime obj
            for dt_field in ["created_at", "last_updated"]:
                if data_dict.get(dt_field):
                    data_dict[dt_field] = datetime.fromisoformat(data_dict[dt_field])
            # Reconstruct complex objects
            if data_dict.get('trading_config'):
                data_dict['trading_config'] = TradingConfiguration(**data_dict['trading_config'])
            
            if data_dict.get('open_positions'):
                positions = []
                for pos_data in data_dict['open_positions']:
                    if isinstance(pos_data['timestamp'], str):
                        pos_data['timestamp'] = datetime.fromisoformat(pos_data['timestamp'])
                    positions.append(TradingPosition(**pos_data))
                data_dict['open_positions'] = positions

            session_data = SessionData(**data_dict) 

            # verify checksum
            expected_checksum = session_data.checksum
            session_data.checksum = None
            actual_checksum = self._calculate_checksum(session_data)
            session_data.checksum = expected_checksum
            
            if expected_checksum != actual_checksum:
                self.logger.warning(f"Checksum mismatch for session {session_data.session_id}")

            return session_data

        except Exception as e:
            self.logger.error(f"Failed to deserialize session data: {str(e)}")
            raise ValueError(f"Invalid session data format : {e}")
            
            
        
