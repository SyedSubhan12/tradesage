import uuid
from uuid import UUID
from decimal import Decimal
from common.config import settings
from app.models.tradingposition import TradingPosition, TradingConfiguration
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

from common.models.user_session import UserSession, SessionState

from app.models.session_data import SessionData
from app.config.session_config import SessionConfig
from common.circuit_breaker import CircuitBreaker
from common.redis_client import get_redis_client

logger = logging.getLogger("tradesage.session")
logger.setLevel(logging.DEBUG)

debug_logger = logging.getLogger("tradesage.session.debug")
debug_logger.setLevel(logging.DEBUG)


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
        token = hashlib.sha256(
            f"{uuid.uuid4()}{time.time()}{uuid.uuid4()}".encode()
        ).hexdigest()
        self.logger.debug(f"Generated new session ID: {token}")
        return token
    
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
    
    def _calculate_checksum(self, data: SessionData) -> str:
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

    # ----------------------------
    # Mapping helpers
    # ----------------------------
    def _session_data_to_db_record(
        self,
        session_data: SessionData,
        db_record: Optional[UserSession] = None,
    ) -> UserSession:
        """Populate an existing UserSession row or create a new one from SessionData.
        Does NOT add or commit; caller must add to session if a new row is created."""
        if db_record is None:
            db_record = UserSession(
                id=session_data.session_id,
                user_id=session_data.user_id,
                session_token=self._generate_session_token(),
            )
        # Metadata / auth columns
        db_record.refresh_token_hash = session_data.refresh_token_hash
        db_record.previous_refresh_token_hash = session_data.previous_refresh_token_hash
        db_record.previous_refresh_token_expires_at = session_data.previous_refresh_token_expires_at
        db_record.state = (
            SessionState.ACTIVE if session_data.is_active else SessionState.SUSPENDED
        )
        db_record.expires_at = session_data.expires_at
        db_record.version = session_data.version
        db_record.last_accessed = datetime.utcnow()
        return db_record

    def _db_record_to_session_data(self, db_record: UserSession) -> SessionData:
        """Convert DB row to SessionData, overriding authoritative metadata from DB."""
        decrypted_json = self._decrypt_data(db_record.encrypted_data)
        session_data = self._deserialize_session_data(decrypted_json)
        # Override authoritative fields from DB
        session_data.expires_at = db_record.expires_at
        session_data.is_active = db_record.state == SessionState.ACTIVE
        session_data.refresh_token_hash = db_record.refresh_token_hash
        session_data.previous_refresh_token_hash = db_record.previous_refresh_token_hash
        session_data.previous_refresh_token_expires_at = (
            db_record.previous_refresh_token_expires_at
        )
        session_data.version = db_record.version
        return session_data

    async def create_session(self, user_id: str, data: dict) -> str:
        start_time = time.time()
        try:
            session_id = str(uuid.uuid4())
            session_data = SessionData(session_id=session_id, user_id=user_id, data=data)
            serialized_data = self._serialize_session_data(session_data)
            encrypted_data = self._encrypt_data(serialized_data)
            # Save to Redis (short-term cache)
            redis_client = await self.get_redis_client()
            if redis_client:
                await redis_client.setex(
                    f"session:{session_id}",
                    self.config.session_timeout,
                    encrypted_data
                )
                debug_logger.info(f"Session created successfully. ID: {session_id}, User ID: {user_id}, Duration: {(time.time() - start_time):.2f} seconds")
            else:
                debug_logger.warning(f"Redis client unavailable for creating session {session_id}")
            # Save to database (long-term storage)
            async with self.async_session_factory() as db_session:
                async with db_session.begin():
                    db_record = self._session_data_to_db_record(session_data)
                    db_record.encrypted_data = encrypted_data
                    db_session.add(db_record)
                    debug_logger.info(f"Session created successfully. ID: {session_id}, User ID: {user_id}, Duration: {(time.time() - start_time):.2f} seconds")
                await db_session.commit()
                # Post-commit verification
                verify_record = await db_session.get(UserSession, session_id)
                if not verify_record:
                    debug_logger.error(f"Post-commit verification failed for session {session_id}")
                    raise RuntimeError("Session persistence verification failed")
            return session_id
        except Exception as e:
            debug_logger.error(f"Error creating session ID {session_id}: {e}")
            raise
    
    async def save_session(self, session_data: SessionData) -> bool:
        """Save session data to Redis and database with circuit breaker"""
        if await self.circuit_breaker.is_open():
            self.logger.warning(f"Circuit breaker open, skipping session save for {session_data.session_id}")
            return False

        try:
            serialized_data = self._serialize_session_data(session_data)
            self.logger.debug(f"Saving session {session_data.session_id}. Serialized data length: {len(serialized_data)}")
            encrypted_data = self._encrypt_data(serialized_data)
            self.logger.debug(f"Saving session {session_data.session_id}. Encrypted data length: {len(encrypted_data)}")
            
            # Save to Redis (short-term cache)
            redis_client = await self.get_redis_client()
            if redis_client:
                await redis_client.setex(
                    f"session:{session_data.session_id}",
                    self.config.session_timeout,
                    encrypted_data
                )
                debug_logger.info(f"Session saved to Redis successfully. ID: {session_data.session_id}, Duration: {(time.time() - start_time):.2f} seconds")
            else:
                debug_logger.warning(f"Redis client unavailable for saving session {session_data.session_id}")

            # Save to database (long-term storage)
            async with self.async_session_factory() as db_session:
                async with db_session.begin():
                    db_record = await db_session.get(UserSession, session_data.session_id)
                    if db_record:
                        self._session_data_to_db_record(session_data, db_record)
                        db_record.encrypted_data = encrypted_data
                        db_record.updated_at = datetime.utcnow()
                        debug_logger.info(f"Updated existing session record {session_data.session_id} in database")
                    else:
                        db_record = self._session_data_to_db_record(session_data)
                        db_record.encrypted_data = encrypted_data
                        db_session.add(db_record)
                        debug_logger.info(f"Created new session record {session_data.session_id} in database")
                await db_session.commit()
                # Post-commit verification
                verify_record = await db_session.get(UserSession, session_data.session_id)
                if not verify_record:
                    debug_logger.error(f"Post-commit verification failed for session {session_data.session_id}")
                    raise RuntimeError("Session persistence verification failed")
                debug_logger.info(f"Session saved to database successfully. ID: {session_data.session_id}, Duration: {(time.time() - start_time):.2f} seconds")

            await self.circuit_breaker.record_success()
            return True
        except Exception as e:
            debug_logger.error(f"Failed to save session {session_data.session_id}: {str(e)}")
            await self.circuit_breaker.record_failure()
            return False

    async def get_session(self, session_id: str) -> Optional[SessionData]:
        start_time = time.time()
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if await self.circuit_breaker.is_open():
                    self.logger.warning(f"Circuit breaker open, skipping session retrieval for {session_id}")
                    return None
                
                self.logger.debug(f"Attempt {attempt+1}: Retrieving session {session_id} from cache/database")
                # Try Redis first
                redis_client = await self.get_redis_client()
                if redis_client:
                    encrypted_data = await redis_client.get(f"session:{session_id}")
                    if encrypted_data:
                        decrypted_data = self._decrypt_data(encrypted_data)
                        session_data = self._deserialize_session_data(decrypted_data)
                        debug_logger.debug(f"Attempt {attempt+1}: Session retrieved from Redis successfully. ID: {session_id}, Duration: {(time.time() - start_time):.2f} seconds")
                        await self.circuit_breaker.record_success()
                        return session_data
                    else:
                        debug_logger.debug(f"Attempt {attempt+1}: Session not found in Redis, falling back to database. ID: {session_id}, Duration: {(time.time() - start_time):.2f} seconds")
                else:
                    debug_logger.warning(f"Attempt {attempt+1}: Redis client unavailable for retrieving session {session_id}, falling back to database. ID: {session_id}, Duration: {(time.time() - start_time):.2f} seconds")
                
                # Fall back to database
                async with self.async_session_factory() as db_session:
                    db_record = await db_session.get(UserSession, session_id)
                    if db_record:
                        session_data = self._db_record_to_session_data(db_record)
                        debug_logger.info(f"Attempt {attempt+1}: Session retrieved from database successfully. ID: {session_id}, Duration: {(time.time() - start_time):.2f} seconds")
                        # Update Redis cache
                        if redis_client:
                            await redis_client.setex(
                                f"session:{session_id}",
                                self.config.session_timeout,
                                db_record.encrypted_data
                            )
                            debug_logger.debug(f"Attempt {attempt+1}: Session cached in Redis after database retrieval. ID: {session_id}, Duration: {(time.time() - start_time):.2f} seconds")
                        await self.circuit_breaker.record_success()
                        return session_data
                    else:
                        debug_logger.debug(f"Attempt {attempt+1}: Session not found in database. ID: {session_id}, Duration: {(time.time() - start_time):.2f} seconds")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(0.5)
                            continue
                        return None
                await self.circuit_breaker.record_success()
                return None
            except Exception as e:
                debug_logger.error(f"Attempt {attempt+1}: Failed to retrieve session {session_id}: {str(e)}, Duration: {(time.time() - start_time):.2f} seconds")
                if attempt < max_retries - 1:
                    await asyncio.sleep(0.5)
                    continue
                await self.circuit_breaker.record_failure()
                return None
        return None

    async def delete_session(self, session_id: str) -> None:
        start_time = time.time()
        try:
            # Delete from Redis
            redis_client = await self.get_redis_client()
            if redis_client:
                await redis_client.delete(f"session:{session_id}")
                debug_logger.info(f"Session deleted from Redis successfully. ID: {session_id}, Duration: {(time.time() - start_time):.2f} seconds")
            else:
                debug_logger.warning(f"Redis client unavailable for deleting session {session_id}")
            # Delete from database
            async with self.async_session_factory() as db_session:
                await db_session.execute(delete(UserSession).where(UserSession.session_id == session_id))
                await db_session.commit()
                debug_logger.info(f"Session deleted from database successfully. ID: {session_id}, Duration: {(time.time() - start_time):.2f} seconds")
        except Exception as e:
            debug_logger.error(f"Error deleting session ID {session_id}: {e}, Duration: {(time.time() - start_time):.2f} seconds")
            raise
