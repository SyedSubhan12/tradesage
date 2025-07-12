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
from ..config.session_config import SessionConfig
from ..models.session_data import SessionData
from ..sessionpresistencemanager import SessionPresistenceManager


async def _save_to_database(self, session_data: SessionData, session_token: str):
    """Save session to PostgreSQL with full ACID properties"""
    try:
        async with self.async_session_factory() as db_session:
            # serialize and encryt data
            serialized_data = self._serialize_session_data(session_data)
            encrypted_data = self._encrypt_data(serialized_data)
            data_hash = hashlib.sha256(serialized_data.encode()).hexdigest()

            #check if session already exists
            existing_session = await db_session.get(UserSession, session_data.session_id)

            if existing_session:
                # update existing session
                existing_session.encrypted_data = encrypted_data
                existing_session.data_hash = data_hash
                existing_session.version += 1
                existing_session.state = SessionState.ACTIVE.value
                existing_session.last_accessed = datetime.utcnow()
                existing_session.last_updated = datetime.utcnow()

                
                # Log Audit trail
                audit_log = SessionAuditLog(
                    session_id=session_data.session_id,
                    user_id=session_data.user_id,
                    action="UPDATE",
                    old_state=existing_session.state,
                new_state=SessionState.ACTIVE.value,
                data_size=len(encrypted_data)
                    
                )
                await db_session.add(audit_log)
                
            else:
                # create new session
                new_session = UserSession(
                    session_id=session_data.session_id,
                    user_id=session_data.user_id,
                    session_token=session_token,
                    encrypted_data=encrypted_data,
                    data_hash=data_hash,
                    expires_at=datetime.utcnow() + timedelta(seconds=self.config.session_timeout),
                    client_ip=session_data.client_ip,
                    user_agent=session_data.user_agent,
                    state=SessionState.ACTIVE.value,
                    version=1,
                    last_accessed=datetime.utcnow(),
                    created_at=datetime.utcnow(),
                    last_updated=datetime.utcnow(),
                )
                await db_session.add(new_session)
               

                # Log Audit trail
                audit_log = SessionAuditLog(
                    session_id=session_data.session_id,
                    user_id=session_data.user_id,
                    action="CREATE",
                    new_state=SessionState.ACTIVE.value,
                    data_size=len(encrypted_data)
                )
                await db_session.add(audit_log)
            await db_session.commit()
            self.logger.info(f"Session {session_data.session_id} saved to database")
    except Exception as e:
        self.logger.error(f"Failed to save session to database: {e}")
        raise
    
async def _load_from_database(self, session_id: str) -> Optional[SessionData]:
    """Load session from PostgreSQL"""
    try:
        async with self.async_session_factory() as db_session:
            user_session = await db_session.get(UserSession, session_id)

            if not user_session:
                return None
            
            #check expiration
            if user_session.expires_at < datetime.utcnow():
                self.logger.warning(f"Session {session_id} has expired")
                return None
            
            # Decrypt and deserialize the data
            decrypted_data = self._decrypt_data(user_session.encrypted_data)

            # verify data integrity
            data_hash = hashlib.sha256(decrypted_data.encode()).hexdigest()
            if data_hash != user_session.data_hash:
                self.logger.warning(f"Data integrity check failed for session {session_id}")
                raise ValueError("Session data integrity compromised")
            
            session_data = self._deserialize_session_data(decrypted_data)

            # Update last accesed
            user_session.last_accessed = datetime.utcnow()
            await db_session.commit()

            # Log audit trail
            audit_log = SessionAuditLog(
                session_id=session_id,
                user_id=session_data.user_id,
                action="RESTORE",
                new_state=SessionState.ACTIVE.value,
                data_size=len(user_session.encrypted_data)
            )
            db_session.add(audit_log)
            await db_session.commit()

            return session_data
    except Exception as e:
        self.logger.error(f"Failed to load the session from Database: {e}")
        raise

                

            