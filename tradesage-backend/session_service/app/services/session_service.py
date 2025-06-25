import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Any as AnyType

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from cryptography.fernet import Fernet

from common.models.user_session import UserSession, SessionState
from common.config import settings

import asyncio
import logging
from dataclasses import asdict

from .circuitbreaker import CircuitBreaker
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..models.session_data import SessionData
from ..models.sessionauditlog import SessionAuditLog


class SessionService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession], redis_client: redis.Redis, encryption_key: str, config: AnyType):
        self.async_session_factory = session_factory
        self.redis = redis_client
        self.fernet = Fernet(encryption_key.encode())
        self.config = config
        # Initialize circuit breaker for DB loads
        threshold = getattr(config, "circuit_breaker_threshold", 5)
        self.circuit_breaker = CircuitBreaker(threshold=threshold, timeout=30)
        self.logger = logging.getLogger(__name__)
        self._auto_save_tasks = {}

    def _generate_session_token(self) -> str:
        return str(uuid.uuid4())

    def _serialize_session_data(self, session_data: SessionData) -> bytes:
        """Encrypts and serializes session data."""
        data_dict = asdict(session_data)

        # Exclude refresh token data from the encrypted blob
        data_dict.pop('refresh_token_hash', None)
        data_dict.pop('previous_refresh_token_hash', None)
        data_dict.pop('previous_refresh_token_expires_at', None)

        for key, value in data_dict.items():
            if isinstance(value, datetime):
                data_dict[key] = value.isoformat()
            elif isinstance(value, uuid.UUID):
                data_dict[key] = str(value)
        return self.fernet.encrypt(json.dumps(data_dict).encode())

    def _deserialize_session_data(self, encrypted_data: bytes) -> SessionData:
        """Deserializes and decrypts session data."""
        decrypted_json = self.fernet.decrypt(encrypted_data).decode()
        data_dict = json.loads(decrypted_json)
        for key, value in data_dict.items():
            if isinstance(value, str):
                try:
                    data_dict[key] = datetime.fromisoformat(value)
                except (ValueError, TypeError):
                    pass
        
        session_data_fields = {f.name for f in SessionData.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data_dict.items() if k in session_data_fields}
        return SessionData(**filtered_data)

    async def _cache_session(self, session_id: str, session_data: SessionData):
        encrypted_data = self._serialize_session_data(session_data)
        await self.redis.set(
            f"{self.config.session_cache_prefix}{session_id}",
            encrypted_data,
            ex=int(self.config.session_token_expire_minutes * 60),
        )

    async def _get_cached_session(self, session_id: str) -> Optional[SessionData]:
        cached_data = await self.redis.get(f"{self.config.session_cache_prefix}{session_id}")
        if cached_data:
            return self._deserialize_session_data(cached_data)
        return None

    async def _invalidate_cache(self, session_id: str, user_id: str):
        await self.redis.delete(f"{self.config.session_cache_prefix}{session_id}")

    async def _save_to_database(self, session_data: SessionData, session_token: str, client_ip: Optional[str] = None, user_agent: Optional[str] = None):
        encrypted_data = self._serialize_session_data(session_data)
        
        async with self.async_session_factory() as db_session:
            result = await db_session.execute(
                select(UserSession).where(UserSession.id == session_data.session_id)
            )
            user_session = result.scalars().first()

            if user_session:
                user_session.encrypted_data = encrypted_data
                user_session.version = session_data.version
                user_session.last_accessed = datetime.utcnow()
                user_session.is_active = session_data.is_active
                user_session.expires_at = session_data.expires_at
            else:
                user_session = UserSession(
                    id=session_data.session_id,
                    user_id=session_data.user_id,
                    session_token=session_token,
                    encrypted_data=encrypted_data,
                    is_active=session_data.is_active,
                    expires_at=session_data.expires_at,
                    client_ip={"ip": client_ip} if client_ip else None,
                    user_agent=user_agent,
                    state=SessionState.ACTIVE.value
                )
                db_session.add(user_session)
            
            try:
                await db_session.commit()
            except Exception as commit_err:
                await db_session.rollback()
                self.logger.error(
                    f"Database commit failed while saving session {session_data.session_id}: {commit_err}",
                    exc_info=True,
                )
                raise

    @CircuitBreaker()
    async def _load_from_database(self, session_id: str) -> Optional[SessionData]:
        async with self.async_session_factory() as db_session:
            user_session = await db_session.get(UserSession, session_id)
            if user_session and user_session.state == SessionState.ACTIVE.value:
                session_data = self._deserialize_session_data(user_session.encrypted_data)
                if session_data:
                    # CRITICAL: Overwrite with values from dedicated columns to ensure freshness
                    session_data.refresh_token_hash = user_session.refresh_token_hash
                    session_data.previous_refresh_token_hash = user_session.previous_refresh_token_hash
                    session_data.previous_refresh_token_expires_at = user_session.previous_refresh_token_expires_at
                return session_data
        return None

    def _decrypt_data(self, encrypted_data: bytes) -> Dict[str, Any]:
        return json.loads(self.fernet.decrypt(encrypted_data).decode())

    async def create_session(
        self,
        user_id: str,
        session_data: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create new session with instant persistence"""
        session_id = str(uuid.uuid4())
        session_token = self._generate_session_token()
        
        # Initialize session state object
        session_data_obj = SessionData(
            user_id=str(user_id),
            session_id=session_id,
        )

        # Compute expiry and ensure lifecycle fields
        session_data_obj.expires_at = datetime.utcnow() + timedelta(minutes=self.config.session_token_expire_minutes)
        session_data_obj.is_active = True

        # Inject caller-supplied data if any
        if session_data:
            for key, value in session_data.items():
                if hasattr(session_data_obj, key):
                    setattr(session_data_obj, key, value)
        
        try:
            # Save to both cache and database atomically
            await asyncio.gather(
                self._cache_session(session_id, session_data_obj),
                self._save_to_database(session_data_obj, session_token, client_ip, user_agent)
            )
            
            # Start auto-save task
            self._start_auto_save(session_id)
            
            self.logger.info(f"Created session {session_id} for user {user_id}")
            return {
                "session_token": session_token,
                "user_id": user_id,
                "created_at": session_data_obj.created_at,
                "expires_at": session_data_obj.expires_at,
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create session: {e}")
            raise
    
    async def get_session(self, session_id: str) -> Optional[SessionData]:
        """Retrieves a session, prioritizing data integrity by loading from the database first."""
        try:
            # ARCHITECTURAL FIX: The database is the single source of truth.
            # The previous cache-first approach returned incomplete data (missing hashes),
            # causing persistent refresh failures. We now always load from the DB.
            self.logger.debug(f"Loading session {session_id} from database to ensure data integrity.")
            session_data = await self._load_from_database(session_id)

            if session_data:
                # After a successful DB load, update the cache with the complete, correct data.
                await self._cache_session(session_id, session_data)
                return session_data
            
            # If the session is not in the database, it's invalid.
            self.logger.warning(f"Session {session_id} not found in database.")
            return None

        except Exception as e:
            # The circuit breaker in _load_from_database will handle DB connection errors.
            self.logger.error(f"An unexpected error occurred while getting session {session_id}: {e}", exc_info=True)
            return None
    
    async def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update session data with atomic operations, writing to DB before cache."""
        try:
            async with self.async_session_factory() as db_session:
                # Lock the row for update to prevent race conditions
                result = await db_session.execute(
                    select(UserSession).where(UserSession.id == session_id).with_for_update()
                )
                user_session = result.scalars().first()

                if not user_session:
                    self.logger.warning(f"Session {session_id} not found in DB for update")
                    return False

                # Deserialize existing data to apply updates
                session_data = self._deserialize_session_data(user_session.encrypted_data)

                # Apply updates from the request to the dataclass
                for key, value in updates.items():
                    if hasattr(session_data, key):
                        # Handle datetime strings from JSON payload
                        if key == "previous_refresh_token_expires_at" and isinstance(value, str):
                            try:
                                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                            except (ValueError, TypeError):
                                self.logger.warning(f"Could not parse datetime string for {key}: {value}")
                                continue
                        setattr(session_data, key, value)

                session_data.version += 1
                session_data.last_updated = datetime.utcnow()

                # Update the database record directly
                user_session.encrypted_data = self._serialize_session_data(session_data)
                user_session.version = session_data.version
                user_session.last_accessed = datetime.utcnow()

                # Explicitly update dedicated columns from the dataclass
                user_session.refresh_token_hash = session_data.refresh_token_hash
                user_session.previous_refresh_token_hash = session_data.previous_refresh_token_hash
                user_session.previous_refresh_token_expires_at = session_data.previous_refresh_token_expires_at

                await db_session.commit()

                # Update cache only after successful DB commit
                await self._cache_session(session_id, session_data)

                self.logger.info(f"Session {session_id} updated successfully in DB and cache")
                return True

        except Exception as e:
            self.logger.error(f"Failed to update session {session_id}: {e}", exc_info=True)
            return False
    
    async def get_session_by_token(self, session_token: str) -> Optional[SessionData]:
        """Fetch session data using the public session_token."""
        try:
            async with self.async_session_factory() as db_session:
                result = await db_session.execute(
                    select(UserSession).where(UserSession.session_token == session_token)
                )
                user_session = result.scalars().first()
                if not user_session:
                    self.logger.warning(f"Session token {session_token} not found")
                    return None
                return await self.get_session(str(user_session.id))
        except Exception as e:
            self.logger.error(f"Failed to get session via token {session_token}: {e}", exc_info=True)
            return None

    async def update_session_by_token(self, session_token: str, updates: Dict[str, Any]) -> bool:
        """Update session data using the public session_token."""
        try:
            async with self.async_session_factory() as db_session:
                result = await db_session.execute(
                    select(UserSession).where(UserSession.session_token == session_token)
                )
                user_session = result.scalars().first()
                if not user_session:
                    self.logger.warning(f"Session token {session_token} not found for update")
                    return False
                return await self.update_session(str(user_session.id), updates)
        except Exception as e:
            self.logger.error(f"Failed to update session via token {session_token}: {e}", exc_info=True)
            return False

    def _start_auto_save(self, session_id: str):
        """Start background auto-save task"""
        async def auto_save_loop():
            while True:
                try:
                    await asyncio.sleep(self.config.auto_save_interval)
                    
                    # Get session from cache
                    session_data = await self._get_cached_session(session_id)
                    if session_data:
                        # Save to database
                        await self._save_to_database(session_data, "")  # Token not needed for updates
                        
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Auto-save failed for session {session_id}: {e}")
        
        task = asyncio.create_task(auto_save_loop())
        self._auto_save_tasks[session_id] = task
    
    async def terminate_session(self, session_id: str) -> bool:
        """Terminate session with cleanup"""
        try:
            session_data = await self.get_session(session_id)
            if not session_data:
                return False
            
            # Cancel auto-save
            if session_id in self._auto_save_tasks:
                self._auto_save_tasks[session_id].cancel()
                del self._auto_save_tasks[session_id]
            
            # Mark session inactive and do final save
            session_data.is_active = False
            session_data.last_updated = datetime.utcnow()
            await self._save_to_database(session_data, "")
            
            # Update session state in database
            async with self.async_session_factory() as db_session:
                user_session = await db_session.get(UserSession, session_id)
                if user_session:
                    user_session.state = SessionState.TERMINATED.value
                    
                    audit_log = SessionAuditLog(
                        session_id=session_id,
                        user_id=session_data.user_id,
                        action="TERMINATE",
                        old_state=SessionState.ACTIVE.value,
                        new_state=SessionState.TERMINATED.value
                    )
                    db_session.add(audit_log)
                    try:
                        await db_session.commit()
                    except Exception as commit_err:
                        await db_session.rollback()
                        self.logger.error(
                            f"Database commit failed while terminating session {session_id}: {commit_err}",
                            exc_info=True,
                        )
                        raise
            
            # Clean up cache
            await self._invalidate_cache(session_id, session_data.user_id)
            
            self.logger.info(f"Session {session_id} terminated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to terminate session {session_id}: {e}")
            return False
    
    async def delete_session(self, session_token: str) -> bool:
        """Delete (terminate) a session using its public `session_token`.

        Routers provide the opaque token, whereas most internal helpers work
        with the underlying `session_id`.  This method resolves the mapping and
        then re-uses `terminate_session` to perform the heavy-lifting so that
        all teardown logic stays in one place.
        """
        try:
            # 1. Map session token -> session row (and therefore session_id)
            async with self.async_session_factory() as db_session:
                result = await db_session.execute(
                    select(UserSession).where(UserSession.session_token == session_token)
                )
                user_session = result.scalars().first()
                if not user_session:
                    self.logger.warning(f"Session token {session_token} not found")
                    return False
                session_id_str = str(user_session.id)

            # 2. Delegate to existing helper – this updates DB state, audits, cache, etc.
            if await self.terminate_session(session_id_str):
                return True

            # 3. Fallback – ensure DB row is marked terminated even if terminate_session failed
            async with self.async_session_factory() as db_session:
                user_session = await db_session.get(UserSession, session_id_str)
                if user_session:
                    user_session.state = SessionState.TERMINATED.value
                    await db_session.commit()

            # 4. Invalidate cache and autosave (if still present)
            await self._invalidate_cache(session_id_str, str(user_session.user_id))
            if session_id_str in self._auto_save_tasks:
                self._auto_save_tasks[session_id_str].cancel()
                del self._auto_save_tasks[session_id_str]

            self.logger.info(f"Session {session_id_str} deleted via token")
            return True

        except Exception as e:
            self.logger.error(f"Failed to delete session via token {session_token}: {e}", exc_info=True)
            return False

    async def cleanup_expired_sessions(self) -> int:
        """Find and terminate all expired sessions."""
        terminated_count = 0
        async with self.async_session_factory() as db_session:
            try:
                expired_sessions = await db_session.execute(
                    select(UserSession.id)
                    .where(UserSession.expires_at < datetime.utcnow(), UserSession.state == SessionState.ACTIVE.value)
                )
                session_ids = expired_sessions.scalars().all()

                for session_id in session_ids:
                    if await self.terminate_session(session_id):
                        terminated_count += 1
                
                self.logger.info(f"Cleaned up {terminated_count} expired sessions.")
                return terminated_count
            except Exception as e:
                self.logger.error(f"Error during expired session cleanup: {e}", exc_info=True)
                return 0

    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user"""
        try:
            async with self.async_session_factory() as db_session:
                # Query active sessions
                from sqlalchemy import select
                stmt = select(UserSession).where(
                    (UserSession.user_id == user_id) & 
                    (UserSession.state == SessionState.ACTIVE.value) &
                    (UserSession.expires_at > datetime.utcnow())
                )
                result = await db_session.execute(stmt)
                sessions = result.scalars().all()
                
                return [
                    {
                        "session_id": str(session.id),
                        "created_at": session.created_at,
                        "last_accessed": session.last_accessed,
                        "expires_at": session.expires_at,
                        "client_ip": session.client_ip
                    }
                    for session in sessions
                ]
                
        except Exception as e:
            self.logger.error(f"Failed to get user sessions for {user_id}: {e}")
            return []
