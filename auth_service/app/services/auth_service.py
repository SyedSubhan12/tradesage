from datetime import datetime, timedelta, timezone
from uuid import UUID as UUIDType
import hashlib
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from fastapi import HTTPException, status

from common.models import Tenant, TenantStatus, BaseUser
from common.redis_client import redis_manager
from auth_service.app.models.token_blacklist import TokenBlacklist
from auth_service.app.models.user_session import UserSession

logger = logging.getLogger("tradesage.auth")

async def validate_tenant_active(tenant_id: UUIDType, db: AsyncSession):
    """Validate tenant is active before authentication"""
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        logger.warning(f"Tenant validation failed: {tenant_id} not found")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid tenant configuration"
        )
    if tenant.status != TenantStatus.ACTIVE:
        logger.warning(f"Tenant {tenant_id} is not active (status={tenant.status})")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant account is {tenant.status.value.lower()}"
        )

async def blacklist_token(db: AsyncSession, token: str, user_id: UUIDType, revoke_only: bool = False):
    """Add or mark a refresh token as revoked in the blacklist"""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        result = await db.execute(
            select(TokenBlacklist).where(
                TokenBlacklist.user_id == user_id,
                TokenBlacklist.token_hash == token_hash
            )
        )
        token_record = result.scalar_one_or_none()
        if token_record:
            token_record.revoked = True
        elif not revoke_only:
            db.add(
                TokenBlacklist(
                    user_id=user_id,
                    token_hash=token_hash,
                    expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                    revoked=True
                )
            )
        await db.commit()
    except Exception as e:
        logger.error(f"Error blacklisting token: {e}")
        await db.rollback()

async def is_token_blacklisted(db: AsyncSession, token: str) -> bool:
    """Check if a token is blacklisted"""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        result = await db.execute(
            select(TokenBlacklist).where(
                TokenBlacklist.token_hash == token_hash,
                TokenBlacklist.revoked.is_(True)
            )
        )
        return result.scalars().first() is not None
    except Exception as e:
        logger.error(f"Error checking token blacklist: {e}")
        return False

async def cleanup_expired_tokens(db: AsyncSession):
    """Clean up expired password reset tokens, sessions, and blacklisted tokens"""
    from auth_service.app.models.password_reset_token_models import PasswordResetToken
    
    try:
        current_time = datetime.now(timezone.utc)
        
        # Clean expired password reset tokens
        await db.execute(
            delete(PasswordResetToken).where(
                PasswordResetToken.expires_at < current_time
            )
        )
        
        # Clean expired user sessions
        await db.execute(
            delete(UserSession).where(
                UserSession.expires_at < current_time
            )
        )
        
        # Clean expired blacklisted tokens
        await db.execute(
            delete(TokenBlacklist).where(
                TokenBlacklist.expires_at < current_time
            )
        )
        
        await db.commit()
        logger.info("Cleaned up expired tokens, sessions, and blacklisted tokens")
    except Exception as e:
        logger.error(f"Error cleaning up expired tokens: {e}")
        await db.rollback()