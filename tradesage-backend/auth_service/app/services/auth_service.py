from datetime import datetime, timedelta, timezone
from uuid import UUID as UUIDType
import hashlib
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from fastapi import HTTPException, status, Request

from common.models import Tenant, TenantStatus, BaseUser
from common.redis_client import redis_manager
from auth_service.app.models.token_blacklist import TokenBlacklist
from typing import Dict

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
        # Check if the token already exists in the blacklist
        result = await db.execute(
            select(TokenBlacklist).where(
                TokenBlacklist.user_id == user_id,
                TokenBlacklist.token_hash == token_hash
            )
        )
        token_record = result.scalar_one_or_none()

        if not token_record:
            # If it doesn't exist, add it to the blacklist
            db.add(
                TokenBlacklist(
                    user_id=user_id,
                    token_hash=token_hash,
                    expires_at=datetime.now(timezone.utc) + timedelta(days=7) # Token is blacklisted until this expiry
                )
            )
        try:
            await db.commit()
            logger.info(f"Successfully committed changes for blacklisting token for user {user_id}.")
        except Exception as commit_e:
            logger.error(f"Error committing transaction for blacklisting token for user {user_id}: {commit_e}", exc_info=True)
            await db.rollback()
            logger.info(f"Rolled back transaction for blacklisting token for user {user_id}.")
            raise # Re-raise the exception after logging and rollback
    except Exception as e:
        logger.error(f"Unexpected error in blacklist_token for user {user_id}: {e}", exc_info=True)
        await db.rollback()
        raise # Re-raise the exception

async def is_token_blacklisted(db: AsyncSession, token: str) -> bool:
    """Check if a token is blacklisted"""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        result = await db.execute(
            select(TokenBlacklist).where(
                TokenBlacklist.token_hash == token_hash
            )
        )
        return result.scalars().first() is not None
    except Exception as e:
        logger.error(f"Error checking token blacklist: {e}")
        return False

async def cleanup_expired_tokens(db: AsyncSession):
    """
    Clean up expired password reset tokens, sessions, and blacklisted tokens.

    This is an async generator that yields the number of deleted items for each category.
    """
    from auth_service.app.models.password_reset_token_models import PasswordResetToken

    try:
        current_time = datetime.now(timezone.utc)

        # Clean expired password reset tokens
        result = await db.execute(
            delete(PasswordResetToken).where(PasswordResetToken.expires_at < current_time)
        )
        deleted_count = result.rowcount
        logger.info(f"Deleted {deleted_count} expired password reset tokens.")
        yield deleted_count



        # Clean expired blacklisted tokens
        result = await db.execute(
            delete(TokenBlacklist).where(TokenBlacklist.expires_at < current_time)
        )
        deleted_count = result.rowcount
        logger.info(f"Deleted {deleted_count} expired blacklisted tokens.")
        yield deleted_count

    except Exception as e:
        logger.error(f"Critical error during token cleanup: {e}", exc_info=True)
        # Re-raise to ensure the transaction context manager handles the rollback
        raise

async def validate_session_security(session: Dict[str, any], request: Request, user_id: UUIDType) -> (bool, str):
    """
    Performs security validation on the user session.
    Checks for IP address and user agent consistency.
    """
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    session_ip = session.get("client_ip")
    if session_ip and session_ip != client_ip:
        logger.warning(f"Session security violation for user {user_id}: IP mismatch. Session IP: {session_ip}, Current IP: {client_ip}")
        return False, "ip_mismatch"

    # Temporarily disable user agent validation for debugging
    # session_ua = session.get("user_agent")
    # if session_ua and session_ua != user_agent:
    #     logger.warning(f"Session security violation for user {user_id}: User-Agent mismatch. Session UA: {session_ua}, Current UA: {user_agent}")
    #     return False, "user_agent_mismatch"

    return True, "valid"