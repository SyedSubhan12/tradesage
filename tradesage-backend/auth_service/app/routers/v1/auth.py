from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from common.rate_limiter import rate_limiter, get_rate_limit
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import uuid
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from datetime import timedelta, datetime, timezone
from uuid import UUID as UUIDType, uuid4
import logging
import secrets
import hashlib
import traceback
from typing import Optional, Tuple

from common.database import db_manager, atomic_session_operation
from common.config import settings
from common.auth import auth_manager, TokenExpiredError
from common.models import BaseUser, Tenant, TenantStatus, User
from common.utils import get_user_by_username_or_email
from common.audit_logger import log_audit_event
from common.redis_client import redis_manager

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from fastapi_mail.errors import ConnectionErrors
from pydantic import EmailStr
from contextlib import asynccontextmanager

from auth_service.app.models.password_reset_token_models import PasswordResetToken
from auth_service.app.models.token_blacklist import TokenBlacklist
from auth_service.app.clients.session_client import session_service_client
from auth_service.app.dependencies import get_current_active_user
from auth_service.app.services.auth_service import validate_session_security, is_token_blacklisted

from auth_service.app.schemas.auth import (
    TokenResponse,
    PasswordReset,
    PasswordResetConfirm,
    PasswordChange
)

# Enhanced logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tradesage.auth")

debug_logger = logging.getLogger("tradesage.auth.debug")
debug_logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
debug_logger.addHandler(console_handler)



async def store_refresh_token_securely(session_id: str, refresh_token: str, expiry_seconds: int) -> bool:
    try:
        debug_logger.debug(f"Storing refresh token for session {session_id}")
        redis_client = await redis_manager.get_redis()
        if redis_client:
            await redis_client.set(
                f"refresh_token:{session_id}",
                refresh_token,
                ex=expiry_seconds
            )
            debug_logger.debug(f"Refresh token stored successfully for session {session_id}")
            return True
        debug_logger.warning("Redis client unavailable")
        return False
    except Exception as e:
        debug_logger.error(f"Failed to store refresh token for session {session_id}: {e}")
        debug_logger.error(f"Traceback: {traceback.format_exc()}")
        return False

async def delete_refresh_token_securely(session_id: str) -> bool:
    try:
        debug_logger.debug(f"Deleting refresh token for session {session_id}")
        redis_client = await redis_manager.get_redis()
        if redis_client:
            result = await redis_client.delete(f"refresh_token:{session_id}")
            debug_logger.debug(f"Refresh token deletion result: {result}")
            return bool(result)
        debug_logger.warning("Redis client unavailable")
        return False
    except Exception as e:
        debug_logger.error(f"Failed to delete refresh token for session {session_id}: {e}")
        debug_logger.error(f"Traceback: {traceback.format_exc()}")
        return False

async def invalidate_user_sessions(user_id: str, current_session_id: str = None) -> bool:
    try:
        debug_logger.debug(f"Invalidating sessions for user {user_id} via session service")
        sessions = await session_service_client.get_user_sessions(user_id)
        if sessions is None:
            debug_logger.warning(f"Could not retrieve sessions for user {user_id} to invalidate.")
            return False

        invalidation_count = 0
        for session in sessions:
            session_token = session.get("session_token")
            if session_token and session_token != current_session_id:
                success = await session_service_client.terminate_session(session_token)
                if success:
                    invalidation_count += 1
                else:
                    debug_logger.warning(f"Failed to terminate session {session_token} for user {user_id}")
        
        debug_logger.debug(f"Invalidated {invalidation_count} sessions for user {user_id}")
        return True
    except Exception as e:
        debug_logger.error(f"Failed to invalidate sessions for user {user_id}: {e}")
        debug_logger.error(f"Traceback: {traceback.format_exc()}")
        return False

router = APIRouter(prefix="/auth", tags=["authentication"])

conf = ConnectionConfig(
    MAIL_USERNAME="your_smtp_username",
    MAIL_PASSWORD="your_smtp_password",
    MAIL_FROM="noreply@example.com",
    MAIL_PORT=587,
    MAIL_SERVER="your_smtp_server",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    MAIL_DEBUG=1,
    SUPPRESS_SEND=0
)

async def send_password_reset_email_async(email_to: EmailStr, token: str, http_request: Request):
    try:
        debug_logger.debug(f"Sending password reset email to {email_to}")
        reset_link = f"{http_request.url_for('confirm_password_reset_form_placeholder').replace('confirm_password_reset_form_placeholder', 'password/reset-confirm-form')}?token={token}"
        html_content = f"""
        <html>
            <body>
                <p>Hello,</p>
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <p><a href="{reset_link}">{reset_link}</a></p>
                <p>If you did not request this, please ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
            </body>
        </html>
        """
        message = MessageSchema(
            subject="Password Reset Request",
            recipients=[email_to],
            body=html_content,
            subtype=MessageType.html
        )
        fm = FastMail(conf)
        await fm.send_message(message)
        debug_logger.info(f"Password reset email sent to {email_to}")
    except ConnectionErrors as e:
        debug_logger.error(f"Failed to send email: {e}")
        debug_logger.error(f"Traceback: {traceback.format_exc()}")
    except Exception as e:
        debug_logger.error(f"Unexpected error sending email: {e}")
        debug_logger.error(f"Traceback: {traceback.format_exc()}")

@router.get("/password/reset-confirm-form", include_in_schema=False)
async def confirm_password_reset_form_placeholder():
    pass

@router.post("/token", response_model=TokenResponse)
@rate_limiter.limit(get_rate_limit("auth", "login"))
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(db_manager.get_session)
):
    debug_logger.debug(f"Login attempt for {form_data.username}")
    try:
        user = await get_user_by_username_or_email(db, username=form_data.username)
        if not user or not user.is_active:
            await log_audit_event(
                event_type="login_failed_non_existent_user",
                user_id=None,
                details={
                    "email_attempted": form_data.username,
                    "client_ip": request.client.host,
                    "reason": "non_existent_or_inactive_user"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"}
            )

        tenant = await db.get(Tenant, user.tenant_id)
        if not tenant or tenant.status != TenantStatus.ACTIVE:
            await log_audit_event(
                event_type="login_failed_inactive_tenant",
                user_id=str(user.id),
                details={
                    "email": user.email,
                    "client_ip": request.client.host,
                    "tenant_id": str(user.tenant_id),
                    "tenant_status": tenant.status.value if tenant else 'None',
                    "reason": "inactive_tenant"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Tenant account is {(tenant.status.value.lower() if tenant else 'invalid')}"
            )

        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            await log_audit_event(
                event_type="login_failed_account_locked",
                user_id=str(user.id),
                details={
                    "email": user.email,
                    "client_ip": request.client.host,
                    "locked_until": user.locked_until.isoformat(),
                    "reason": "account_locked"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account locked. Try again after {user.locked_until.isoformat()}"
            )

        if not auth_manager.verify_password(form_data.password, user.hashed_password):
            user.failed_login_attempts += 1
            lockout_duration = timedelta()
            event_details_update = {}

            if user.failed_login_attempts >= 15:
                user.locked_until = datetime.max.replace(tzinfo=timezone.utc)
                await log_audit_event(
                    event_type="account_locked_permanently",
                    user_id=str(user.id),
                    details={
                        "email": user.email,
                        "client_ip": request.client.host,
                        "failed_attempts": user.failed_login_attempts,
                        "reason": "excessive_failed_attempts_permanent"
                    }
                )
                event_details_update["lockout_status"] = "permanent"
            elif user.failed_login_attempts >= 10:
                lockout_duration = timedelta(hours=24)
            elif user.failed_login_attempts >= 7:
                lockout_duration = timedelta(minutes=30)
            elif user.failed_login_attempts >= 5:
                lockout_duration = timedelta(minutes=5)
            elif user.failed_login_attempts >= 3:
                lockout_duration = timedelta(minutes=1)

            if lockout_duration.total_seconds() > 0 and user.locked_until != datetime.max.replace(tzinfo=timezone.utc):
                user.locked_until = datetime.now(timezone.utc) + lockout_duration
                await log_audit_event(
                    event_type="account_locked_temporarily",
                    user_id=str(user.id),
                    details={
                        "email": user.email,
                        "client_ip": request.client.host,
                        "failed_attempts": user.failed_login_attempts,
                        "lockout_duration_minutes": lockout_duration.total_seconds() / 60,
                        "locked_until": user.locked_until.isoformat()
                    }
                )
                event_details_update["lockout_status"] = "temporary"
                event_details_update["locked_until"] = user.locked_until.isoformat()

            await log_audit_event(
                event_type="login_failed",
                user_id=str(user.id),
                details={
                    "email": user.email,
                    "client_ip": request.client.host,
                    "reason": "incorrect_password",
                    "failed_attempts_count": user.failed_login_attempts,
                    **event_details_update
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"}
            )

        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc)

        new_session_data = await session_service_client.create_session(
            user_id=user.id,
            client_ip=request.client.host,
            user_agent=request.headers.get("user-agent"),
            initial_data={}
        )
        if not new_session_data or "session_token" not in new_session_data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user session"
            )
        
        session_token = new_session_data["session_token"]

        access_token_expires = timedelta(minutes=auth_manager.access_token_expire_minutes)
        token_data = {
            "sub": str(user.id),
            "user_id": str(user.id),
            "email": user.email,
            "tenant_id": str(user.tenant_id),
            "session_id": session_token,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + access_token_expires
        }

        access_token = auth_manager.create_access_token(
            data=token_data,
            expires_in=access_token_expires,
            tenant_id=str(user.tenant_id),
            roles=[user.role.value],
            scopes=[],
            session_id=session_token
        )

        refresh_token_raw = auth_manager.create_refresh_token(
            data=token_data,
            tenant_id=str(user.tenant_id),
            roles=[user.role.value],
            scopes=[],
            session_id=session_token
        )

        if not refresh_token_raw:
            await session_service_client.terminate_session(session_token)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate refresh token"
            )
        
        refresh_token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
        refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=auth_manager.refresh_token_expire_days)

        update_success = await session_service_client.update_session(
            session_token=session_token,
            data={
                "refresh_token_hash": refresh_token_hash,
                "expires_at": refresh_expires_at.isoformat()
            }
        )

        if not update_success:
            await session_service_client.terminate_session(session_token)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to finalize user session"
            )

        await store_refresh_token_securely(
            session_token,
            refresh_token_raw,
            int(auth_manager.refresh_token_expire_days * 24 * 60 * 60)
        )

        await log_audit_event(
            event_type="user_login_success",
            user_id=str(user.id),
            details={
                "email": user.email,
                "client_ip": request.client.host,
                "tenant_id": str(user.tenant_id),
                "tenant_status": tenant.status.value,
                "session_id": session_token
            }
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token_raw,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/auth",
            expires=refresh_expires_at
        )

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            tenant_status=tenant.status.value
        )

    except HTTPException:
        raise
    except Exception as e:
        debug_logger.error(f"Login error: {e}")
        debug_logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during login."
        )

@router.post("/refresh", response_model=TokenResponse)
@rate_limiter.limit(get_rate_limit("auth", "refresh"))
async def refresh_access_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(db_manager.get_session)
):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    debug_logger.info(f"Token refresh attempt from IP: {client_ip}")

    token_data = None
    try:
        async with atomic_session_operation(db) as transaction_db:
            refresh_token_raw = request.cookies.get("refresh_token")
            if not refresh_token_raw:
                auth_header = request.headers.get("Authorization")
                if auth_header and auth_header.startswith("Bearer "):
                    refresh_token_raw = auth_header.split(" ")[1]
                else:
                    await log_audit_event(
                        event_type="token_refresh_failed",
                        user_id=None,
                        details={"client_ip": client_ip, "reason": "no_refresh_token"},
                    )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Refresh token required",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

            try:
                token_data = auth_manager.decode_token(refresh_token_raw, is_refresh=True)
                if not token_data.user_id or not token_data.session_id:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token payload"
                    )
            except TokenExpiredError:
                await log_audit_event(
                    event_type="token_refresh_failed",
                    user_id=getattr(token_data, 'user_id', None),
                    details={"client_ip": client_ip, "reason": "refresh_token_expired"},
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has expired"
                )
            except Exception as e:
                await log_audit_event(
                    event_type="token_refresh_failed",
                    user_id=None,
                    details={"client_ip": client_ip, "reason": "invalid_refresh_token", "error": str(e)},
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
                )

            user_id = token_data.user_id
            session_id = token_data.session_id

            session_data = await session_service_client.get_session(session_id)

            if not session_data:
                reason = "session_not_found"
                details = {"client_ip": client_ip, "session_id": session_id, "failure_reason": reason}
                debug_logger.error(f"Token refresh failed. Details: {details}")
                await log_audit_event(event_type="token_refresh_failed", user_id=user_id, details=details)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid or expired session: {reason}"
                )

            if not session_data.get("is_active"):
                reason = "session_is_inactive"
                details = {"client_ip": client_ip, "session_id": session_id, "failure_reason": reason}
                debug_logger.error(f"Token refresh failed. Details: {details}")
                await log_audit_event(event_type="token_refresh_failed", user_id=user_id, details=details)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid or expired session: {reason}"
                )

            try:
                expires_raw = session_data.get("expires_at")
                if isinstance(expires_raw, datetime):
                    expires_at = expires_raw if expires_raw.tzinfo else expires_raw.replace(tzinfo=timezone.utc)
                elif isinstance(expires_raw, str):
                    expires_str = expires_raw.replace("Z", "+00:00")
                    expires_at = datetime.fromisoformat(expires_str)
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                else:
                    raise ValueError("Invalid expires_at value")
                if expires_at <= datetime.now(timezone.utc):
                    raise ValueError("Session expired")
            except (ValueError, TypeError):
                reason = "session_has_expired"
                details = {
                    "client_ip": client_ip,
                    "session_id": session_id,
                    "failure_reason": reason,
                    "expires_at": session_data.get("expires_at"),
                }
                debug_logger.error(f"Token refresh failed. Details: {details}")
                await log_audit_event(event_type="token_refresh_failed", user_id=user_id, details=details)
                await session_service_client.terminate_session(session_id)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid or expired session: {reason}"
                )

            refresh_token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
            current_hash = session_data.get("refresh_token_hash")
            previous_hash = session_data.get("previous_refresh_token_hash")

            previous_expires_raw = session_data.get("previous_refresh_token_expires_at")
            previous_hash_expires_at = None
            if isinstance(previous_expires_raw, datetime):
                previous_hash_expires_at = (
                    previous_expires_raw
                    if previous_expires_raw.tzinfo
                    else previous_expires_raw.replace(tzinfo=timezone.utc)
                )
            elif isinstance(previous_expires_raw, str):
                try:
                    expires_str = previous_expires_raw.replace("Z", "+00:00")
                    previous_hash_expires_at = datetime.fromisoformat(expires_str)
                    if previous_hash_expires_at.tzinfo is None:
                        previous_hash_expires_at = previous_hash_expires_at.replace(tzinfo=timezone.utc)
                except ValueError:
                    previous_hash_expires_at = None

            should_rotate = False
            if current_hash == refresh_token_hash:
                should_rotate = True
                debug_logger.info(f"Current refresh token used for session {session_id}. Proceeding with rotation.")
            elif (
                previous_hash == refresh_token_hash
                and previous_hash_expires_at
                and datetime.now(timezone.utc) <= previous_hash_expires_at
            ):
                should_rotate = False
                debug_logger.warning(
                    f"Previous refresh token used for session {session_id} within grace period. "
                    f"Re-issuing access token without rotation to handle race condition."
                )
            else:
                reason = "refresh_token_hash_mismatch"
                details = {
                    "client_ip": client_ip,
                    "session_id": session_id,
                    "failure_reason": reason,
                    "jti": token_data.jti if token_data else "unknown",
                }
                debug_logger.error(f"Token refresh failed. Details: {details}")
                await log_audit_event(event_type="token_refresh_failed", user_id=user_id, details=details)
                await session_service_client.terminate_session(session_id)
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid or expired session: {reason}")

            is_valid, reason = await validate_session_security(session_data, request, user_id)
            if not is_valid:
                await session_service_client.terminate_session(session_id)
                await log_audit_event(
                    event_type="token_refresh_failed",
                    user_id=user_id,
                    details={"client_ip": client_ip, "session_id": session_id, "reason": f"security_validation_failed_{reason}"},
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Session security validation failed: {reason}"
                )

            user = await db.get(User, user_id)
            if not user or not user.is_active:
                await session_service_client.terminate_session(session_id)
                await log_audit_event(
                    event_type="token_refresh_failed",
                    user_id=user_id,
                    details={"client_ip": client_ip, "session_id": session_id, "reason": "user_inactive"},
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="User account is inactive or not found"
                )

            tenant = await transaction_db.get(Tenant, user.tenant_id)
            if not tenant or tenant.status != TenantStatus.ACTIVE:
                await session_service_client.terminate_session(session_id)
                await log_audit_event(
                    event_type="token_refresh_failed",
                    user_id=user_id,
                    details={
                        "client_ip": client_ip,
                        "session_id": session_id,
                        "tenant_status": tenant.status.value if tenant else "None",
                        "reason": "inactive_tenant",
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=f"Tenant account is {tenant.status.value.lower() if tenant else 'invalid'}"
                )

            if token_data.jti and await is_token_blacklisted(db, token_data.jti):
                await session_service_client.terminate_session(session_id)
                await log_audit_event(
                    event_type="token_refresh_failed",
                    user_id=user_id,
                    details={"client_ip": client_ip, "session_id": session_id, "reason": "token_blacklisted"},
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked"
                )

            access_token_expires = timedelta(minutes=auth_manager.access_token_expire_minutes)
            new_token_data = {
                "sub": str(user.id),
                "user_id": str(user.id),
                "email": user.email,
                "tenant_id": str(user.tenant_id),
                "session_id": session_id,
                "iat": datetime.now(timezone.utc),
                "exp": datetime.now(timezone.utc) + access_token_expires,
            }

            new_access_token = auth_manager.create_access_token(
                data=new_token_data,
                expires_in=access_token_expires,
                tenant_id=str(user.tenant_id),
                roles=[user.role.value],
                scopes=[],
                session_id=session_id,
            )

            if should_rotate:
                refresh_token_expires_delta = timedelta(days=settings.refresh_token_expire_days)
                if settings.refresh_token_expire_minutes:
                    refresh_token_expires_delta = timedelta(minutes=settings.refresh_token_expire_minutes)

                new_refresh_token_raw = auth_manager.create_refresh_token(
                    data={"user_id": str(user.id), "session_id": session_id},
                    expires_in=refresh_token_expires_delta,
                    session_id=session_id,
                    user_id=str(user.id),
                )
                new_refresh_token_hash = hashlib.sha256(new_refresh_token_raw.encode()).hexdigest()

                session_update_data = {
                    "previous_refresh_token_hash": current_hash,
                    "previous_refresh_token_expires_at": (
                        datetime.now(timezone.utc) + timedelta(seconds=settings.refresh_token_grace_period_seconds)
                    ).isoformat(),
                    "refresh_token_hash": new_refresh_token_hash,
                    "last_accessed": datetime.now(timezone.utc).isoformat(),
                    "user_agent": user_agent,
                }

                update_success = await session_service_client.update_session(session_id, session_update_data)

                if not update_success:
                    await session_service_client.terminate_session(session_id)
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to update session with new refresh token",
                    )

                await store_refresh_token_securely(
                    session_id,
                    new_refresh_token_raw,
                    int(refresh_token_expires_delta.total_seconds()),
                )

                response.set_cookie(
                    key="refresh_token",
                    value=new_refresh_token_raw,
                    httponly=True,
                    secure=True,
                    samesite="lax",
                    path="/auth",
                    expires=datetime.now(timezone.utc) + refresh_token_expires_delta,
                )

            await log_audit_event(
                event_type="token_refresh_success",
                user_id=user_id,
                details={"client_ip": client_ip, "session_id": session_id, "rotated": should_rotate},
            )

            return TokenResponse(
                access_token=new_access_token,
                token_type="bearer",
                expires_in=int(access_token_expires.total_seconds()),
                tenant_status=tenant.status.value,
            )

    except HTTPException as e:
        raise e
    except Exception as e:
        debug_logger.error(f"Unexpected error in refresh_access_token: {e}", exc_info=True)
        await log_audit_event(
            event_type="token_refresh_failed",
            user_id=getattr(token_data, 'user_id', None),
            details={"client_ip": client_ip, "reason": "unexpected_error", "error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during token refresh.",
        )

@router.post("/password/change")
async def change_password(
    request: Request,
    password_change: PasswordChange,
    current_user: BaseUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    async with atomic_session_operation(db) as transaction_db:
        try:
            if not auth_manager.verify_password(password_change.current_password, current_user.hashed_password):
                await log_audit_event(
                    event_type="password_change_failed",
                    user_id=str(current_user.id),
                    details={
                        "email": current_user.email,
                        "client_ip": request.client.host,
                        "reason": "incorrect_password"
                    }
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

            current_user.hashed_password = auth_manager.hash_password(password_change.new_password)
            current_user.password_last_changed_at = datetime.now(timezone.utc)
            current_user.failed_login_attempts = 0
            current_user.locked_until = None

            await invalidate_user_sessions(user_id=str(current_user.id))

            await log_audit_event(
                event_type="password_change_success",
                user_id=str(current_user.id),
                details={
                    "email": current_user.email,
                    "client_ip": request.client.host
                }
            )

            return {"message": "Password changed successfully"}

        except HTTPException:
            raise
        except Exception as e:
            debug_logger.error(f"Password change error: {e}")
            debug_logger.error(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

@router.post("/password-reset/request")
@rate_limiter.limit(get_rate_limit("auth", "password_reset"))
async def request_password_reset(
    request: Request,
    request_data: PasswordReset,
    background_tasks: BackgroundTasks,
    http_request: Request = None,
    db: AsyncSession = Depends(db_manager.get_session)
):
    http_request = http_request or request
    async with atomic_session_operation(db) as transaction_db:
        try:
            result = await transaction_db.execute(
                select(User).where(User.email == request_data.email)
            )
            user = result.scalar_one_or_none()

            log_details = {"email_attempted": request_data.email, "client_ip": http_request.client.host}

            if not user or not user.is_active:
                await log_audit_event(
                    event_type="password_reset_request_failed",
                    user_id=str(user.id) if user else None,
                    details=log_details
                )
                return {"message": "If your email is registered, you will receive a reset link"}

            reset_token_value = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(reset_token_value.encode()).hexdigest()
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

            await transaction_db.execute(
                update(PasswordResetToken).where(
                    PasswordResetToken.user_id == user.id,
                    PasswordResetToken.used == False,
                    PasswordResetToken.expires_at > datetime.now(timezone.utc)
                ).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
            )

            new_token = PasswordResetToken(
                user_id=user.id,
                token=token_hash,
                expires_at=expires_at,
                used=False
            )
            transaction_db.add(new_token)

            background_tasks.add_task(
                send_password_reset_email_async,
                user.email,
                reset_token_value,
                http_request
            )

            await log_audit_event(
                event_type="password_reset_request_success",
                user_id=str(user.id),
                details=log_details
            )

            return {"message": "If your email is registered, you will receive a reset link"}

        except Exception as e:
            debug_logger.error(f"Password reset request error: {e}")
            debug_logger.error(f"Traceback: {traceback.format_exc()}")
            return {"message": "An error occurred. Please contact support"}

@router.post("/password/reset-confirm")
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirm,
    http_request: Request,
    db: AsyncSession = Depends(db_manager.get_session)
):
    async with atomic_session_operation(db) as transaction_db:
        try:
            token_hash = hashlib.sha256(reset_confirm.token.encode()).hexdigest()
            result = await transaction_db.execute(
                select(PasswordResetToken).where(
                    PasswordResetToken.token == token_hash,
                    PasswordResetToken.used == False,
                    PasswordResetToken.expires_at > datetime.now(timezone.utc)
                )
            )
            token_record = result.scalar_one_or_none()

            log_details = {
                "client_ip": http_request.client.host,
                "token_used_attempt": reset_confirm.token[:8] + "..."
            }

            if not token_record:
                await log_audit_event(
                    event_type="password_reset_confirm_failed",
                    user_id=None,
                    details=log_details
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired reset token"
                )

            user = await transaction_db.get(User, token_record.user_id)
            if not user or not user.is_active:
                token_record.used = True
                await log_audit_event(
                    event_type="password_reset_confirm_failed",
                    user_id=str(token_record.user_id),
                    details=log_details
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User account not found or inactive"
                )

            user.hashed_password = auth_manager.hash_password(reset_confirm.new_password)
            user.password_last_changed_at = datetime.now(timezone.utc)
            user.failed_login_attempts = 0
            user.locked_until = None
            token_record.used = True
            token_record.used_at = datetime.now(timezone.utc)

            await invalidate_user_sessions(transaction_db, str(user.id))

            log_details["email"] = user.email
            await log_audit_event(
                event_type="password_reset_confirm_success",
                user_id=str(user.id),
                details=log_details
            )

            return {"message": "Password reset successfully"}

        except HTTPException:
            raise
        except Exception as e:
            debug_logger.error(f"Password reset confirm error: {e}")
            debug_logger.error(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: BaseUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    async with atomic_session_operation(db) as transaction_db:
        try:
            token = None
            authorization = request.headers.get("Authorization")
            if authorization and authorization.startswith("Bearer "):
                token = authorization.split(" ")[1]

            session_id_to_revoke = None
            if token:
                try:
                    payload = auth_manager.decode_token(token, is_refresh=False)
                    session_id_to_revoke = payload.session_id
                except TokenExpiredError:
                    debug_logger.warning(f"Expired token during logout for {current_user.email}")
                except Exception as e:
                    debug_logger.error(f"Token decode error during logout: {e}")

            if session_id_to_revoke:
                revoke_success = await session_service_client.terminate_session(session_id_to_revoke)
                if revoke_success:
                    await delete_refresh_token_securely(session_id_to_revoke)
                else:
                    debug_logger.warning(f"Failed to terminate session {session_id_to_revoke} during logout.")

            await log_audit_event(
                event_type="user_logout_success",
                user_id=str(current_user.id),
                details={
                    "email": current_user.email,
                    "client_ip": request.client.host,
                    "session_id_revoked": session_id_to_revoke
                }
            )

            response.delete_cookie(key="refresh_token", path="/auth")
            return {"message": "Logged out successfully"}

        except Exception as e:
            debug_logger.error(f"Logout error: {e}")
            debug_logger.error(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

@router.get("/me", response_model=dict)
async def read_users_me(current_user: BaseUser = Depends(get_current_active_user)):
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "role": current_user.role.value if hasattr(current_user, 'role') else 'N/A'
    }