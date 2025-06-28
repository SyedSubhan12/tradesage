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
from common.auth import auth_manager
import secrets
import hashlib
import traceback
import asyncio
import aiohttp
from typing import Optional, Tuple, Dict, Any
import time
import json
from contextlib import asynccontextmanager
import structlog
from prometheus_client import Counter, Histogram, Gauge
from auth_service.app.utils.cookie_manager import *

# Import JWT error handling - FIXED Error #3
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
# Add to top of auth.py
from auth_service.app.utils.cookie_manager import get_cookie_manager

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

from auth_service.app.models.password_reset_token_models import PasswordResetToken
from auth_service.app.models.token_blacklist import TokenBlacklist
from auth_service.app.clients.session_client import session_service_client
from auth_service.app.dependencies import get_current_active_user, validate_token_format, debug_token_validation
from auth_service.app.services.auth_service import validate_session_security, is_token_blacklisted

from auth_service.app.schemas.auth import (
    TokenResponse,
    PasswordReset,
    PasswordResetConfirm,
    PasswordChange
)

# =============================================================================
# PRODUCTION-GRADE LOGGING AND MONITORING SETUP
# =============================================================================

# Structured logging configuration
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# Enhanced logger setup
logger = structlog.get_logger("tradesage.auth")

# Prometheus metrics for monitoring
auth_requests_total = Counter(
    'auth_requests_total',
    'Total authentication requests',
    ['endpoint', 'method', 'status']
)

auth_request_duration = Histogram(
    'auth_request_duration_seconds',
    'Authentication request duration',
    ['endpoint', 'method']
)

active_sessions = Gauge(
    'auth_active_sessions_total',
    'Number of active sessions'
)

token_refresh_attempts = Counter(
    'auth_token_refresh_attempts_total',
    'Token refresh attempts',
    ['status', 'failure_reason']
)

login_attempts = Counter(
    'auth_login_attempts_total',
    'Login attempts',
    ['status', 'failure_reason']
)

# =============================================================================
# CORRELATION ID AND REQUEST CONTEXT
# =============================================================================

def get_correlation_id(request: Request) -> str:
    """Generate or extract correlation ID for request tracing"""
    correlation_id = request.headers.get("X-Correlation-ID")
    if not correlation_id:
        correlation_id = str(uuid4())
    return correlation_id

def get_request_context(request: Request, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Create standardized request context for logging"""
    return {
        "correlation_id": get_correlation_id(request),
        "client_ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "unknown"),
        "method": request.method,
        "url": str(request.url),
        "user_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# =============================================================================
# ENHANCED ERROR HANDLING AND MONITORING
# =============================================================================

class AuthenticationError(Exception):
    """Custom authentication error with context"""
    def __init__(self, message: str, error_code: str, context: Dict[str, Any] = None):
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        super().__init__(self.message)

async def handle_auth_error(
    error: Exception,
    context: Dict[str, Any],
    logger_instance: structlog.BoundLogger,
    error_type: str = "general"
) -> HTTPException:
    """Centralized error handling with monitoring"""
    
    # Log error with full context
    logger_instance.error(
        "Authentication error occurred",
        error_type=error_type,
        error_message=str(error),
        error_class=error.__class__.__name__,
        traceback=traceback.format_exc(),
        **context
    )
    
    # Update metrics
    auth_requests_total.labels(
        endpoint=context.get('endpoint', 'unknown'),
        method=context.get('method', 'unknown'),
        status='error'
    ).inc()
    
    # Return appropriate HTTP exception
    if isinstance(error, HTTPException):
        return error
    elif isinstance(error, AuthenticationError):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error.message
        )
    else:
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# =============================================================================
# ENHANCED UTILITY FUNCTIONS WITH MONITORING
# =============================================================================

async def store_refresh_token_securely(session_id: str, refresh_token: str, expiry_seconds: int) -> bool:
    """Store refresh token with enhanced error handling and monitoring"""
    context_logger = logger.bind(session_id=session_id, operation="store_refresh_token")
    
    try:
        context_logger.debug("Storing refresh token")
        redis_client = await redis_manager.get_redis()
        
        if not redis_client:
            context_logger.warning("Redis client unavailable")
            # Could implement fallback storage mechanism here
            return False
        
        await redis_client.set(
            f"refresh_token:{session_id}",
            refresh_token,
            ex=expiry_seconds
        )
        
        context_logger.info("Refresh token stored successfully")
        return True
        
    except Exception as e:
        context_logger.error(
            "Failed to store refresh token",
            error=str(e),
            traceback=traceback.format_exc()
        )
        # Could implement metrics for Redis failures
        return False

async def delete_refresh_token_securely(session_id: str) -> bool:
    """Delete refresh token with enhanced monitoring"""
    context_logger = logger.bind(session_id=session_id, operation="delete_refresh_token")
    
    try:
        context_logger.debug("Deleting refresh token")
        redis_client = await redis_manager.get_redis()
        
        if not redis_client:
            context_logger.warning("Redis client unavailable for token deletion")
            return False
        
        result = await redis_client.delete(f"refresh_token:{session_id}")
        context_logger.info("Refresh token deletion completed", deletion_result=bool(result))
        return bool(result)
        
    except Exception as e:
        context_logger.error(
            "Failed to delete refresh token",
            error=str(e),
            traceback=traceback.format_exc()
        )
        return False

async def invalidate_user_sessions(user_id: str, current_session_id: str = None) -> bool:
    """Invalidate user sessions with comprehensive monitoring"""
    context_logger = logger.bind(
        user_id=user_id,
        current_session_id=current_session_id,
        operation="invalidate_sessions"
    )
    
    try:
        context_logger.debug("Starting session invalidation")
        sessions = await session_service_client.get_user_sessions(user_id)
        
        if sessions is None:
            context_logger.warning("Could not retrieve sessions for invalidation")
            return False

        invalidation_count = 0
        failed_invalidations = 0
        
        for session in sessions:
            session_token = session.get("session_token")
            if session_token and session_token != current_session_id:
                success = await session_service_client.terminate_session(session_token)
                if success:
                    invalidation_count += 1
                    # Also delete the refresh token
                    await delete_refresh_token_securely(session_token)
                else:
                    failed_invalidations += 1
                    context_logger.warning(
                        "Failed to terminate session",
                        session_token=session_token
                    )
        
        context_logger.info(
            "Session invalidation completed",
            invalidated_count=invalidation_count,
            failed_count=failed_invalidations,
            total_sessions=len(sessions)
        )
        return True
        
    except Exception as e:
        context_logger.error(
            "Failed to invalidate user sessions",
            error=str(e),
            traceback=traceback.format_exc()
        )
        return False

# =============================================================================
# ROUTER SETUP
# =============================================================================

router = APIRouter(prefix="/auth", tags=["authentication"])

# Email configuration (move to environment variables in production)
conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=settings.MAIL_USE_CREDENTIALS,
    VALIDATE_CERTS=settings.MAIL_VALIDATE_CERTS,
    MAIL_DEBUG=settings.MAIL_DEBUG,
    SUPPRESS_SEND=settings.MAIL_SUPPRESS_SEND
)

async def send_password_reset_email_async(email_to: EmailStr, token: str, http_request: Request):
    """Send password reset email with comprehensive error handling"""
    context_logger = logger.bind(
        email_to=email_to,
        operation="send_password_reset_email",
        correlation_id=get_correlation_id(http_request)
    )
    
    try:
        context_logger.debug("Sending password reset email")
        
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
        
        context_logger.info("Password reset email sent successfully")
        
    except ConnectionErrors as e:
        context_logger.error(
            "Email connection error",
            error=str(e),
            error_type="connection"
        )
    except Exception as e:
        context_logger.error(
            "Unexpected error sending email",
            error=str(e),
            traceback=traceback.format_exc()
        )

@router.get("/password/reset-confirm-form", include_in_schema=False)
async def confirm_password_reset_form_placeholder():
    pass

# =============================================================================
# ENHANCED LOGIN ENDPOINT
# =============================================================================

@router.post("/token", response_model=TokenResponse)
@rate_limiter.limit(get_rate_limit("auth", "login"))
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(db_manager.get_session)
):
    start_time = time.time()
    request_context = get_request_context(request)
    context_logger = logger.bind(**request_context)
    
    try:
        context_logger.info(
            "Login attempt started",
            username_attempted=form_data.username
        )
        
        with auth_request_duration.labels(endpoint='login', method='POST').time():
            user = await get_user_by_username_or_email(db, username=form_data.username)
            
            if not user or not user.is_active:
                login_attempts.labels(status='failed', failure_reason='user_not_found').inc()
                
                await log_audit_event(
                    event_type="login_failed_non_existent_user",
                    user_id=None,
                    details={
                        "email_attempted": form_data.username,
                        "client_ip": request.client.host,
                        "reason": "non_existent_or_inactive_user",
                        **request_context
                    }
                )
                
                context_logger.warning(
                    "Login failed - user not found or inactive",
                    username_attempted=form_data.username
                )
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect email or password",
                    headers={"WWW-Authenticate": "Bearer"}
                )

            # Update context with user info
            request_context["user_id"] = str(user.id)
            context_logger = logger.bind(**request_context)

            tenant = await db.get(Tenant, user.tenant_id)
            if not tenant or tenant.status != TenantStatus.ACTIVE:
                login_attempts.labels(status='failed', failure_reason='inactive_tenant').inc()
                
                await log_audit_event(
                    event_type="login_failed_inactive_tenant",
                    user_id=str(user.id),
                    details={
                        "email": user.email,
                        "tenant_id": str(user.tenant_id),
                        "tenant_status": tenant.status.value if tenant else 'None',
                        "reason": "inactive_tenant",
                        **request_context
                    }
                )
                
                context_logger.warning(
                    "Login failed - inactive tenant",
                    tenant_status=tenant.status.value if tenant else 'None'
                )
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Tenant account is {(tenant.status.value.lower() if tenant else 'invalid')}"
                )

            # Check account lockout
            if user.locked_until and user.locked_until > datetime.now(timezone.utc):
                login_attempts.labels(status='failed', failure_reason='account_locked').inc()
                
                await log_audit_event(
                    event_type="login_failed_account_locked",
                    user_id=str(user.id),
                    details={
                        "email": user.email,
                        "locked_until": user.locked_until.isoformat(),
                        "reason": "account_locked",
                        **request_context
                    }
                )
                
                context_logger.warning(
                    "Login failed - account locked",
                    locked_until=user.locked_until.isoformat()
                )
                
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"Account locked. Try again after {user.locked_until.isoformat()}"
                )

            # Verify password
            if not auth_manager.verify_password(form_data.password, user.hashed_password):
                login_attempts.labels(status='failed', failure_reason='invalid_password').inc()
                
                user.failed_login_attempts += 1
                lockout_duration = timedelta()
                event_details_update = {}

                # Progressive lockout logic
                if user.failed_login_attempts >= 15:
                    user.locked_until = datetime.max.replace(tzinfo=timezone.utc)
                    event_details_update["lockout_status"] = "permanent"
                    
                    await log_audit_event(
                        event_type="account_locked_permanently",
                        user_id=str(user.id),
                        details={
                            "email": user.email,
                            "failed_attempts": user.failed_login_attempts,
                            "reason": "excessive_failed_attempts_permanent",
                            **request_context
                        }
                    )
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
                    event_details_update.update({
                        "lockout_status": "temporary",
                        "locked_until": user.locked_until.isoformat(),
                        "lockout_duration_minutes": lockout_duration.total_seconds() / 60
                    })
                    
                    await log_audit_event(
                        event_type="account_locked_temporarily",
                        user_id=str(user.id),
                        details={
                            "email": user.email,
                            "failed_attempts": user.failed_login_attempts,
                            **event_details_update,
                            **request_context
                        }
                    )

                await log_audit_event(
                    event_type="login_failed",
                    user_id=str(user.id),
                    details={
                        "email": user.email,
                        "reason": "incorrect_password",
                        "failed_attempts_count": user.failed_login_attempts,
                        **event_details_update,
                        **request_context
                    }
                )
                
                context_logger.warning(
                    "Login failed - incorrect password",
                    failed_attempts=user.failed_login_attempts
                )
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect email or password",
                    headers={"WWW-Authenticate": "Bearer"}
                )

            # Successful authentication - reset failure counters
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login_at = datetime.now(timezone.utc)

            # Create session
            new_session_data = await session_service_client.create_session(
                user_id=user.id,
                client_ip=request.client.host,
                user_agent=request.headers.get("user-agent"),
                initial_data={}
            )
            
            if not new_session_data or "session_token" not in new_session_data:
                context_logger.error("Failed to create user session")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create user session"
                )
            
            session_token = new_session_data["session_token"]

            # Generate tokens
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
                context_logger.error("Failed to generate refresh token")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to generate refresh token"
                )
            
            # Store refresh token hash in session
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
                context_logger.error("Failed to finalize user session")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to finalize user session"
                )

            # Store refresh token securely
            await store_refresh_token_securely(
                session_token,
                refresh_token_raw,
                int(auth_manager.refresh_token_expire_days * 24 * 60 * 60)
            )

            # Successful login audit
            await log_audit_event(
                event_type="user_login_success",
                user_id=str(user.id),
                details={
                    "email": user.email,
                    "tenant_id": str(user.tenant_id),
                    "tenant_status": tenant.status.value,
                    "session_id": session_token,
                    **request_context
                }
            )

            # Set secure cookie
            response.set_cookie(
                key="refresh_token",
                value=refresh_token_raw,
                httponly=True,
                secure=True,
                samesite="lax",
                path="/auth",
                expires=refresh_expires_at
            )

            # Update metrics
            login_attempts.labels(status='success', failure_reason='none').inc()
            active_sessions.inc()
            auth_requests_total.labels(endpoint='login', method='POST', status='success').inc()

            duration = time.time() - start_time
            context_logger.info(
                "Login successful",
                duration=f"{duration:.2f}s",
                session_id=session_token
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
        duration = time.time() - start_time
        context_logger.error(
            "Login error",
            error=str(e),
            duration=f"{duration:.2f}s",
            traceback=traceback.format_exc()
        )
        
        auth_requests_total.labels(endpoint='login', method='POST', status='error').inc()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during login."
        )

# =============================================================================
# ENHANCED TOKEN REFRESH ENDPOINT - FIXES ALL IDENTIFIED ERRORS
# =============================================================================

@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(db_manager.get_session)
):
    """
    Production-ready refresh token endpoint with comprehensive error handling,
    cookie debugging, and enterprise-grade monitoring.
    """
    start_time = time.time()
    request_context = get_request_context(request)
    context_logger = logger.bind(**request_context)
    
    try:
        context_logger.info("Token refresh attempt started")
        token_refresh_attempts.labels(status="attempt", failure_reason="none").inc()

        # Extract refresh token from cookie (primary) or Authorization header (fallback)
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                refresh_token = auth_header.split(" ")[1]
                context_logger.info(f"Refresh token extracted from Authorization header refresh_token: {refresh_token}")
            else:
                context_logger.warning("No refresh token found in cookie or header")
                token_refresh_attempts.labels(status="failure", failure_reason="missing_token").inc()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="No refresh token provided. Please log in again.",
                    headers={"WWW-Authenticate": "Bearer"}
                )
        else:
            context_logger.info("Refresh token extracted from cookie")

        # Decode the refresh token to extract user information
        try:
            payload = auth_manager.decode_token(refresh_token, is_refresh=True)
            if payload is None:
                context_logger.warning("Invalid refresh token format")
                token_refresh_attempts.labels(status="failure", failure_reason="invalid_token").inc()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token. Please log in again.",
                    headers={"WWW-Authenticate": "Bearer"}
                )

            user_id = payload.get("sub")
            session_id = payload.get("session_id")
            if not user_id or not session_id:
                context_logger.warning("Missing user_id or session_id in refresh token")
                token_refresh_attempts.labels(status="failure", failure_reason="missing_data").inc()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token data. Please log in again.",
                    headers={"WWW-Authenticate": "Bearer"}
                )
        except Exception as e:
            context_logger.error("Error decoding refresh token", error=str(e))
            token_refresh_attempts.labels(status="failure", failure_reason="decoding_error").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Validate session existence and ownership
        session_valid = await validate_session_existence(session_id, user_id, context_logger)
        if not session_valid:
            context_logger.warning("Session validation failed", session_id=session_id)
            token_refresh_attempts.labels(status="failure", failure_reason="invalid_session").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Fetch session information for security validation
        session_info = await session_service_client.get_session(session_id)
        if not session_info:
            context_logger.warning("Session not found after validation", session_id=session_id)
            token_refresh_attempts.labels(status="failure", failure_reason="session_not_found").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Perform session security validation (IP, user-agent checks)
        is_valid, reason = await validate_session_security(session_info, request, user_id)
        if not is_valid:
            context_logger.warning("Session security validation failed", reason=reason)
            token_refresh_attempts.labels(status="failure", failure_reason=f"security_{reason}").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Session security validation failed: {reason}. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Check if the refresh token is blacklisted
        if await is_token_blacklisted(refresh_token, db):
            context_logger.warning("Refresh token has been revoked")
            token_refresh_attempts.labels(status="failure", failure_reason="token_revoked").inc()
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # =================================================================
        # STEP 4: DECODE AND VALIDATE REFRESH TOKEN
        # =================================================
        context_logger.info("Refresh token validated successfully")

        # Fetch user information
        user_result = await db.execute(select(User).where(User.id == UUID(user_id)))
        user = user_result.scalar_one_or_none()
        if not user:
            context_logger.warning("User not found for refresh token", user_id=user_id)
            token_refresh_attempts.labels(status="failure", failure_reason="user_not_found").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Check if user is active
        if not user.is_active:
            context_logger.warning("Inactive user attempted token refresh", user_id=user_id)
            token_refresh_attempts.labels(status="failure", failure_reason="inactive_user").inc()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled. Please contact support.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Get tenant status
        tenant_result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
        tenant = tenant_result.scalar_one_or_none()
        tenant_status = tenant.status.value if tenant else "unknown"

        # Update session last accessed
        try:
            await session_service_client.update_session(
                session_id, 
                {"last_accessed": datetime.now(timezone.utc).isoformat()}
            )
        except Exception as e:
            context_logger.error("Failed to update session last accessed", error=str(e))

        # Create new access token
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = auth_manager.create_access_token(
            data={"sub": user_id, "session_id": session_id},
            user_id=user_id,
            session_id=session_id,
            expires_in=access_token_expires
        )

        # Create new refresh token
        new_refresh_token = auth_manager.create_refresh_token(
            data={"sub": user_id, "session_id": session_id},
            user_id=user_id,
            session_id=session_id,
            expires_in=timedelta(days=settings.refresh_token_expire_days)
        )

        # Store new refresh token in database
        refresh_token_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
        new_refresh_token_entry = RefreshToken(
            user_id=UUID(user_id),
            token=refresh_token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
        )
        db.add(new_refresh_token_entry)

        # Update user session with new refresh token hash
        user_session_result = await db.execute(
            select(UserSession).where(UserSession.id == UUID(session_id))
        )
        user_session = user_session_result.scalar_one_or_none()
        if user_session:
            user_session.previous_refresh_token_hash = user_session.refresh_token_hash
            user_session.previous_refresh_token_expires_at = user_session.expires_at
            user_session.refresh_token_hash = refresh_token_hash
            user_session.expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)

        await db.commit()
        context_logger.info("New refresh token stored in database")

        # Set refresh token as cookie
        cookie_manager = CookieManager(request, response, session_config)
        cookie_manager.set_refresh_token_cookie(new_refresh_token)
        context_logger.info("New refresh token set as cookie")

        # Log success
        context_logger.info("Token refresh successful")
        token_refresh_attempts.labels(status="success", failure_reason="none").inc()
        auth_requests_total.labels(endpoint='refresh', method='POST', status='success').inc()

        # Return new tokens
        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=int(access_token_expires.total_seconds()),
            tenant_status=tenant_status
        )

    except HTTPException as he:
        context_logger.error("HTTP error during token refresh", error=str(he.detail))
        auth_requests_total.labels(endpoint='refresh', method='POST', status='error').inc()
        raise

    except Exception as e:
        context_logger.error(
            "Unexpected error during token refresh",
            error=str(e),
            traceback=traceback.format_exc()
        )
        token_refresh_attempts.labels(status="failure", failure_reason="unexpected_error").inc()
        auth_requests_total.labels(endpoint='refresh', method='POST', status='error').inc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during token refresh",
            headers={"WWW-Authenticate": "Bearer"}
        )
    finally:
        latency = time.time() - start_time
        auth_request_duration.labels(endpoint='refresh', method='POST').observe(latency)
        context_logger.debug(f"Token refresh request completed in {latency:.3f} seconds")

# =============================================================================
# ENHANCED PASSWORD MANAGEMENT ENDPOINTS
# =============================================================================

@router.post("/password/change")
async def change_password(
    request: Request,
    password_change: PasswordChange,
    current_user: BaseUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    request_context = get_request_context(request, str(current_user.id))
    context_logger = logger.bind(**request_context)
    
    async with atomic_session_operation(db) as transaction_db:
        try:
            context_logger.info("Password change attempt started")
            
            # Verify current password
            if not auth_manager.verify_password(password_change.current_password, current_user.hashed_password):
                context_logger.warning("Password change failed - incorrect current password")
                
                await log_audit_event(
                    event_type="password_change_failed",
                    user_id=str(current_user.id),
                    details={
                        "email": current_user.email,
                        "reason": "incorrect_password",
                        **request_context
                    }
                )
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password is incorrect"
                )

            # Update password and security fields
            current_user.hashed_password = auth_manager.hash_password(password_change.new_password)
            current_user.password_last_changed_at = datetime.now(timezone.utc)
            current_user.failed_login_attempts = 0
            current_user.locked_until = None

            # Invalidate all other user sessions for security
            await invalidate_user_sessions(user_id=str(current_user.id))

            await log_audit_event(
                event_type="password_change_success",
                user_id=str(current_user.id),
                details={
                    "email": current_user.email,
                    **request_context
                }
            )

            context_logger.info("Password changed successfully")
            return {"message": "Password changed successfully"}

        except HTTPException:
            raise
        except Exception as e:
            context_logger.error(
                "Password change error",
                error=str(e),
                traceback=traceback.format_exc()
            )
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
    db: AsyncSession = Depends(db_manager.get_session)
):
    request_context = get_request_context(request)
    context_logger = logger.bind(**request_context)
    
    async with atomic_session_operation(db) as transaction_db:
        try:
            context_logger.info(
                "Password reset request started",
                email_attempted=request_data.email
            )
            
            result = await transaction_db.execute(
                select(User).where(User.email == request_data.email)
            )
            user = result.scalar_one_or_none()

            log_details = {
                "email_attempted": request_data.email,
                **request_context
            }

            if not user or not user.is_active:
                await log_audit_event(
                    event_type="password_reset_request_failed",
                    user_id=str(user.id) if user else None,
                    details=log_details
                )
                
                context_logger.warning("Password reset request for non-existent or inactive user")
                
                # Always return success message to prevent email enumeration
                return {"message": "If your email is registered, you will receive a reset link"}

            # Generate secure reset token
            reset_token_value = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(reset_token_value.encode()).hexdigest()
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

            # Invalidate existing tokens for this user
            await transaction_db.execute(
                update(PasswordResetToken).where(
                    PasswordResetToken.user_id == user.id,
                    PasswordResetToken.used == False,
                    PasswordResetToken.expires_at > datetime.now(timezone.utc)
                ).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
            )

            # Create new reset token
            new_token = PasswordResetToken(
                user_id=user.id,
                token=token_hash,
                expires_at=expires_at,
                used=False
            )
            transaction_db.add(new_token)

            # Send email asynchronously
            background_tasks.add_task(
                send_password_reset_email_async,
                user.email,
                reset_token_value,
                request
            )

            await log_audit_event(
                event_type="password_reset_request_success",
                user_id=str(user.id),
                details=log_details
            )

            context_logger.info("Password reset request processed successfully")
            return {"message": "If your email is registered, you will receive a reset link"}

        except Exception as e:
            context_logger.error(
                "Password reset request error",
                error=str(e),
                traceback=traceback.format_exc()
            )
            return {"message": "An error occurred. Please contact support"}

@router.post("/password/reset-confirm")
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirm,
    request: Request,
    db: AsyncSession = Depends(db_manager.get_session)
):
    request_context = get_request_context(request)
    context_logger = logger.bind(**request_context)
    
    async with atomic_session_operation(db) as transaction_db:
        try:
            context_logger.info("Password reset confirmation started")
            
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
                "token_used_attempt": reset_confirm.token[:8] + "...",
                **request_context
            }

            if not token_record:
                await log_audit_event(
                    event_type="password_reset_confirm_failed",
                    user_id=None,
                    details=log_details
                )
                
                context_logger.warning("Invalid or expired reset token used")
                
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
                
                context_logger.warning("Password reset attempted for inactive user")
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User account not found or inactive"
                )

            # Update user password and security fields
            user.hashed_password = auth_manager.hash_password(reset_confirm.new_password)
            user.password_last_changed_at = datetime.now(timezone.utc)
            user.failed_login_attempts = 0
            user.locked_until = None
            
            # Mark token as used
            token_record.used = True
            token_record.used_at = datetime.now(timezone.utc)

            # Invalidate all user sessions for security
            await invalidate_user_sessions(str(user.id))

            log_details["email"] = user.email
            await log_audit_event(
                event_type="password_reset_confirm_success",
                user_id=str(user.id),
                details=log_details
            )

            context_logger.info("Password reset completed successfully")
            return {"message": "Password reset successfully"}

        except HTTPException:
            raise
        except Exception as e:
            context_logger.error(
                "Password reset confirm error",
                error=str(e),
                traceback=traceback.format_exc()
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

# =============================================================================
# ENHANCED LOGOUT ENDPOINT
# =============================================================================

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: BaseUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    request_context = get_request_context(request, str(current_user.id))
    context_logger = logger.bind(**request_context)
    
    async with atomic_session_operation(db) as transaction_db:
        try:
            context_logger.info("Logout started")
            
            # Extract token from Authorization header
            token = None
            authorization = request.headers.get("Authorization")
            if authorization and authorization.startswith("Bearer "):
                token = authorization.split(" ")[1]

            session_id_to_revoke = None
            if token:
                try:
                    payload = auth_manager.decode_token(token, is_refresh=False)
                    session_id_to_revoke = payload.session_id
                    context_logger.debug("Session ID extracted from token", session_id=session_id_to_revoke)
                except TokenExpiredError:
                    context_logger.warning("Expired token during logout")
                except Exception as e:
                    context_logger.error("Token decode error during logout", error=str(e))

            # Revoke session and refresh token
            if session_id_to_revoke:
                revoke_success = await session_service_client.terminate_session(session_id_to_revoke)
                if revoke_success:
                    await delete_refresh_token_securely(session_id_to_revoke)
                    context_logger.debug("Session and refresh token revoked successfully")
                    active_sessions.dec()  # Update metrics
                else:
                    context_logger.warning("Failed to terminate session during logout")

            # Audit logging
            await log_audit_event(
                event_type="user_logout_success",
                user_id=str(current_user.id),
                details={
                    "email": current_user.email,
                    "session_id_revoked": session_id_to_revoke,
                    **request_context
                }
            )

            # Clear refresh token cookie
            response.delete_cookie(key="refresh_token", path="/auth")
            
            auth_requests_total.labels(endpoint='logout', method='POST', status='success').inc()
            
            context_logger.info("Logout completed successfully")
            return {"message": "Logged out successfully"}

        except Exception as e:
            context_logger.error(
                "Logout error",
                error=str(e),
                traceback=traceback.format_exc()
            )
            
            auth_requests_total.labels(endpoint='logout', method='POST', status='error').inc()
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

# =============================================================================
# USER INFO ENDPOINT
# =============================================================================

@router.get("/me", response_model=dict)
async def read_users_me(
    request: Request,
    current_user: BaseUser = Depends(get_current_active_user)
):
    request_context = get_request_context(request, str(current_user.id))
    context_logger = logger.bind(**request_context)
    
    try:
        context_logger.debug("User info request")
        
        user_info = {
            "user_id": current_user.id,
            "email": current_user.email,
            "role": current_user.role.value if hasattr(current_user, 'role') else 'N/A',
            "last_login": current_user.last_login_at.isoformat() if hasattr(current_user, 'last_login_at') and current_user.last_login_at else None,
            "account_status": "active" if current_user.is_active else "inactive"
        }
        
        auth_requests_total.labels(endpoint='me', method='GET', status='success').inc()
        
        return user_info
        
    except Exception as e:
        context_logger.error(
            "Error retrieving user info",
            error=str(e),
            traceback=traceback.format_exc()
        )
        
        auth_requests_total.labels(endpoint='me', method='GET', status='error').inc()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# =============================================================================
# HEALTH CHECK AND MONITORING ENDPOINTS
# =============================================================================

@router.get("/health", include_in_schema=False)
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check Redis connectivity
        redis_status = "healthy"
        try:
            redis_client = await redis_manager.get_redis()
            if redis_client:
                await redis_client.ping()
            else:
                redis_status = "unavailable"
        except Exception:
            redis_status = "unhealthy"
        
        # Check session service connectivity
        session_service_status = "healthy"
        try:
            # This would be a lightweight health check to session service
            # Implementation depends on your session service API
            pass
        except Exception:
            session_service_status = "unhealthy"
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",  # You might want to get this from settings
            "dependencies": {
                "redis": redis_status,
                "session_service": session_service_status,
                "database": "healthy"  # Assume healthy if we can respond
            }
        }
        
        # If any dependency is unhealthy, mark overall status as degraded
        if any(status != "healthy" for status in health_status["dependencies"].values()):
            health_status["status"] = "degraded"
        
        return health_status
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unhealthy"
        )

@router.get("/metrics", include_in_schema=False)
async def get_metrics():
    """Expose metrics endpoint for Prometheus scraping"""
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error("Metrics endpoint failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Metrics unavailable"
        )