from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import timedelta, datetime, timezone
from uuid import UUID as UUIDType, uuid4
import logging
import secrets
import hashlib

from common.database import db_manager
from common.auth import auth_manager
from common.models import BaseUser, Tenant, TenantStatus, User
from common.utils import get_user_by_username_or_email
from common.audit_logger import log_audit_event
from common.redis_client import redis_manager
# from common.config import settings # Assuming settings might be used for email, etc.

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from fastapi_mail.errors import ConnectionErrors
from pydantic import EmailStr
from typing import List

from auth_service.app.models.password_reset_token_models import PasswordResetToken
from auth_service.app.models.user_session import UserSession
# from auth_service.app.models.token_blacklist import TokenBlacklist # Not used in this version
from auth_service.app.dependencies import get_current_active_user
# from auth_service.app.services.auth_service import is_token_blacklisted # Not used in this version

# Import Pydantic models
from auth_service.app.schemas.auth import (
    TokenResponse,
    PasswordReset,
    PasswordResetConfirm,
    PasswordChange
)

router = APIRouter(prefix="/auth", tags=["authentication"])
logger = logging.getLogger("tradesage.auth")

# IMPORTANT: Move these to environment variables or a secure config management system!
conf = ConnectionConfig(
    MAIL_USERNAME = "your_smtp_username",
    MAIL_PASSWORD = "your_smtp_password",
    MAIL_FROM = "noreply@example.com",  # Corrected: EmailStr is a type, not a constructor here
    MAIL_PORT = 587,
    MAIL_SERVER = "your_smtp_server",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True,
    MAIL_DEBUG=1, # Set to 0 in production
    SUPPRESS_SEND=0 # Set to 1 for testing without sending emails
)

async def send_password_reset_email_async(email_to: EmailStr, token: str, http_request: Request):
    reset_link = f"{http_request.url_for('confirm_password_reset_form_placeholder').replace('confirm_password_reset_form_placeholder', 'password/reset-confirm-form')}?token={token}"
    # Note: The above URL construction is a bit of a hack for demonstration.
    # In a real app, you'd likely construct this URL based on frontend routing.
    # Or, more simply, use a known frontend base URL:
    # reset_link = f"https://your-frontend-app.com/reset-password?token={token}"

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
    try:
        await fm.send_message(message)
        logger.info(f"Password reset email sent to {email_to}")
    except ConnectionErrors as e:
        logger.error(f"Failed to send password reset email to {email_to}: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"An unexpected error occurred while sending password reset email to {email_to}: {e}", exc_info=True)

# Placeholder for a route that might serve a password reset form (frontend concern usually)
@router.get("/password/reset-confirm-form", include_in_schema=False)
async def confirm_password_reset_form_placeholder():
    pass


@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(
    request: Request, # Added Request
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(db_manager.get_session)
):
    try:
        user = await get_user_by_username_or_email(db, username=form_data.username)
        if not user:
            # Log audit event for non-existent user attempt
            await log_audit_event(
                event_type="login_failed_non_existent_user",
                user_id=None, # No user ID available
                details={
                    "email_attempted": form_data.username,
                    "client_ip": request.client.host,
                    "reason": "non_existent_user"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if not user.tenant_id:
            # This case should ideally not happen if user creation enforces tenant association
            logger.error(f"User {user.email} has no tenant_id.")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User configuration error")
        
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
                detail=f"Tenant account is {(tenant.status.value.lower() if tenant else 'invalid')}",
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
                detail=f"Account locked. Try again after {user.locked_until.isoformat()}",
            )

        if not auth_manager.verify_password(form_data.password, user.hashed_password):
            user.failed_login_attempts += 1
            lockout_duration = timedelta()
            event_details_update = {}

            if user.failed_login_attempts >= 15:
                user.locked_until = datetime.max.replace(tzinfo=timezone.utc) # Permanent lock
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

            if lockout_duration.total_seconds() > 0 and not user.locked_until == datetime.max.replace(tzinfo=timezone.utc):
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
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"}
            )

        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc)

        access_token_expires = timedelta(minutes=auth_manager.access_token_expire_minutes)
        session_id = str(uuid4())
        token_data = {
            "sub": str(user.id),
            "user_id": str(user.id),
            "email": user.email,
            "tenant_id": str(user.tenant_id),
            "session_id": session_id, # Include session_id in token
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + access_token_expires
        }

        access_token = auth_manager.create_access_token(
            data=token_data,
            expires_in=access_token_expires,
            tenant_id=str(user.tenant_id),
            roles=[user.role.value],
            scopes=[], # Add scopes if applicable
            session_id=session_id
        )

        refresh_token_raw = auth_manager.create_refresh_token(
            data=token_data, # Use same data for consistency, esp. session_id
            tenant_id=str(user.tenant_id),
            roles=[user.role.value],
            scopes=[],
            session_id=session_id
        )

        if not refresh_token_raw:
            logger.error(f"Failed to generate refresh token for user: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate refresh token"
            )

        refresh_token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
        refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=auth_manager.refresh_token_expire_days)

        new_session = UserSession(
            user_id=user.id,
            session_id=session_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=refresh_expires_at,
            client_ip=request.client.host, # Store client IP with session
            user_agent=request.headers.get("user-agent"), # Store user agent
            is_active=True
        )
        db.add(new_session)
        await db.commit()

        try:
            redis_client = await redis_manager.get_redis()
            if redis_client:
                await redis_client.set(f"refresh_token:{session_id}", refresh_token_raw, ex=int(auth_manager.refresh_token_expire_days * 24 * 60 * 60))
        except Exception as redis_error:
            logger.warning(f"Failed to store refresh token in Redis for session {session_id}: {redis_error}")

        await log_audit_event(
            event_type="user_login_success",
            user_id=str(user.id),
            details={
                "email": user.email,
                "client_ip": request.client.host, 
                "tenant_id": str(user.tenant_id),
                "tenant_status": tenant.status.value,
                "session_id": session_id
            }
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token_raw,
            httponly=True,
            secure=True, # Set to True in production
            samesite="lax", # Can be 'strict' or 'lax'
            path="/auth",
            expires=refresh_expires_at
        )

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=int(access_token_expires.total_seconds()),
            tenant_status=tenant.status.value
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error logging in user: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.post("/logout")
async def logout(
    request: Request, # Added request for IP
    response: Response,
    current_user: BaseUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    try:
        authorization = request.headers.get("Authorization")
        token = None
        if authorization and authorization.startswith("Bearer "):
            token = authorization.split(" ")[1]
        
        session_id_to_revoke = None
        if token:
            try:
                payload = auth_manager.decode_token(token)
                session_id_to_revoke = payload.session_id
            except Exception as e:
                logger.warning(f"Error decoding token during logout for user {current_user.email}: {e}")

        if session_id_to_revoke:
            result = await db.execute(
                select(UserSession).where(
                    UserSession.session_id == session_id_to_revoke,
                    UserSession.user_id == current_user.id # Ensure user owns the session
                )
            )
            session = result.scalar_one_or_none()
            if session:
                session.is_active = False
                session.logged_out_at = datetime.now(timezone.utc)
                await db.commit()
                logger.info(f"User session {session_id_to_revoke} for {current_user.email} marked inactive.")

                try:
                    redis_client = await redis_manager.get_redis()
                    if redis_client:
                        await redis_client.delete(f"refresh_token:{session_id_to_revoke}")
                except Exception as redis_error:
                    logger.warning(f"Failed to delete refresh token from Redis for session {session_id_to_revoke}: {redis_error}")
            else:
                logger.warning(f"No active session found for session_id {session_id_to_revoke} and user {current_user.email} during logout.")
        else:
            logger.warning(f"Could not determine session_id from token for user {current_user.email} during logout.")

        await log_audit_event(
            event_type="user_logout_success",
            user_id=str(current_user.id),
            details={
                "email": current_user.email,
                "client_ip": request.client.host, # Added client_ip
                "session_id_revoked": session_id_to_revoke
            }
        )
        response.delete_cookie(key="refresh_token", path="/auth")
        return {"message": "Logged out successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error logging out user {current_user.email}: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    request: Request, # Added request for IP and headers
    response: Response,
    db: AsyncSession = Depends(db_manager.get_session)
):
    auth_header = request.headers.get("Authorization")
    logger.info(f"--- P1 Action: /auth/refresh received Authorization header: {auth_header}")
    try:
        refresh_token_raw = request.cookies.get("refresh_token")

        # If cookie is not present, check Authorization header for Bearer token
        if not refresh_token_raw:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                refresh_token_raw = auth_header.split(" ")[1]

        if not refresh_token_raw:
            await log_audit_event(
                event_type="token_refresh_failed",
                user_id=None,
                details={
                    "client_ip": request.client.host,
                    "reason": "empty_refresh_token_in_header"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token must be provided in Authorization header as Bearer token",
                headers={"WWW-Authenticate": "Bearer"}
            )

        try:
            token_payload = auth_manager.decode_token(refresh_token_raw, is_refresh=True)
        except Exception as e: # Catch specific JoseErrors if possible
            await log_audit_event(
                event_type="token_refresh_failed",
                user_id=getattr(token_payload, "user_id", None) if 'token_payload' in locals() else None,
                details={
                    "client_ip": request.client.host,
                    "reason": "invalid_or_expired_refresh_token",
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if not token_payload or not token_payload.user_id or not token_payload.session_id:
            await log_audit_event(
                event_type="token_refresh_failed",
                user_id=token_payload.user_id if token_payload else None,
                details={
                    "client_ip": request.client.host,
                    "reason": "incomplete_refresh_token_payload"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token payload",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Validate session from DB
        refresh_token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
        session_query = select(UserSession).where(
            UserSession.session_id == token_payload.session_id,
            UserSession.user_id == token_payload.user_id,
            UserSession.refresh_token_hash == refresh_token_hash, # Match the exact token
            UserSession.is_active == True,
            UserSession.expires_at > datetime.now(timezone.utc)
        )
        result = await db.execute(session_query)
        session = result.scalar_one_or_none()

        if not session:
            await log_audit_event(
                event_type="token_refresh_failed",
                user_id=str(token_payload.user_id),
                details={
                    "client_ip": request.client.host,
                    "session_id": token_payload.session_id,
                    "reason": "session_not_found_or_inactive_or_expired_or_mismatched_token"
                }
            )
            # Optional: blacklist the token if a valid session is not found for it
            # await blacklist_token(token_payload.jti) # Assuming jti is in refresh token
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token is invalid, session not found, or session expired.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        user = await db.get(User, token_payload.user_id)
        if not user or not user.is_active:
            await log_audit_event(
                event_type="token_refresh_failed",
                user_id=str(token_payload.user_id),
                details={
                    "client_ip": request.client.host,
                    "session_id": token_payload.session_id,
                    "reason": "user_not_found_or_inactive"
                }
            )
            session.is_active = False # Deactivate session if user is inactive
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="User account is inactive or not found."
            )
        
        tenant = await db.get(Tenant, user.tenant_id)
        if not tenant or tenant.status != TenantStatus.ACTIVE:
            await log_audit_event(
                event_type="token_refresh_failed",
                user_id=str(user.id),
                details={
                    "email": user.email,
                    "client_ip": request.client.host,
                    "tenant_id": str(user.tenant_id),
                    "tenant_status": tenant.status.value if tenant else 'None',
                    "reason": "inactive_tenant_on_refresh"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Tenant account is {(tenant.status.value.lower() if tenant else 'invalid')}",
            )

        # Create new access token
        access_token_expires = timedelta(minutes=auth_manager.access_token_expire_minutes)
        new_access_token_data = {
            "sub": str(user.id),
            "user_id": str(user.id),
            "email": user.email,
            "tenant_id": str(user.tenant_id),
            "session_id": token_payload.session_id, # Carry over session_id
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + access_token_expires).timestamp())
        }
        

        new_access_token = auth_manager.create_access_token(
            data=new_access_token_data,
            expires_in=access_token_expires,
            tenant_id=str(user.tenant_id),
            roles=[str(user.role.value)],
            scopes=token_payload.scopes or [],
            session_id=token_payload.session_id
        )
        
        # Update session last activity
        session.last_activity_at = datetime.now(timezone.utc)
        session.client_ip = request.client.host # Update IP on refresh
        session.user_agent = request.headers.get("user-agent") # Update user agent
        await db.commit()

        await log_audit_event(
            event_type="token_refresh_success",
            user_id=str(user.id),
            details={
                "email": user.email,
                "client_ip": request.client.host,
                "session_id": token_payload.session_id,
                "tenant_id": str(user.tenant_id)
            }
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token_raw,
            httponly=True,
            secure=True, # Set to True in production
            samesite="lax",
            path="/auth",
            expires=session.expires_at
        )

        return TokenResponse(
            access_token=new_access_token,
            token_type="bearer",
            expires_in=int(access_token_expires.total_seconds()),
            tenant_status=tenant.status.value
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing token: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not refresh token"
        )

@router.post("/password/change")
async def change_password(
    request: Request, # Added request for IP
    password_change: PasswordChange,
    current_user: BaseUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    try:
        if not auth_manager.verify_password(password_change.current_password, current_user.hashed_password):
            await log_audit_event(
                event_type="password_change_failed",
                user_id=str(current_user.id),
                details={
                    "email": current_user.email,
                    "client_ip": request.client.host,
                    "reason": "incorrect_current_password"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        current_user.hashed_password = auth_manager.hash_password(password_change.new_password)
        current_user.password_last_changed_at = datetime.now(timezone.utc)
        current_user.failed_login_attempts = 0 # Reset on successful password change
        current_user.locked_until = None

        await db.commit()
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
        logger.error(f"Error changing password for user {current_user.email}: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.post("/password/reset-request")
async def request_password_reset(
    request_data: PasswordReset, # Changed from reset_request to avoid conflict with fastapi.Request
    background_tasks: BackgroundTasks,
    http_request: Request, # Added http_request for IP
    db: AsyncSession = Depends(db_manager.get_session)
):
    try:
        user_query = select(User).where(User.email == request_data.email)
        result = await db.execute(user_query)
        user = result.scalar_one_or_none()

        # Always return a generic message to avoid email enumeration
        log_details = {"email_attempted": request_data.email, "client_ip": http_request.client.host}
        if not user or not user.is_active:
            await log_audit_event(
                event_type="password_reset_request_failed_user_not_found_or_inactive",
                user_id=str(user.id) if user else None,
                details=log_details
            )
            logger.info(f"Password reset requested for non-existent or inactive email: {request_data.email}")
            return {"message": "If your email is registered and active, you will receive a password reset link."}

        reset_token_value = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(reset_token_value.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1) # 1 hour expiry

        # Invalidate previous active reset tokens for this user
        await db.execute(
            PasswordResetToken.__table__.update().where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used == False,
                PasswordResetToken.expires_at > datetime.now(timezone.utc)
            ).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)) # Expire them immediately
        )

        new_token = PasswordResetToken(
            user_id=user.id,
            token=token_hash,
            expires_at=expires_at,
            used=False
        )
        db.add(new_token)
        await db.commit()

        # Send password reset email in the background
        background_tasks.add_task(send_password_reset_email_async, user.email, reset_token_value, http_request)
        # logger.info(f"Password reset token generated for {user.email}. Token: {reset_token_value} (actual token, not hash)") # Removed for security

        await log_audit_event(
            event_type="password_reset_request_success",
            user_id=str(user.id),
            details=log_details
        )
        return {"message": "If your email is registered and active, you will receive a password reset link."}
    except Exception as e:
        logger.error(f"Error requesting password reset for {request_data.email}: {e}", exc_info=True)
        await db.rollback()
        # Do not expose internal errors for this endpoint to prevent info leakage
        return {"message": "An error occurred. If the problem persists, please contact support."}

@router.post("/password/reset-confirm")
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirm,
    http_request: Request, # Added http_request for IP
    db: AsyncSession = Depends(db_manager.get_session)
):
    try:
        token_hash = hashlib.sha256(reset_confirm.token.encode()).hexdigest()

        token_query = select(PasswordResetToken).where(
            PasswordResetToken.token == token_hash,
            PasswordResetToken.used == False,
            PasswordResetToken.expires_at > datetime.now(timezone.utc)
        )
        result = await db.execute(token_query)
        token_record = result.scalar_one_or_none()

        log_details = {"client_ip": http_request.client.host, "token_used_attempt": reset_confirm.token[:8] + "..."}

        if not token_record:
            await log_audit_event(
                event_type="password_reset_confirm_failed_invalid_token",
                user_id=None, # User unknown at this point
                details=log_details
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset token."
            )

        user = await db.get(User, token_record.user_id)
        if not user or not user.is_active:
            await log_audit_event(
                event_type="password_reset_confirm_failed_user_not_found_or_inactive",
                user_id=str(token_record.user_id),
                details=log_details
            )
            token_record.used = True # Mark token as used even if user is inactive to prevent reuse
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account not found or is inactive."
            )

        user.hashed_password = auth_manager.hash_password(reset_confirm.new_password)
        user.password_last_changed_at = datetime.now(timezone.utc)
        token_record.used = True
        token_record.used_at = datetime.now(timezone.utc)
        user.failed_login_attempts = 0 # Reset on successful password reset
        user.locked_until = None

        await db.commit()

        log_details["email"] = user.email
        await log_audit_event(
            event_type="password_reset_confirm_success",
            user_id=str(user.id),
            details=log_details
        )
        return {"message": "Password has been reset successfully."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error confirming password reset: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

# Example of a protected endpoint
@router.get("/me", response_model=dict) # Replace dict with a proper UserResponse schema
async def read_users_me(current_user: BaseUser = Depends(get_current_active_user)):
    # This is just an example, you'd return more relevant user info
    return {"user_id": current_user.id, "email": current_user.email, "role": current_user.role.value if hasattr(current_user, 'role') else 'N/A'}