from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID as UUIDType
import time
import structlog
import traceback
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from prometheus_client import Counter, Histogram, Gauge
import hashlib

# Import JWT error handling
from jose import JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from common.database import db_manager
from common.auth import auth_manager, TokenExpiredError
from common.models import BaseUser, User, Tenant, TenantStatus
from common.audit_logger import log_audit_event
from common.redis_client import redis_manager
from auth_service.app.clients.session_client import session_service_client
from auth_service.app.services.auth_service import is_token_blacklisted

# =============================================================================
# PRODUCTION LOGGING AND MONITORING SETUP
# =============================================================================

logger = structlog.get_logger("tradesage.auth.dependencies")

# Prometheus metrics for dependency monitoring
token_validation_requests = Counter(
    'auth_token_validation_requests_total',
    'Total token validation requests',
    ['status', 'failure_reason']
)

token_validation_duration = Histogram(
    'auth_token_validation_duration_seconds',
    'Token validation duration',
    ['validation_type']
)

active_token_validations = Gauge(
    'auth_active_token_validations',
    'Currently active token validations'
)

dependency_errors = Counter(
    'auth_dependency_errors_total',
    'Authentication dependency errors',
    ['error_type', 'component']
)

# =============================================================================
# OAUTH2 SCHEME CONFIGURATION
# =============================================================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/token",
    scheme_name="JWT",
    auto_error=False  # We'll handle errors manually for better control
)

# =============================================================================
# ENHANCED TOKEN VALIDATION UTILITIES
# =============================================================================

async def validate_token_format(token: str) -> bool:
    """Validate basic token format before processing"""
    if not token:
        return False
    
    # Basic JWT format validation (3 parts separated by dots)
    parts = token.split('.')
    if len(parts) != 3:
        return False
    
    # Check if parts are not empty
    return all(part for part in parts)

async def check_token_blacklist(
    token: str, 
    context_logger: structlog.BoundLogger,
    db: AsyncSession  # ADD THIS PARAMETER
) -> bool:
    """Check if token is blacklisted with proper error handling - FIXED"""
    try:
        is_blacklisted = await is_token_blacklisted(token, db)  # Pass db parameter
        if is_blacklisted:
            context_logger.warning("Token is blacklisted")
            return True
        return False
    except Exception as e:
        context_logger.error(
            "Error checking token blacklist",
            error=str(e),
            traceback=traceback.format_exc()
        )
        dependency_errors.labels(error_type='blacklist_check', component='redis').inc()
        # In case of error, allow the token (fail open) but log the issue
        return False

async def validate_session_existence(session_id: str, user_id: str, context_logger: structlog.BoundLogger) -> bool:
    """Validate that the session exists and belongs to the user"""
    try:
        if not session_id:
            context_logger.warning("No session ID in token")
            return False
        
        session_info = await session_service_client.get_session(session_id)
        if not session_info:
            context_logger.warning("Session not found", session_id=session_id)
            return False
        
        if session_info.get("user_id") != user_id:
            context_logger.warning(
                "Session user mismatch",
                session_id=session_id,
                token_user_id=user_id,
                session_user_id=session_info.get("user_id")
            )
            return False
        
        # Check if session is expired
        expires_at_str = session_info.get("expires_at")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                if expires_at < datetime.now(timezone.utc):
                    context_logger.warning("Session has expired", session_id=session_id)
                    return False
            except ValueError as e:
                context_logger.warning("Invalid session expiration format", error=str(e))
                return False
        
        return True
        
    except Exception as e:
        context_logger.error(
            "Error validating session existence",
            error=str(e),
            traceback=traceback.format_exc()
        )
        dependency_errors.labels(error_type='session_validation', component='session_service').inc()
        return False


def get_request_context(request: Request, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Enhanced request context with better error handling"""
    try:
        return {
            "correlation_id": request.headers.get("X-Correlation-ID", "unknown"),
            "client_ip": getattr(request.client, 'host', 'unknown') if hasattr(request, 'client') else 'unknown',
            "user_agent": request.headers.get("user-agent", "unknown"),
            "method": getattr(request, 'method', 'unknown'),
            "url": str(request.url) if hasattr(request, 'url') else "unknown",
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        # Fallback context if request object is malformed
        return {
            "correlation_id": "error",
            "client_ip": "unknown",
            "user_agent": "unknown", 
            "method": "unknown",
            "url": "unknown",
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "context_error": str(e)
        }


# =============================================================================
# ENHANCED TOKEN DEBUGGING (Production-Safe)
# =============================================================================

def debug_token_validation(token: str, context_logger: structlog.BoundLogger):
    """Production-safe token debugging that doesn't expose sensitive data"""
    try:
        if not token:
            context_logger.debug("No token provided")
            return None
        
        # Basic token structure validation
        parts = token.split('.')
        if len(parts) != 3:
            context_logger.debug("Invalid token structure", parts_count=len(parts))
            return None
        
        # Decode header and payload without verification (for debugging only)
        import base64
        import json
        
        try:
            # Decode header
            header_padding = '=' * (4 - len(parts[0]) % 4)
            header_bytes = base64.urlsafe_b64decode(parts[0] + header_padding)
            header = json.loads(header_bytes.decode('utf-8'))
            
            # Decode payload
            payload_padding = '=' * (4 - len(parts[1]) % 4)
            payload_bytes = base64.urlsafe_b64decode(parts[1] + payload_padding)
            payload = json.loads(payload_bytes.decode('utf-8'))
            
            # Log non-sensitive information
            context_logger.debug(
                "Token structure validation",
                algorithm=header.get('alg'),
                token_type=header.get('typ'),
                has_sub=bool(payload.get('sub')),
                has_exp=bool(payload.get('exp')),
                has_iat=bool(payload.get('iat')),
                has_session_id=bool(payload.get('session_id')),
                exp_timestamp=payload.get('exp'),
                current_timestamp=int(time.time())
            )
            
            return payload
            
        except Exception as decode_error:
            context_logger.debug("Token decode error", error=str(decode_error))
            return None
            
    except Exception as e:
        context_logger.error("Token debugging error", error=str(e))
        return None

# =============================================================================
# ENHANCED DEPENDENCY FUNCTIONS - FIXES ERROR #1
# =============================================================================

async def validate_token_format(token: str) -> bool:
    """Validate basic token format before processing"""
    if not token:
        return False
    
    # Basic JWT format validation (3 parts separated by dots)
    parts = token.split('.')
    if len(parts) != 3:
        return False
    
    # Check if parts are not empty
    return all(part for part in parts)

# Define the OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Enhanced logger setup
logger = structlog.get_logger("tradesage.auth.dependencies")

async def get_current_user_from_access_token(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(db_manager.get_session)
) -> BaseUser:
    """FIXED: Enhanced dependency with proper db parameter passing"""
    start_time = time.time()
    
    # Create request context for logging
    request_context = get_request_context(request)
    context_logger = logger.bind(**request_context)
    
    active_token_validations.inc()
    
    try:
        with token_validation_duration.labels(validation_type='access_token').time():
            context_logger.debug("Starting access token validation")
            
            # Step 1: Basic token validation
            if not token:
                context_logger.warning("No access token provided")
                token_validation_requests.labels(status='failed', failure_reason='no_token').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication token required",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Step 2: Token format validation
            if not await validate_token_format(token):
                context_logger.warning("Invalid token format")
                token_validation_requests.labels(status='failed', failure_reason='invalid_format').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token format",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Step 3: Debug token structure (production-safe)
            debug_token_validation(token, context_logger)
            
            # Step 4: Check token blacklist - FIXED: Pass db parameter
            if await check_token_blacklist(token, context_logger, db):
                token_validation_requests.labels(status='failed', failure_reason='blacklisted').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Step 5: Decode and validate token
            try:
                token_data = auth_manager.decode_token(token, is_refresh=False)
                if not token_data or not token_data.user_id:
                    context_logger.warning("Token validation failed - no token data or user_id")
                    token_validation_requests.labels(status='failed', failure_reason='invalid_token_data').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid token data",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                    
            except TokenExpiredError as e:
                context_logger.warning("Access token expired", error=str(e))
                token_validation_requests.labels(status='failed', failure_reason='token_expired').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Access token has expired. Please refresh your token.",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e
                
            except ExpiredSignatureError as e:
                context_logger.warning("Token signature expired", error=str(e))
                token_validation_requests.labels(status='failed', failure_reason='signature_expired').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token signature expired. Please refresh your token.",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e
                
            except JWTClaimsError as e:
                context_logger.warning("Invalid JWT claims", error=str(e))
                token_validation_requests.labels(status='failed', failure_reason='invalid_claims').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token claims",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e
                
            except JWTError as e:
                context_logger.error("JWT validation error", error=str(e))
                token_validation_requests.labels(status='failed', failure_reason='jwt_error').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate token",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e
            
            # Update context with user information
            request_context["user_id"] = token_data.user_id
            context_logger = logger.bind(**request_context)
            
            # Step 6: Check for impending expiration (enhanced)
            if token_data.exp:
                current_time = time.time()
                time_until_expiry = token_data.exp - current_time
                
                context_logger.debug(
                    "Token expiration check",
                    exp_timestamp=token_data.exp,
                    current_timestamp=current_time,
                    time_until_expiry=time_until_expiry
                )
                
                if time_until_expiry < 0:
                    context_logger.warning("Token has already expired")
                    token_validation_requests.labels(status='failed', failure_reason='token_expired').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token has expired. Please refresh your token.",
                        headers={"WWW-Authenticate": "Bearer"}
                    )
                elif time_until_expiry < 60:  # 1 minute warning for 2-minute tokens
                    context_logger.info(
                        "Access token expiring soon",
                        time_until_expiry=time_until_expiry
                    )
            
            # Step 7: Validate session exists and is valid
            session_id = getattr(token_data, 'session_id', None)
            if session_id:
                if not await validate_session_existence(session_id, token_data.user_id, context_logger):
                    token_validation_requests.labels(status='failed', failure_reason='invalid_session').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session is invalid or expired. Please log in again.",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            
            # Step 8: Fetch and validate user
            try:
                from common.utils import get_user_by_id
                user = await get_user_by_id(db, token_data.user_id)
                if not user:
                    context_logger.error("User not found", user_id=token_data.user_id)
                    token_validation_requests.labels(status='failed', failure_reason='user_not_found').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="User not found",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                
                # Check if user is still active
                if not user.is_active:
                    context_logger.warning("User account is inactive", user_id=token_data.user_id)
                    token_validation_requests.labels(status='failed', failure_reason='user_inactive').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="User account is inactive",
                    )
                
                # Check tenant status if applicable
                if hasattr(user, 'tenant_id') and user.tenant_id:
                    tenant = await db.get(Tenant, user.tenant_id)
                    if not tenant or tenant.status != TenantStatus.ACTIVE:
                        context_logger.warning(
                            "User tenant is inactive",
                            user_id=token_data.user_id,
                            tenant_id=str(user.tenant_id),
                            tenant_status=tenant.status.value if tenant else 'None'
                        )
                        token_validation_requests.labels(status='failed', failure_reason='tenant_inactive').inc()
                        
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="User tenant is inactive",
                        )
                
            except HTTPException:
                raise
            except Exception as e:
                context_logger.error(
                    "Database error during user validation",
                    error=str(e),
                    traceback=traceback.format_exc()
                )
                dependency_errors.labels(error_type='database_error', component='user_fetch').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error during authentication",
                ) from e
            
            # Step 9: Audit successful validation
            duration = time.time() - start_time
            context_logger.info(
                "Access token validation successful",
                user_id=token_data.user_id,
                session_id=session_id,
                duration=f"{duration:.3f}s"
            )
            
            token_validation_requests.labels(status='success', failure_reason='none').inc()
            
            return user
            
    except HTTPException:
        raise
    except Exception as e:
        duration = time.time() - start_time
        context_logger.error(
            "Unexpected error during token validation",
            error=str(e),
            duration=f"{duration:.3f}s",
            traceback=traceback.format_exc()
        )
        
        dependency_errors.labels(error_type='unexpected_error', component='token_validation').inc()
        token_validation_requests.labels(status='failed', failure_reason='unexpected_error').inc()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication",
        ) from e
    finally:
        active_token_validations.dec()

async def get_current_user_from_refresh_token(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(db_manager.get_session)
) -> BaseUser:
    """
    Enhanced dependency to get the current authenticated user from a REFRESH token.
    """
    start_time = time.time()
    
    # Create request context for logging
    request_context = get_request_context(request)
    context_logger = logger.bind(**request_context)
    
    active_token_validations.inc()
    
    try:
        with token_validation_duration.labels(validation_type='refresh_token').time():
            context_logger.debug("Starting refresh token validation")
            
            if not token:
                context_logger.warning("No refresh token provided")
                token_validation_requests.labels(status='failed', failure_reason='no_token').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token required",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Token format validation
            if not await validate_token_format(token):
                context_logger.warning("Invalid refresh token format")
                token_validation_requests.labels(status='failed', failure_reason='invalid_format').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token format",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Debug token structure
            debug_token_validation(token, context_logger)
            
            # Check token blacklist
            if await check_token_blacklist(token, context_logger, db):
                token_validation_requests.labels(status='failed', failure_reason='blacklisted').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Decode and validate refresh token
            try:
                token_data = auth_manager.decode_token(token, is_refresh=True)
                if not token_data or not token_data.user_id:
                    context_logger.warning("Refresh token validation failed - no token data or user_id")
                    token_validation_requests.labels(status='failed', failure_reason='invalid_token_data').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid refresh token data",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                    
            except TokenExpiredError as e:
                context_logger.warning("Refresh token expired", error=str(e))
                token_validation_requests.labels(status='failed', failure_reason='token_expired').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token has expired. Please log in again.",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e
                
            except JWTError as e:
                context_logger.error("JWT validation error for refresh token", error=str(e))
                token_validation_requests.labels(status='failed', failure_reason='jwt_error').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate refresh token",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e
            
            # Update context with user information
            request_context["user_id"] = token_data.user_id
            context_logger = logger.bind(**request_context)
            
            # Validate session if present
            session_id = getattr(token_data, 'session_id', None)
            if session_id:
                if not await validate_session_existence(session_id, token_data.user_id, context_logger):
                    token_validation_requests.labels(status='failed', failure_reason='invalid_session').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session is invalid or expired. Please log in again.",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            
            # Fetch and validate user
            try:
                from common.utils import get_user_by_id
                user = await get_user_by_id(db, token_data.user_id)
                if not user:
                    context_logger.error("User not found for refresh token", user_id=token_data.user_id)
                    token_validation_requests.labels(status='failed', failure_reason='user_not_found').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="User not found",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                
                if not user.is_active:
                    context_logger.warning("User account is inactive for refresh token", user_id=token_data.user_id)
                    token_validation_requests.labels(status='failed', failure_reason='user_inactive').inc()
                    
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="User account is inactive",
                    )
                
            except HTTPException:
                raise
            except Exception as e:
                context_logger.error(
                    "Database error during refresh token user validation",
                    error=str(e),
                    traceback=traceback.format_exc()
                )
                dependency_errors.labels(error_type='database_error', component='user_fetch').inc()
                
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error during refresh token validation",
                ) from e
            
            # Audit successful validation
            duration = time.time() - start_time
            context_logger.info(
                "Refresh token validation successful",
                user_id=token_data.user_id,
                session_id=session_id,
                duration=f"{duration:.3f}s"
            )
            
            token_validation_requests.labels(status='success', failure_reason='none').inc()
            
            return user
            
    except HTTPException:
        raise
    except Exception as e:
        duration = time.time() - start_time
        context_logger.error(
            "Unexpected error during refresh token validation",
            error=str(e),
            duration=f"{duration:.3f}s",
            traceback=traceback.format_exc()
        )
        
        dependency_errors.labels(error_type='unexpected_error', component='refresh_token_validation').inc()
        token_validation_requests.labels(status='failed', failure_reason='unexpected_error').inc()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during refresh token validation",
        ) from e
    finally:
        active_token_validations.dec()

# =============================================================================
# ENHANCED USER ROLE AND STATUS DEPENDENCIES
# =============================================================================

async def get_current_active_user(
    request: Request,
    current_user: BaseUser = Depends(get_current_user_from_access_token)
) -> BaseUser:
    """
    Enhanced dependency to get the current active user with comprehensive validation.
    """
    request_context = get_request_context(request, str(current_user.id))
    context_logger = logger.bind(**request_context)
    
    try:
        context_logger.debug("Validating user active status")
        
        # Double-check user is active (defense in depth)
        if not current_user.is_active:
            context_logger.warning("Inactive user attempted access")
            
            await log_audit_event(
                event_type="inactive_user_access_attempt",
                user_id=str(current_user.id),
                details={
                    "email": current_user.email,
                    **request_context
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )
        
        # Check if user account is locked
        if hasattr(current_user, 'locked_until') and current_user.locked_until:
            if current_user.locked_until > datetime.now(timezone.utc):
                context_logger.warning("Locked user attempted access")
                
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"Account is locked until {current_user.locked_until.isoformat()}"
                )
        
        context_logger.debug("User active status validation passed")
        return current_user
        
    except HTTPException:
        raise
    except Exception as e:
        context_logger.error(
            "Error during active user validation",
            error=str(e),
            traceback=traceback.format_exc()
        )
        dependency_errors.labels(error_type='user_validation', component='active_check').inc()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during user validation"
        ) from e

async def get_current_admin_user(
    request: Request,
    current_user: BaseUser = Depends(get_current_active_user)
) -> BaseUser:
    """
    Enhanced dependency to get the current admin user with comprehensive validation.
    """
    request_context = get_request_context(request, str(current_user.id))
    context_logger = logger.bind(**request_context)
    
    try:
        context_logger.debug("Validating admin user privileges")
        
        # Check admin role
        user_role = getattr(current_user, 'role', None)
        if not user_role or (hasattr(user_role, 'value') and user_role.value != "admin") or (isinstance(user_role, str) and user_role != "admin"):
            context_logger.warning(
                "Non-admin user attempted admin access",
                user_role=user_role.value if hasattr(user_role, 'value') else str(user_role)
            )
            
            await log_audit_event(
                event_type="unauthorized_admin_access_attempt",
                user_id=str(current_user.id),
                details={
                    "email": current_user.email,
                    "user_role": user_role.value if hasattr(user_role, 'value') else str(user_role),
                    **request_context
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrative privileges required"
            )
        
        context_logger.debug("Admin privileges validation passed")
        return current_user
        
    except HTTPException:
        raise
    except Exception as e:
        context_logger.error(
            "Error during admin user validation",
            error=str(e),
            traceback=traceback.format_exc()
        )
        dependency_errors.labels(error_type='role_validation', component='admin_check').inc()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during admin validation"
        ) from e

# =============================================================================
# OPTIONAL DEPENDENCIES FOR FLEXIBLE AUTHENTICATION
# =============================================================================

async def get_current_user_optional(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(db_manager.get_session)
) -> Optional[BaseUser]:
    """
    Optional dependency that returns user if authenticated, None otherwise.
    Useful for endpoints that work with or without authentication.
    """
    if not token:
        return None
    
    try:
        return await get_current_user_from_access_token(request, token, db)
    except HTTPException:
        return None
    except Exception:
        return None

# =============================================================================
# HEALTH CHECK DEPENDENCY
# =============================================================================

async def get_dependency_health() -> Dict[str, Any]:
    """Get health status of authentication dependencies"""
    health_status = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies": {
            "database": "unknown",
            "redis": "unknown",
            "session_service": "unknown"
        }
    }
    
    # Check database
    try:
        async with db_manager.get_session() as db:
            await db.execute("SELECT 1")
        health_status["dependencies"]["database"] = "healthy"
    except Exception:
        health_status["dependencies"]["database"] = "unhealthy"
    
    # Check Redis
    try:
        redis_client = await redis_manager.get_redis()
        if redis_client:
            await redis_client.ping()
            health_status["dependencies"]["redis"] = "healthy"
        else:
            health_status["dependencies"]["redis"] = "unavailable"
    except Exception:
        health_status["dependencies"]["redis"] = "unhealthy"
    
    # Check session service
    try:
        # This would be a health check specific to your session service
        # For now, we'll assume it's healthy if we can import the client
        health_status["dependencies"]["session_service"] = "healthy"
    except Exception:
        health_status["dependencies"]["session_service"] = "unhealthy"
    
    return health_status