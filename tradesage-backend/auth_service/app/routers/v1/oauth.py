from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Form, Query
from fastapi.security import OAuth2PasswordBearer
from starlette.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
from uuid import UUID as UUIDType, uuid4
import secrets
import hashlib
import base64
import logging
import json
import httpx
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from typing import Optional, List, Dict, Any, cast

from common.circuit_breaker import CircuitBreakers, CircuitBreakerError

from common.database import db_manager
from common.auth import auth_manager
from common.models import BaseUser, User, Tenant, TenantStatus
from common.config import settings
from common.utils import get_user_by_id, get_user_by_username_or_email
from common.audit_logger import log_audit_event

from auth_service.app.models.oauth_models import OAuthClient
from auth_service.app.models.auth_code_models import AuthCode
from auth_service.app.clients.session_client import session_service_client
from auth_service.app.dependencies import get_current_active_user, get_current_admin_user
from auth_service.app.services.auth_service import blacklist_token

# Import Pydantic models
from auth_service.app.schemas.oauth import (
    OAuthClientCreate,
    OAuthClientResponse,
    OAuthClientUpdate,
    AuthorizationRequest,
    TokenRequest,
    TokenResponse
)

router = APIRouter(prefix="/oauth", tags=["oauth"])
logger = logging.getLogger("tradesage.oauth")

# OAuth Client Management Endpoints
@router.post("/clients", response_model=OAuthClientResponse)
async def create_oauth_client(
    client_data: OAuthClientCreate,
    current_user: BaseUser = Depends(get_current_admin_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    """Create a new OAuth client (admin only)"""
    client_id = secrets.token_urlsafe(32)
    client_secret = secrets.token_urlsafe(64) if client_data.is_confidential else None
    
    new_client = OAuthClient(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=client_data.redirect_uris,
        grant_types=client_data.grant_types,
        scopes=client_data.scopes,
        is_confidential=client_data.is_confidential
    )
    
    db.add(new_client)
    await db.commit()
    await db.refresh(new_client)
    
    await log_audit_event(
        event_type="oauth_client_created",
        user_id=str(current_user.id),
        details={
            "client_id": client_id,
            "grant_types": client_data.grant_types,
            "is_confidential": client_data.is_confidential
        }
    )
    
    # Include client_secret in response but never again
    return OAuthClientResponse(
        id=str(new_client.id),
        client_id=new_client.client_id,
        client_secret=client_secret,  # Only returned once upon creation
        redirect_uris=new_client.redirect_uris,
        grant_types=new_client.grant_types,
        scopes=new_client.scopes,
        is_confidential=new_client.is_confidential,
        created_at=new_client.created_at
    )

@router.get("/clients", response_model=List[OAuthClientResponse])
async def list_oauth_clients(
    current_user: BaseUser = Depends(get_current_admin_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    """List all OAuth clients (admin only)"""
    result = await db.execute(select(OAuthClient))
    clients = result.scalars().all()
    
    return [
        OAuthClientResponse(
            id=str(client.id),
            client_id=client.client_id,
            client_secret=None,  # Never return client_secret after creation
            redirect_uris=client.redirect_uris,
            grant_types=client.grant_types,
            scopes=client.scopes,
            is_confidential=client.is_confidential,
            created_at=client.created_at
        ) for client in clients
    ]

@router.get("/clients/{client_id}", response_model=OAuthClientResponse)
async def get_oauth_client(
    client_id: str,
    current_user: BaseUser = Depends(get_current_admin_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    """Get a specific OAuth client (admin only)"""
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(status_code=404, detail="OAuth client not found")
    
    return OAuthClientResponse( 
        id=str(client.id),
        client_id=client.client_id,
        client_secret=None,  # Never return client_secret after creation
        redirect_uris=client.redirect_uris,
        grant_types=client.grant_types,
        scopes=client.scopes,
        is_confidential=client.is_confidential,
        created_at=client.created_at
    )

@router.put("/clients/{client_id}", response_model=OAuthClientResponse)
async def update_oauth_client(
    client_id: str,
    client_data: OAuthClientUpdate,
    current_user: BaseUser = Depends(get_current_admin_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    """Update an OAuth client (admin only)"""
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(status_code=404, detail="OAuth client not found")
    
    # Update fields
    if client_data.redirect_uris is not None:
        client.redirect_uris = client_data.redirect_uris
    if client_data.grant_types is not None:
        client.grant_types = client_data.grant_types
    if client_data.scopes is not None:
        client.scopes = client_data.scopes
    
    await db.commit()
    await db.refresh(client)
    
    await log_audit_event(
        event_type="oauth_client_updated",
        user_id=str(current_user.id),
        details={
            "client_id": client_id,
            "updated_fields": [k for k, v in client_data.dict(exclude_unset=True).items() if v is not None]
        }
    )
    
    return OAuthClientResponse(
        id=str(client.id),
        client_id=client.client_id,
        client_secret=None,
        redirect_uris=client.redirect_uris,
        grant_types=client.grant_types,
        scopes=client.scopes,
        is_confidential=client.is_confidential,
        created_at=client.created_at
    )

@router.delete("/clients/{client_id}")
async def delete_oauth_client(
    client_id: str,
    current_user: BaseUser = Depends(get_current_admin_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    """Delete an OAuth client (admin only)"""
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(status_code=404, detail="OAuth client not found")
    
    await db.delete(client)
    await db.commit()
    
    await log_audit_event(
        event_type="oauth_client_deleted",
        user_id=str(current_user.id),
        details={"client_id": client_id}
    )
    
    return {"message": "OAuth client deleted successfully"}

# Google OAuth Endpoints
@CircuitBreakers.oauth_provider()
async def exchange_google_code_for_token(client: httpx.AsyncClient, code: str) -> dict[str, Any]:
    """Exchange Google OAuth code for access token with circuit breaker protection."""
    try:
        # Use the correct settings from config
        client_id = settings.google_client_id or settings.GOOGLE_OAUTH_CLIENT_ID
        client_secret = settings.google_client_secret or settings.GOOGLE_OAUTH_CLIENT_SECRET
        redirect_uri = settings.google_redirect_uri or settings.GOOGLE_OAUTH_REDIRECT_URI
        
        if not client_id or not client_secret or not redirect_uri:
            logger.error("Google OAuth credentials not properly configured")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="OAuth configuration error"
            )
            
        token_url = settings.google_token_uri
        data = {
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code"
        }
        
        logger.debug(f"Exchanging Google OAuth code. URL: {token_url}, Redirect URI: {redirect_uri}")
        response = await client.post(token_url, data=data, timeout=10.0)
        
        # Log the full error response for debugging
        if response.status_code != 200:
            error_detail = response.text
            logger.error(f"Google OAuth token exchange failed: {response.status_code} - {error_detail}")
            
        response.raise_for_status()
        return cast(dict[str, Any], response.json())
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during Google OAuth token exchange: {str(e)}")
        if hasattr(e, 'response') and e.response:
            logger.error(f"Response content: {e.response.text}")
        raise
    except Exception as e:
        logger.error(f"Failed to exchange Google OAuth code: {str(e)}", exc_info=True)
        raise

@CircuitBreakers.oauth_provider()
async def get_google_user_info(client: httpx.AsyncClient, access_token: str) -> dict[str, Any]:
    """Fetch Google user info with circuit breaker protection."""
    try:
        # Try v3 endpoint first
        user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = await client.get(user_info_url, headers=headers, timeout=10.0)
        response.raise_for_status()
        user_data = cast(dict[str, Any], response.json())
        
        # Log the received data for debugging
        logger.debug(f"Received user data from Google: {user_data}")
        
        # Validate required fields
        required_fields = ['sub', 'email']
        missing_fields = [field for field in required_fields if field not in user_data]
        
        if missing_fields:
            # If v3 endpoint didn't provide required fields, try v2 as fallback
            user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            response = await client.get(user_info_url, headers=headers, timeout=10.0)
            response.raise_for_status()
            user_data = cast(dict[str, Any], response.json())
            
            # Check again for required fields
            missing_fields = [field for field in required_fields if field not in user_data]
            if missing_fields:
                logger.error(f"Missing required fields in Google user data: {missing_fields}")
                logger.debug(f"Received user data: {user_data}")
                raise ValueError(f"Missing required fields from Google: {', '.join(missing_fields)}")
        
        # Add additional profile information if available
        if 'name' not in user_data and ('given_name' in user_data or 'family_name' in user_data):
            name_parts = []
            if 'given_name' in user_data:
                name_parts.append(user_data['given_name'])
            if 'family_name' in user_data:
                name_parts.append(user_data['family_name'])
            user_data['name'] = ' '.join(name_parts)
            
        return user_data
    except Exception as e:
        logger.error(f"Failed to fetch Google user info: {str(e)}", exc_info=True)
        raise


@router.get("/login/google")
async def login_google():
    """
    Initiate Google OAuth flow by redirecting to Google's OAuth consent screen
    """
    # Get the correct client ID and redirect URI from settings
    client_id = settings.google_client_id or settings.GOOGLE_OAUTH_CLIENT_ID
    redirect_uri = settings.google_redirect_uri or settings.GOOGLE_OAUTH_REDIRECT_URI
    
    if not client_id or not redirect_uri:
        logger.error("Google OAuth client_id or redirect_uri not configured")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth configuration error"
        )
    
    # Build the Google OAuth URL with required scopes
    params = {
        'client_id': client_id,
        'response_type': 'code',
        'scope': 'openid email profile https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
        'redirect_uri': redirect_uri,
        'access_type': 'offline',  # Request refresh token
        'prompt': 'consent',  # Force consent screen to get refresh token
        'include_granted_scopes': 'true'  # Include any previously granted scopes
    }
    
    logger.debug(f"Initiating Google OAuth flow with client_id: {client_id}, redirect_uri: {redirect_uri}")
    google_auth_url = f"{settings.google_auth_uri}?{urlencode(params)}"
    return RedirectResponse(url=google_auth_url)

@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: str,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: AsyncSession = Depends(db_manager.get_session)
):
    """
    Handle the callback from Google OAuth
    """
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth error: {error}"
        )

    try:
        # Exchange authorization code for tokens
        try:
            async with httpx.AsyncClient() as client:
                token_data = await exchange_google_code_for_token(client, code)
                user_data = await get_google_user_info(client, token_data['access_token'])
        except CircuitBreakerError as e:
            logger.error(f"Circuit breaker open for Google OAuth: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable. Please try again later."
            )
        except ValueError as e:
            logger.error(f"Invalid user data from Google: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Received invalid user data from Google. Please try again."
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during Google OAuth flow: {e.response.text}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Error communicating with Google OAuth service."
            )
        else:
            # ---------------------
            # User processing logic
            # ---------------------
            # Check if user exists by email
            if 'email' not in user_data:
                logger.error("No email in Google user data")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email address is required for registration"
                )
                
            user = await get_user_by_username_or_email(db, user_data['email'])
            
            if not user:
                # Create new user
                tenant = Tenant(
                    name=user_data['email'].split('@')[0],
                    schema_name=f"tenant_{str(uuid4()).replace('-', '_')}",
                    status=TenantStatus.ACTIVE,
                )
                db.add(tenant)
                await db.flush()

                # Create Postgres schema for this tenant
                try:
                    await db_manager.create_tenant_schema(db, str(tenant.id))
                except Exception as schema_error:
                    logger.error(f"Schema creation failed for tenant {tenant.id}: {schema_error}")
                    await db.rollback()
                    raise HTTPException(status_code=500, detail="Failed to create tenant schema")
                
                # Get optional user fields with safe defaults
                user = User(
                    email=user_data['email'],
                    username=user_data['email'].split('@')[0],
                    hashed_password=auth_manager.hash_password(secrets.token_urlsafe(32)),
                    first_name=user_data.get('given_name', ''),
                    last_name=user_data.get('family_name', ''),
                    is_verified=True,  # Google-verified emails are considered verified
                    is_active=True,
                    tenant_id=tenant.id,
                    user_metadata={
                        "auth_provider": "google",
                        "auth_provider_id": user_data['sub']  # We know this exists from validation
                    }
                )
                db.add(user)
                await db.commit()
                await db.refresh(user)
                
                # Log user creation
                await log_audit_event(
                    event_type="user_created",
                    user_id=str(user.id),
                    details={"provider": "google"}
                )
            
            # Create session via session service to get a session_id
            session_response = await session_service_client.create_session(
                user_id=str(user.id),
                client_ip=request.client.host if request else "N/A",
                user_agent=request.headers.get("user-agent", "N/A")
            )

            # Fallback mechanism for session service failures
            session_id = None
            if session_response and "session_token" in session_response:
                session_id = session_response["session_token"]
                logger.info(f"Session created successfully via session service for user {user.id}")
            else:
                # Fallback: Generate a temporary session ID for token creation
                # This allows OAuth to complete even if session service is down
                session_id = str(uuid4())
                logger.warning(f"Session service unavailable, using fallback session ID for user {user.id}: {session_id}")

            # Create access and refresh tokens using the session_id (real or fallback)
            access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = auth_manager.create_access_token(
                data={"sub": str(user.id), "session_id": session_id},
                user_id=str(user.id),
                session_id=session_id,
                expires_in=access_token_expires
            )
            
            refresh_token = auth_manager.create_refresh_token(
                data={"sub": str(user.id), "session_id": session_id},
                user_id=str(user.id),
                session_id=session_id,
                expires_in=timedelta(days=settings.refresh_token_expire_days)
            )

            # Only attempt session update if we have a real session (not fallback)
            if session_response and "session_token" in session_response:
                # Update the session with the refresh token hash
                refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
                expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
                
                update_success = await session_service_client.update_session(
                    session_token=session_id,
                    data={
                        "refresh_token_hash": refresh_token_hash,
                        "expires_at": expires_at.isoformat(),
                    }
                )

                if not update_success:
                    logger.warning(f"Failed to update session {session_id} with refresh token for user {user.id}, but continuing with OAuth flow")
            else:
                logger.info(f"Using fallback session - skipping session service update for user {user.id}")
            
            await db.commit() # Commit any user/tenant changes from earlier
            
            # Log successful login
            await log_audit_event(
                event_type="login_success",
                user_id=str(user.id),
                details={"provider": "google"}
            )
            
            # Redirect to frontend with tokens in URL fragment
            redirect_url = f"{settings.frontend_url}/auth/callback"
            
            # Add tokens to URL fragment
            fragment = urlencode({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            })
            
            logger.info(f"Redirecting to frontend: {redirect_url}")
            return RedirectResponse(f"{redirect_url}#{fragment}")
            
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during Google OAuth: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Error communicating with Google OAuth service"
        )
    except Exception as e:
        logger.error(f"Error during Google OAuth: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during authentication"
        )

# OAuth Authorization Code Flow Endpoints
@router.get("/authorize")
async def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str = Query(...),
    code_challenge_method: str = Query(...),
    scope: Optional[str] = None,
    state: Optional[str] = None,
    current_user: BaseUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    """OAuth 2.0 Authorization Endpoint"""
    # Validate response_type
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response type")
    
    # Validate client
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client")
    
    # Validate redirect_uri
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect URI")
    
    # Validate PKCE parameters
    if code_challenge_method not in ["S256", "plain"]:
        raise HTTPException(status_code=400, detail="Unsupported code_challenge_method. Must be 'S256' or 'plain'.")

    # Validate grant type
    if "authorization_code" not in client.grant_types:
        raise HTTPException(status_code=400, detail="Client not authorized for this grant type")
    
    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    code_hash = hashlib.sha256(auth_code.encode()).hexdigest()
    
    # Store authorization code
    new_auth_code = AuthCode(
        user_id=current_user.id,
        client_id=client.id,
        code=code_hash,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    
    db.add(new_auth_code)
    await db.commit()
    
    # Log the authorization
    await log_audit_event(
        event_type="oauth_authorization",
        user_id=str(current_user.id),
        details={
            "client_id": client_id,
            "scopes": scope,
            "grant_type": "authorization_code",
            "client_ip": request.client.host
        }
    )
    
    # Redirect with code
    redirect_url = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_url += f"&state={state}"
    
    return Response(status_code=302, headers={"Location": redirect_url})

@router.post("/token", response_model=TokenResponse)
async def token(
    request: Request, # Added request parameter
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    db: AsyncSession = Depends(db_manager.get_session)
):
    """OAuth 2.0 Token Endpoint"""
    # Validate client
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client")
    
    # Validate client authentication for confidential clients
    if client.is_confidential and (not client_secret or client_secret != client.client_secret):
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    # Handle different grant types
    if grant_type == "authorization_code":
        # Validate grant type
        if "authorization_code" not in client.grant_types:
            raise HTTPException(status_code=400, detail="Client not authorized for this grant type")
        
        if not code or not redirect_uri:
            raise HTTPException(status_code=400, detail="Code and redirect_uri required")
        
        # Validate code
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        result = await db.execute(
            select(AuthCode).where(
                AuthCode.code == code_hash,
                AuthCode.client_id == client.id,
                AuthCode.redirect_uri == redirect_uri,
                AuthCode.expires_at > datetime.now(timezone.utc)
            )
        )
        auth_code = result.scalar_one_or_none()
        
        if not auth_code:
            raise HTTPException(status_code=400, detail="Invalid or expired code")

        # PKCE Verification
        if not code_verifier:
            raise HTTPException(status_code=400, detail="Code verifier required")

        if auth_code.code_challenge_method == "S256":
            hashed_verifier = hashlib.sha256(code_verifier.encode('utf-8')).digest()
            expected_challenge = base64.urlsafe_b64encode(hashed_verifier).rstrip(b'=').decode('utf-8')
        elif auth_code.code_challenge_method == "plain":
            expected_challenge = code_verifier
        else:
            # This case should ideally not be reached if /authorize validates method
            raise HTTPException(status_code=500, detail="Unsupported code_challenge_method stored")

        if expected_challenge != auth_code.code_challenge:
            await log_audit_event(
                event_type="oauth_pkce_validation_failed",
                user_id=str(auth_code.user_id) if auth_code.user_id else None,
                details={
                    "client_id": client_id,
                    "reason": "Code verifier does not match code challenge",
                    "client_ip": request.client.host
                }
            )
            raise HTTPException(status_code=400, detail="Invalid code verifier")
        
        # Get user
        user = await get_user_by_id(db, auth_code.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        
        # Generate tokens
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "tenant_id": str(user.tenant_id),
            "user_id": str(user.id),
            "client_id": client_id,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + access_token_expires
        }
        
        access_token = auth_manager.create_access_token(
            data=token_data,
            expires_in=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            tenant_id=str(user.tenant_id),
            roles=[user.role.value],
            scopes=[],
            session_id=None
        )
        
        refresh_token_raw = auth_manager.create_refresh_token(
            data=token_data,
            tenant_id=str(user.tenant_id),
            roles=[user.role.value],
            scopes=[],
            session_id=None
        )
        
        # Store refresh token
        refresh_token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
        new_refresh_token = RefreshToken(
            user_id=user.id,
            token=refresh_token_hash,
            client_id=client.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        db.add(new_refresh_token)
        
        # Delete used auth code
        await db.delete(auth_code)
        await db.commit()
        
        # Log token issuance
        await log_audit_event(
            event_type="oauth_token_issued",
            user_id=str(user.id),
            details={
                "client_id": client_id,
                "grant_type": "authorization_code",
                "client_ip": request.client.host
            }
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": refresh_token_raw
        }
        
    elif grant_type == "refresh_token":
        # Validate grant type
        if "refresh_token" not in client.grant_types:
            raise HTTPException(status_code=400, detail="Client not authorized for this grant type")
        
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Refresh token required")

        # First, decode the token to validate signature, expiry, audience, and type
        try:
            payload = auth_manager.decode_token(refresh_token, is_refresh=True)
            if not payload or not payload.user_id:
                raise HTTPException(status_code=400, detail="Invalid refresh token payload")
        except Exception: # Catches JWTError from decode_token
             raise HTTPException(status_code=400, detail="Invalid or expired refresh token")

        # Second, check if the token is revoked in the database (rotation)
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token == refresh_token_hash,
                RefreshToken.client_id == client.id,
                RefreshToken.user_id == payload.user_id,
                RefreshToken.revoked == False
            )
        )
        token_record = result.scalar_one_or_none()

        if not token_record:
            # This could mean the token was already used (rotated)
            await log_audit_event(
                event_type="oauth_revoked_token_used",
                user_id=str(payload.user_id),
                details={
                    "client_id": client_id,
                    "reason": "Attempt to use a revoked or invalid refresh token.",
                    "client_ip": request.client.host
                }
            )
            raise HTTPException(status_code=400, detail="Invalid or expired refresh token")

        # Get user
        user = await get_user_by_id(db, payload.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        
        # Generate new tokens
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "tenant_id": str(user.tenant_id),
            "user_id": str(user.id),
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + access_token_expires
        }
        
        access_token = auth_manager.create_access_token(
            data=token_data,
            expires_in=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            tenant_id=str(user.tenant_id),
            roles=[user.role.value],
            scopes=[],
            session_id=None
        )
        
        new_refresh_token_raw = auth_manager.create_refresh_token(
            data=token_data,
            tenant_id=str(user.tenant_id),
            roles=[user.role.value],
            scopes=[],
            session_id=None
        )
        
        # Revoke old refresh token and store new one
        token_record.revoked = True
        
        new_refresh_token_hash = hashlib.sha256(new_refresh_token_raw.encode()).hexdigest()
        new_refresh_token = RefreshToken(
            user_id=user.id,
            token=new_refresh_token_hash,
            client_id=client.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        db.add(new_refresh_token)
        await db.commit()
        
        # Log token refresh
        await log_audit_event(
            event_type="oauth_token_refreshed",
            user_id=str(user.id),
            details={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "client_ip": request.client.host
            }
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": new_refresh_token_raw
        }
        
    elif grant_type == "client_credentials":
        # Validate grant type
        if "client_credentials" not in client.grant_types:
            raise HTTPException(status_code=400, detail="Client not authorized for this grant type")
        
        # Client credentials must be confidential
        if not client.is_confidential:
            raise HTTPException(status_code=400, detail="Client must be confidential for client credentials grant")
        
        # Generate access token (no refresh token for client credentials)
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = {
            "sub": client_id,  # Use client_id as subject
            "client_id": client_id,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + access_token_expires
        }
        
        access_token = auth_manager.create_access_token(
            data={
                "user_id": str(user.id),
                "client_id": client_id,
                "iat": datetime.now(timezone.utc),
                "exp": datetime.now(timezone.utc) + access_token_expires
            },
            expires_in=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            tenant_id=None,  # No tenant for client credentials
            roles=[],
            scopes=client.scopes,  # Use client's allowed scopes
            session_id=None
        )
        
        # Log token issuance
        await log_audit_event(
            event_type="oauth_token_issued",
            user_id=None,  # No user for client credentials
            details={
                "client_id": client_id,
                "grant_type": "client_credentials",
                "client_ip": request.client.host
            }
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant type")