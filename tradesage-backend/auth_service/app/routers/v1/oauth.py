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
from typing import Optional, List, Dict, Any

from common.database import db_manager
from common.auth import auth_manager
from common.models import BaseUser, User, Tenant, TenantStatus
from common.config import settings
from common.utils import get_user_by_id, get_user_by_username_or_email
from common.audit_logger import log_audit_event

from auth_service.app.models.oauth_models import OAuthClient
from auth_service.app.models.auth_code_models import AuthCode
from auth_service.app.models.refresh_token_models import RefreshToken
from auth_service.app.models.user_session import UserSession
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
@router.get("/login/google")
async def login_google():
    """
    Initiate Google OAuth flow by redirecting to Google's OAuth consent screen
    """
    # Build the Google OAuth URL
    params = {
        'client_id': settings.google_client_id,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': settings.google_redirect_uri,
        'access_type': 'offline',  # Request refresh token
        'prompt': 'consent',  # Force consent screen to get refresh token
    }
    
    google_auth_url = f"{settings.google_auth_uri}?{urlencode(params)}"
    return RedirectResponse(url=google_auth_url)

@router.get("/google/callback")
async def google_callback(
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
        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                settings.google_token_uri,
                data={
                    'code': code,
                    'client_id': settings.google_client_id,
                    'client_secret': settings.google_client_secret,
                    'redirect_uri': settings.google_redirect_uri,
                    'grant_type': 'authorization_code',
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            )
            
            token_data = token_response.json()
            if 'error' in token_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to get access token: {token_data.get('error_description', 'Unknown error')}"
                )
            
            # Get user info
            user_response = await client.get(
                settings.google_user_info_uri,
                headers={
                    'Authorization': f"Bearer {token_data['access_token']}"
                }
            )
            user_data = user_response.json()
            
            # Check if user exists by email
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
                        "auth_provider_id": user_data['sub']
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
            
            # Generate JWT tokens
            access_token = auth_manager.create_access_token(
                data={
                    "email": user.email,
                    "is_active": user.is_active,
                    "is_verified": user.is_verified,
                    "tenant_id": str(user.tenant_id) if user.tenant_id else None,
                },
                user_id=str(user.id),
                expires_in=timedelta(minutes=settings.access_token_expire_minutes)
            )
            
            refresh_token = auth_manager.create_refresh_token(
                data={"sub": str(user.id)},
                user_id=str(user.id),
                expires_in=timedelta(days=settings.refresh_token_expire_days)
            )
            
            # Get or create Google OAuth client
            from auth_service.app.models.oauth_models import OAuthClient
            
            # Determine a tenant-scoped client_id so each tenant has its own Google client row
            tenant_id_str = str(user.tenant_id) if user.tenant_id else "global"
            client_id_value = f"google-{tenant_id_str}"

            stmt = select(OAuthClient).where(OAuthClient.client_id == client_id_value)
            result = await db.execute(stmt)
            oauth_client = result.scalar_one_or_none()

            if not oauth_client:
                logger.info(f"Creating Google OAuth client for tenant {tenant_id_str}…")
                oauth_client = OAuthClient(
                    client_id=client_id_value,
                    client_secret=None,  # Google handles its own secret
                    redirect_uris=[settings.google_redirect_uri],
                    grant_types=["authorization_code"],
                    scopes=["openid", "email", "profile"],
                    tenant_id=user.tenant_id,
                    is_confidential=False,
                )
                db.add(oauth_client)
                await db.commit()
                await db.refresh(oauth_client)
            
            # Store refresh token in database
            refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
            new_refresh_token = RefreshToken(
                user_id=user.id,
                token=refresh_token_hash,
                client_id=oauth_client.id,
                expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
            )
            db.add(new_refresh_token)
            await db.commit()

            # Create user session entry
            session_id = str(uuid4())
            new_session = UserSession(
                user_id=user.id,
                session_id=session_id,
                refresh_token_hash=refresh_token_hash,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes),
                client_ip=None,
                user_agent=None,
            )
            db.add(new_session)
            await db.commit()
            
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
                "expires_in": settings.access_token_expire_minutes * 60
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
        access_token_expires = timedelta(minutes=auth_manager.access_token_expire_minutes)
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
            expires_in=access_token_expires,
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
            "expires_in": auth_manager.access_token_expire_minutes * 60,
            "refresh_token": refresh_token_raw
        }
        
    elif grant_type == "refresh_token":
        # Validate grant type
        if "refresh_token" not in client.grant_types:
            raise HTTPException(status_code=400, detail="Client not authorized for this grant type")
        
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Refresh token required")
        
        # Validate refresh token
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token == refresh_token_hash,
                RefreshToken.client_id == client.id,
                RefreshToken.expires_at > datetime.now(timezone.utc),
                RefreshToken.revoked == False
            )
        )
        token_record = result.scalar_one_or_none()
        
        if not token_record:
            raise HTTPException(status_code=400, detail="Invalid or expired refresh token")
        
        # Get user
        user = await get_user_by_id(db, token_record.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        
        # Generate new tokens
        access_token_expires = timedelta(minutes=auth_manager.access_token_expire_minutes)
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
            expires_in=access_token_expires,
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
            "expires_in": auth_manager.access_token_expire_minutes * 60,
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
        access_token_expires = timedelta(minutes=auth_manager.access_token_expire_minutes)
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
            expires_in=access_token_expires,
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
            "expires_in": auth_manager.access_token_expire_minutes * 60
        }
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant type")