from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime
from uuid import UUID as UUIDType

class OAuthClientCreate(BaseModel):
    redirect_uris: List[str] = Field(..., description="List of allowed redirect URIs")
    grant_types: List[str] = Field(..., description="List of allowed grant types (authorization_code, refresh_token, client_credentials)")
    scopes: List[str] = Field(..., description="List of allowed scopes")
    is_confidential: bool = Field(True, description="Whether this client requires a client_secret")

class OAuthClientUpdate(BaseModel):
    redirect_uris: Optional[List[str]] = None
    grant_types: Optional[List[str]] = None
    scopes: Optional[List[str]] = None

class OAuthClientResponse(BaseModel):
    id: str
    client_id: str
    client_secret: Optional[str] = None
    redirect_uris: List[str]
    grant_types: List[str]
    scopes: List[str]
    is_confidential: bool
    created_at: datetime

    class Config:
        from_attributes = True

class AuthorizationRequest(BaseModel):
    response_type: str = Field(..., description="Must be 'code' for authorization code flow")
    client_id: str
    redirect_uri: str
    scope: Optional[str] = None
    state: Optional[str] = None

class TokenRequest(BaseModel):
    grant_type: str = Field(..., description="One of: authorization_code, refresh_token, client_credentials")
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: str
    client_secret: Optional[str] = None
    refresh_token: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None