from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from jose import JWTError, jwt

class TokenExpiredError(Exception):
    """"
    Custom exception for expired tokens.

    This exception is raised when a JWT token has passed its expiration time.
    It can optionally carry details about the token for logging and error handling.

    Attributes:
        message (str): A human-readable error message.
        token_type (Optional[str]): The type of token that expired (e.g., 'access', 'refresh').
        expired_at (Optional[datetime]): The timestamp when the token expired.
    """

    def __init__(
        self,
        message: str = "Token has expired",
        token_type: Optional[str] = None,
        expired_at: Optional[datetime] = None,
    ):
        self.message = message
        self.token_type = token_type
        self.expired_at = expired_at
        super().__init__(self.message)

    def __str__(self) -> str:
        """Provide a detailed string representation."""
        details = [f"message='{self.message}'"]
        if self.token_type:
            details.append(f"token_type='{self.token_type}'")
        if self.expired_at:
            details.append(f"expired_at='{self.expired_at.isoformat()}'")
        return f"TokenExpiredError({', '.join(details)})"
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict
import secrets
import logging
import base64
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from .config import settings
from .logger import logger

# ────────────────────────────────────────────────────────────────────────────────
# Audience constants to avoid typos
# ────────────────────────────────────────────────────────────────────────────────



# ────────────────────────────────────────────────────────────────────────────────
# Pydantic models for token payload and response
# ────────────────────────────────────────────────────────────────────────────────
class TokenData(BaseModel):
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    scopes: List[str] = []
    roles: List[str] = []
    session_id: Optional[str] = None
    expires_in: Optional[datetime] = None
    jti: Optional[str] = None
    token_type: Optional[str] = None
    ver: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

    model_config = ConfigDict(from_attributes=True)


# ────────────────────────────────────────────────────────────────────────────────
# AuthManager: handles password hashing, token creation, and token verification
# ────────────────────────────────────────────────────────────────────────────────
class AuthManager:
    def __init__(self, private_key_path: str, public_key_path: str, algorithm: str = "ES256"):
        """
        Initialize AuthManager with key paths and algorithm.

        Args:
            private_key_path: Path to private key file
            public_key_path: Path to public key file  
            algorithm: JWT algorithm, default "ES256"
        """
        self.algorithm = algorithm

        # Load keys from files
        raw_private_key_bytes = self._load_key(private_key_path, "private")
        self.private_key = serialization.load_pem_private_key(
            raw_private_key_bytes,
            password=None,  # Assuming keys are not password protected
            backend=default_backend()
        )

        raw_public_key_bytes = self._load_key(public_key_path, "public")
        self.public_key = serialization.load_pem_public_key(
            raw_public_key_bytes,
            backend=default_backend()
        )

        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.bcrypt_rounds = settings.bcrypt_rounds
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        self.refresh_token_expire_days = settings.refresh_token_expire_days

    def _load_key(self, path: str, key_type: str) -> bytes:
        """
        Read a PEM file from the given path.
        Raises an exception if the file is missing or invalid.
        """
        try:
            with open(path, "rb") as f:  # Read in binary mode
                key_content = f.read().strip()

            # Validate the key format
            if key_type == "private" and b"PRIVATE KEY" not in key_content:  # Check for bytes
                raise ValueError(f"Invalid private key format in {path}. Expected PRIVATE KEY")
            elif key_type == "public" and b"PUBLIC KEY" not in key_content:  # Check for bytes
                raise ValueError(f"Invalid public key format in {path}. Expected PUBLIC KEY")

            logger.info(f"Successfully loaded {key_type} key from: {path}")
            return key_content

        except FileNotFoundError:
            logger.error(f"JWT {key_type} key file not found: {path}")
            logger.error("Please ensure the key files exist in the certs directory")
            raise FileNotFoundError(f"Required JWT {key_type} key file not found: {path}")
        except PermissionError:
            logger.error(f"Permission denied reading {key_type} key file: {path}")
            raise PermissionError(f"Cannot read JWT {key_type} key file due to permissions: {path}")
        except Exception as e:
            logger.error(f"Error loading {key_type} key from {path}: {e}")
            raise RuntimeError(f"Failed to load JWT {key_type} key from {path}: {e}")

    def generate_salt(self) -> str:
        """
        Generate a random hex salt (16 bytes). Bcrypt manages its own salt, 
        but this can be used elsewhere if needed.
        """
        return secrets.token_hex(16)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a plaintext password against a bcrypt-hashed password.
        """
        return self.pwd_context.verify(plain_password, hashed_password)

    def hash_password(self, password: str) -> str:
        """
        Hash a plaintext password using bcrypt with configured rounds.
        """
        return self.pwd_context.hash(password, rounds=self.bcrypt_rounds)

    def _validate_token_format(self, token: str) -> bool:
        """
        Validate token format and encoding before processing.

        Args:
            token: JWT token to validate

        Returns:
            True if token format is valid, False otherwise
        """
        try:
            # Ensure token is valid UTF-8
            token.encode("utf-8")

            # Check JWT format (3 parts separated by dots)
            token_parts = token.split(".")
            if len(token_parts) != 3:
                logger.error(f"Invalid JWT format: expected 3 parts, got {len(token_parts)}")
                return False

            # Validate base64 encoding of each part
            for i, part in enumerate(token_parts):
                try:
                    padding = 4 - (len(part) % 4)
                    if padding != 4:
                        part += "=" * padding
                    base64.urlsafe_b64decode(part)
                except Exception as e:
                    logger.error(f"Invalid base64 encoding in JWT part {i}: {e}")
                    return False

            return True

        except UnicodeEncodeError as e:
            logger.error(f"Token contains invalid UTF-8 characters: {e}")
            return False
        except Exception as e:
            logger.error(f"Token format validation error: {e}")
            return False

    def _decode_token_header(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Safely decode JWT header for debugging purposes.

        Args:
            token: JWT token

        Returns:
            Decoded header dict or None if failed
        """
        try:
            token_parts = token.split(".")
            if len(token_parts) != 3:
                logger.error(f"Malformed JWT (expected 3 segments): {token}")
                return None

            header_b64 = token_parts[0]
            padding = 4 - (len(header_b64) % 4)
            if padding != 4:
                header_b64 += "=" * padding

            # Use urlsafe decode to correctly handle “-” or “_”
            header_bytes = base64.urlsafe_b64decode(header_b64)
            header_json = json.loads(header_bytes.decode("utf-8", errors="replace"))
            return header_json

        except Exception as e:
            logger.error(f"Could not decode token header: {e}")
            return None

    # ────────────────────────────────────────────────────────────────────────────
    # Create Access Token (aud = settings.API_GATEWAY_AUDIENCE)
    # ────────────────────────────────────────────────────────────────────────────
    def create_access_token(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        expires_in: Optional[timedelta] = None,
        tenant_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
        scopes: Optional[List[str]] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Create a JWT access token with:
         - Standard claims: exp, iat, nbf, iss, aud, jti
         - Custom claims: data fields, tenant_id, roles, scopes, session_id.
        """
        to_encode = data.copy()

        # Ensure user_id is set either from parameter or data
        if user_id:
            to_encode["user_id"] = user_id
        elif "user_id" not in to_encode or not to_encode["user_id"]:
            raise ValueError("user_id must be set in token payload")

        if expires_in:
            expire = datetime.now(timezone.utc) + expires_in
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)

        # Get current time once
        now = datetime.now(timezone.utc)

        # CRITICAL FIX: Convert datetime objects to Unix timestamps (integers)
        to_encode.update(
            {
                "exp": int(expire.timestamp()),  # Convert to int timestamp
                "iat": int(now.timestamp()),     # Convert to int timestamp  
                "nbf": int(now.timestamp()),     # Convert to int timestamp
                "iss": "tradesage-auth-service",
                "aud": settings.API_GATEWAY_AUDIENCE,  # Use API_GATEWAY_AUDIENCE for consistency
                "token_type": "access",
                "ver": "1.0",
                "jti": str(uuid4()),
            }
        )

        if tenant_id:
            to_encode["tenant_id"] = tenant_id
        if roles:
            to_encode["roles"] = roles
        if scopes:
            to_encode["scopes"] = scopes
        if session_id:
            to_encode["session_id"] = session_id

        try:
            logger.debug(f"Creating access token for user_id: {to_encode.get('user_id')}")
            logger.debug(f"Token audience: {settings.API_GATEWAY_AUDIENCE}")
            logger.debug(f"Token expires at: {expire}")
            logger.debug(f"Access token payload for debugging: {to_encode}")

            # Convert the private key to PEM format if it's not already
            if hasattr(self.private_key, 'private_bytes'):
                private_key_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                private_key_str = private_key_pem.decode('utf-8')
                
                # Encode the JWT with the proper key format
                encoded_jwt = jwt.encode(
                    to_encode,
                    private_key_str,
                    algorithm=self.algorithm
                )
            else:
                encoded_jwt = jwt.encode(to_encode, self.private_key, algorithm=self.algorithm)

            # Validate the created token immediately
            if not self._validate_token_format(encoded_jwt):
                raise ValueError("Created token failed format validation")

            logger.debug(f"Access token created successfully (length: {len(encoded_jwt)})")
            logger.debug(f"Token starts with: {encoded_jwt[:20]}...")

            return encoded_jwt
        except JWTError as je:
            logger.error(f"JWT Error creating access token: {je}")
            raise
        except Exception as e:
            logger.error(f"Failed to create access token: {e}", exc_info=True)
            raise

    # ────────────────────────────────────────────────────────────────────────────
    # Create Refresh Token (aud = REFRESH_TOKEN_AUDIENCE)
    # ────────────────────────────────────────────────────────────────────────────
    def create_refresh_token(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
        scopes: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        expires_in: Optional[timedelta] = None,
    ) -> str:
        """
        Create a JWT refresh token with:
         - Longer expiration (days)
         - Standard claims: exp, iat, nbf, iss, aud, jti
         - Custom claims: data fields, tenant_id, roles, scopes, session_id.
        """
        to_encode = data.copy()
        
        # Use provided expires_in or fall back to default refresh token expiration
        if expires_in is not None:
            expire = datetime.now(timezone.utc) + expires_in
        else:
            expire = datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expire_days)

        # Ensure user_id is set either from parameter or data
        if user_id:
            to_encode["user_id"] = user_id
        elif "user_id" not in to_encode or not to_encode["user_id"]:
            raise ValueError("user_id must be set in token payload")

        # Get current time once
        now = datetime.now(timezone.utc)

        # CRITICAL FIX: Convert datetime objects to Unix timestamps (integers)
        to_encode.update(
            {
                "exp": int(expire.timestamp()),  # Convert to int timestamp
                "iat": int(now.timestamp()),     # Convert to int timestamp
                "nbf": int(now.timestamp()),     # Convert to int timestamp
                "iss": "tradesage-auth-service",
                "aud": settings.API_GATEWAY_AUDIENCE,  # Use API_GATEWAY_AUDIENCE for consistency
                "token_type": "refresh",
                "ver": "1.0",
                "jti": str(uuid4()),
            }
        )

        if tenant_id:
            to_encode["tenant_id"] = tenant_id
        if roles:
            to_encode["roles"] = roles
        if scopes:
            to_encode["scopes"] = scopes
        if session_id:
            to_encode["session_id"] = session_id

        try:
            logger.debug(f"Refresh token to_encode payload before signing: {to_encode}")  # Detailed payload logging
            # Convert the private key to PEM format if it's not already
            if hasattr(self.private_key, 'private_bytes'):
                private_key_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                private_key_str = private_key_pem.decode('utf-8')
                
                # Encode the JWT with the proper key format
                encoded_jwt = jwt.encode(
                    to_encode,
                    private_key_str,
                    algorithm=self.algorithm
                )
            else:
                encoded_jwt = jwt.encode(to_encode, self.private_key, algorithm=self.algorithm)

            # Validate the created token immediately
            if not self._validate_token_format(encoded_jwt):
                raise ValueError("Created refresh token failed format validation")

            logger.debug(f"Refresh token created successfully for user_id: {to_encode.get('user_id')}")
            logger.debug(f"Refresh token created successfully (length: {len(encoded_jwt)})")
            return encoded_jwt
        except JWTError as je:
            logger.error(f"JWT Error creating refresh token: {je}")
            raise
        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}", exc_info=True)
            raise

    # ────────────────────────────────────────────────────────────────────────────
    # Token Verification
    # ────────────────────────────────────────────────────────────────────────────
    def decode_token(self, token: str, is_refresh: bool = False) -> Optional[TokenData]:
        """
        Decode a JWT token and return its payload as TokenData.

        Args:
            token: JWT token to decode
            is_refresh: If True, expect refresh token audience

        Returns:
            TokenData if valid, None otherwise
        """
        if not token:
            logger.error("Empty token provided for decoding")
            return None

        # Clean the token – remove Bearer prefix if present
        token = token.replace("Bearer ", "").strip()

        if not self._validate_token_format(token):
            logger.error("Token failed format validation")
            return None

        expected_audience = settings.API_GATEWAY_AUDIENCE  # Use API_GATEWAY_AUDIENCE for consistency
        expected_token_type = "refresh" if is_refresh else "access"

        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                audience=expected_audience,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                },
                issuer="tradesage-auth-service",
            )

            # Manual validation for token_type
            token_type = payload.get('token_type')
            if token_type != expected_token_type:
                logger.error(f"Token type mismatch. Expected '{expected_token_type}', but got '{token_type}'")
                return None

            if not payload.get("user_id"):
                logger.error("Token missing required user_id field")
                return None

            logger.debug(f"Token decoded successfully. User ID: {payload.get('user_id')}")
            return TokenData(**payload)

        except jwt.ExpiredSignatureError:
            # Token has expired, try to decode without verification to get claims for better error logging
            try:
                unverified_payload = jwt.decode(
                    token,
                    self.public_key,
                    algorithms=[self.algorithm],
                    audience=expected_audience,
                    options={
                        "verify_signature": False,
                        "verify_aud": False,
                        "verify_exp": False,
                        "verify_nbf": False,
                        "verify_iat": False,
                        "verify_iss": False,
                    },
                )
                token_type = unverified_payload.get("token_type")
                expired_at = (
                    datetime.fromtimestamp(unverified_payload.get("exp"), tz=timezone.utc)
                    if unverified_payload.get("exp")
                    else None
                )
                logger.warning(
                    f"Token has expired. Type: {token_type}, Expired at: {expired_at}",
                    extra={"token_type": token_type, "expired_at": expired_at},
                )
                raise TokenExpiredError(
                    message="Token has expired",
                    token_type=token_type,
                    expired_at=expired_at,
                )
            except JWTError:
                # If we can't even decode it, raise the basic error
                logger.warning("Token has expired, but claims could not be decoded.")
                raise TokenExpiredError("Token has expired")
        except jwt.JWTClaimsError as e:
            logger.error(f"JWT claims validation error: {e}")
            return None
        except jwt.JWTError as e:
            logger.error(f"JWT decoding error: {type(e).__name__}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during token decoding: {type(e).__name__}: {e}")
            return None

    def extract_token_from_header(self, authorization: str) -> Optional[str]:
        """
        Extract JWT token from Authorization header.

        Args:
            authorization: Authorization header value (e.g., "Bearer <token>")

        Returns:
            Token string if valid format, None otherwise
        """
        if not authorization:
            logger.error("No authorization header provided")
            return None

        # Handle case-insensitive Bearer prefix
        if not authorization.lower().startswith("bearer "):
            logger.error(f"Invalid authorization header format: missing Bearer prefix")
            return None

        token = authorization[7:].strip()  # Remove "Bearer " prefix

        if not token:
            logger.error("Empty token after Bearer prefix")
            return None

        # Basic format validation
        if not self._validate_token_format(token):
            logger.error("Token extracted from header failed format validation")
            return None

        return token

    def verify_token(self, token: str, is_refresh: bool = False) -> Optional[TokenData]:
        """
        Verify a token by decoding it and checking for a valid user_id.

        Args:
            token: JWT token to verify (can include "Bearer " prefix)
            is_refresh: If True, verify as refresh token

        Returns:
            TokenData if valid, None otherwise
        """
        try:
            # Handle both raw tokens and Authorization header format
            if token.lower().startswith("bearer "):
                extracted_token = self.extract_token_from_header(token)
                if not extracted_token:
                    logger.error("Failed to extract token from Authorization header")
                    return None
                token = extracted_token

            # Pre-validation check
            if not self._validate_token_format(token):
                logger.error("Token failed pre-validation check")
                return None

            try:
                token_data = self.decode_token(token, is_refresh=is_refresh)
                if not token_data or not token_data.user_id:
                    logger.error(
                        f"Invalid token data: user_id={token_data.user_id if token_data else 'None'}"
                    )
                    return None
            except TokenExpiredError:
                logger.warning("Token verification failed: token has expired")
                return None

            logger.debug(f"Token verification successful for user_id: {token_data.user_id}")
            return token_data

        except Exception as e:
            logger.error(f"Token verification failed: {type(e).__name__}: {e}")
            return None


# ────────────────────────────────────────────────────────────────────────────────
# Instantiate a single AuthManager for use in your FastAPI app
# ────────────────────────────────────────────────────────────────────────────────
auth_manager = AuthManager(
    private_key_path=settings.jwt_private_key_path,
    public_key_path=settings.jwt_public_key_path,
    algorithm=settings.jwt_algorithm,  # e.g. "ES256"
)


from typing import Optional
from fastapi import APIRouter, Header, HTTPException, status

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/verify-token")
async def verify_token(authorization: Optional[str] = Header(None)):
    """
    Verify that the incoming request has a valid access token in:
        Authorization: Bearer <jwt>
    Returns 200 + {user_id, tenant_id} if OK, otherwise 401.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    # Extract and validate the “Bearer <token>” format
    token = auth_manager.extract_token_from_header(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization format; must be 'Bearer <token>'",
        )

    token_data = auth_manager.verify_token(token, is_refresh=False)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return {
        "user_id": token_data.user_id,
        "tenant_id": token_data.tenant_id,
    }
