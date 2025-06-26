from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError
import sys
import os
import time
import jwt
import logging

# Add root directory to path for common module imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from common.database import db_manager
from common.auth import auth_manager, TokenExpiredError
from common.models import BaseUser
from common.utils import get_user_by_id

# Define the OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def debug_token_validation(token: str):
    try:
        # Decode without verification first to see payload
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        logging.debug(f"Token payload: {unverified_payload}")
        
        # Check expiration
        import time
        current_time = time.time()
        exp_time = unverified_payload.get('exp', 0)
        logging.debug(f"Token exp: {exp_time}, Current time: {current_time}")
        
        return unverified_payload
    except Exception as e:
        logging.error(f"Token decode error: {e}")
        return None

async def get_current_user_from_access_token(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(db_manager.get_session)
) -> BaseUser:
    """Dependency to get the current authenticated user from an ACCESS token."""
    debug_token_validation(token)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Expect an access token
        token_data = auth_manager.decode_token(token, is_refresh=False)
        if not token_data or not token_data.user_id:
            logging.error("Token validation failed: No token data or user_id")
            raise credentials_exception

        # Check for impending expiration
        exp_time = token_data.exp
        if exp_time and (exp_time - time.time()) < 300:  # 5 minutes in seconds
            logging.warning("Access token is about to expire.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access token is about to expire. Please refresh your token.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        user = await get_user_by_id(db, token_data.user_id)
        if not user:
            logging.error(f"User not found for user_id: {token_data.user_id}")
            raise credentials_exception

        return user

    except TokenExpiredError as e:
        logging.warning(f"Token expired: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        logging.error(f"JWTError during token validation: {e}")
        raise credentials_exception
    except Exception as e:
        logging.error(f"An unexpected error occurred during token validation: {e}", exc_info=True)
        raise credentials_exception

async def get_current_user_from_refresh_token(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(db_manager.get_session)
) -> BaseUser:
    """Dependency to get the current authenticated user from a REFRESH token."""
    debug_token_validation(token)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials using refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Expect a refresh token
        token_data = auth_manager.decode_token(token, is_refresh=True)
        if not token_data or not token_data.user_id:
            logging.error("Refresh token validation failed: No token data or user_id")
            raise credentials_exception

        user = await get_user_by_id(db, token_data.user_id)
        if not user:
            logging.error(f"User not found for user_id from refresh token: {token_data.user_id}")
            raise credentials_exception

        return user

    except TokenExpiredError as e:
        logging.warning(f"Refresh token expired: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        logging.error(f"JWTError during refresh token validation: {e}")
        raise credentials_exception
    except Exception as e:
        logging.error(f"An unexpected error occurred during refresh token validation: {e}", exc_info=True)
        raise credentials_exception


async def get_current_active_user(
    current_user: BaseUser = Depends(get_current_user_from_access_token)
) -> BaseUser:
    """Dependency to get the current active user, raising an error if inactive."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Inactive user"
        )
    return current_user

async def get_current_admin_user(
    current_user: BaseUser = Depends(get_current_active_user)
) -> BaseUser:
    """Dependency to get the current admin user, checking for the 'admin' role."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have enough privileges"
        )
    return current_user