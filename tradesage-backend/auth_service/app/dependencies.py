from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError
import sys
import os

# Add root directory to path for common module imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from common.database import db_manager
from common.auth import auth_manager, TokenExpiredError, TokenExpiredError
from common.models import BaseUser
from common.utils import get_user_by_id

# Define the OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user_from_access_token(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(db_manager.get_session)
) -> BaseUser:
    """Dependency to get the current authenticated user from an ACCESS token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Expect an access token
        token_data = auth_manager.decode_token(token, is_refresh=False)
        if not token_data or not token_data.user_id:
            raise credentials_exception

        user = await get_user_by_id(db, token_data.user_id)
        if not user:
            raise credentials_exception

        return user

    except (JWTError, TokenExpiredError):
        raise credentials_exception
    except Exception:
        raise credentials_exception

async def get_current_user_from_refresh_token(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(db_manager.get_session)
) -> BaseUser:
    """Dependency to get the current authenticated user from a REFRESH token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials using refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Expect a refresh token
        token_data = auth_manager.decode_token(token, is_refresh=True)
        if not token_data or not token_data.user_id:
            raise credentials_exception

        user = await get_user_by_id(db, token_data.user_id)
        if not user:
            raise credentials_exception

        return user

    except (JWTError, TokenExpiredError):
        raise credentials_exception
    except Exception:
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