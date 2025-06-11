from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from uuid import UUID

from common.auth import auth_manager
from common.database import db_manager
from common.models import User
from common.exceptions import AuthenticationError

async def get_current_active_user(
    token: str = Depends(auth_manager.oauth2_scheme),
    db: AsyncSession = Depends(db_manager.get_session),
    token_type: str = "access"
) -> User:  # Change from BaseUser to User
    try:
        token_data = auth_manager.verify_token(token, token_type=token_type)
        if not token_data:
            raise AuthenticationError()

        # Ensure tenant_id is passed as well
        if token_data.tenant_id is None:
            raise AuthenticationError()

        user = await get_user_by_id(db, UUID(token_data.user_id), UUID(token_data.tenant_id))
        if not user or not user.is_active:
            raise AuthenticationError()

        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

async def get_user_by_username_or_email(
    db: AsyncSession,
    username: str,
    tenant_id: Optional[UUID] = None
) -> Optional[User]:
    query = select(User).where(
        (User.username == username) | (User.email == username)
    )
    if tenant_id:
        query = query.where(User.tenant_id == tenant_id)
    result = await db.execute(query)
    return result.scalar_one_or_none()

async def get_user_by_id(db: AsyncSession, user_id: UUID, tenant_id: Optional[UUID] = None) -> Optional[User]:
    query = select(User).where(User.id == user_id)
    if tenant_id:
        query = query.where(User.tenant_id == tenant_id)
    result = await db.execute(query)
    return result.scalar_one_or_none()

__all__ = [get_current_active_user, get_user_by_username_or_email, get_user_by_id]