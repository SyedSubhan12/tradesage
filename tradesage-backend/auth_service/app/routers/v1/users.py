from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from uuid import UUID as UUIDType, uuid4
import logging  # Add this import

from common.database import db_manager
from common.auth import auth_manager
from common.models import User, Tenant, TenantStatus, UserRole
from common.audit_logger import log_audit_event

from auth_service.app.dependencies import get_current_active_user, get_current_admin_user
from auth_service.app.services.user_service import handle_db_integrity_error

# Import Pydantic models
from auth_service.app.schemas.users import UserRegister, UserResponse

# Initialize logger
logger = logging.getLogger(__name__)  # Add this line

router = APIRouter(prefix="/users", tags=["users"])

@router.post("/register", response_model=UserResponse)
async def register_user(user_data: UserRegister, db: AsyncSession = Depends(db_manager.get_session)):
    """Register a new user with automatic tenant creation"""
    # Optional: Map common role names to valid roles
    role_mapping = {
        "user": UserRole.TRADER,  # Map "user" to "trader"
        "administrator": UserRole.ADMIN,  # Map "administrator" to "admin"
        "view": UserRole.VIEWER,  # Map "view" to "viewer"
        "api": UserRole.API_USER  # Map "api" to "api_user"
    }
    
    # If role is a string and in our mapping, convert it
    if isinstance(user_data.role, str) and user_data.role in role_mapping:
        user_data.role = role_mapping[user_data.role]
    
    try:
        existing_user = await db.execute(
            select(User).where(User.email == user_data.email)
        )
        if existing_user.scalars().first():
            raise HTTPException(status_code=400, detail="Email already registered")

        existing_username = await db.execute(
            select(User).where(User.username == user_data.username)
        )
        if existing_username.scalars().first():
            raise HTTPException(status_code=400, detail="Username already taken")

        new_tenant_id = uuid4()
        new_tenant = Tenant(
            id=new_tenant_id,
            name=f"Tenant for {user_data.username}",
            schema_name=f"tenant_{str(new_tenant_id).replace('-', '_')}",
            status=TenantStatus.ACTIVE
        )
        db.add(new_tenant)
        await db.flush()
        
        user_data.tenant_id = new_tenant_id
        
        try:
            await db_manager.create_tenant_schema(db, str(new_tenant_id))
        except Exception as schema_error:
            logger.error(f"Schema creation failed: {schema_error}")
            await db.rollback()
            raise HTTPException(status_code=500, detail="Failed to create tenant schema")

        hashed_password = auth_manager.hash_password(user_data.password)
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            tenant_id=user_data.tenant_id,
            role=user_data.role,
            is_active=True,
            is_verified=False,
        )
        db.add(new_user)
        
        await db.commit()
        await db.refresh(new_user)
        
        logger.info(f"User {new_user.username} registered successfully with tenant {new_tenant_id}")
        
        await log_audit_event(
            event_type="user_registration",
            user_id=str(new_user.id),
            details={
                "username": new_user.username,
                "email": new_user.email,
                "tenant_id": str(new_user.tenant_id),
                "tenant_status": new_tenant.status.value,
                "role": new_user.role.value
            }
        )
        
        return UserResponse(
            id=str(new_user.id),
            tenant_id=str(new_tenant.id),
            tenant_status=new_tenant.status.value,
            username=new_user.username,
            email=new_user.email,
            first_name=new_user.first_name,
            last_name=new_user.last_name,
            role=new_user.role,
            is_active=new_user.is_active,
            is_verified=new_user.is_verified,
            failed_login_attempts=new_user.failed_login_attempts,
            locked_until=new_user.locked_until,
            created_at=new_user.created_at
        )
        
    except HTTPException:
        raise
    except IntegrityError as ie:
        await handle_db_integrity_error(db, "registration", ie)
    # In the register_user function
    except Exception as e:
        try:
            logger.error(f"Unexpected error during registration: {str(e)}", exc_info=True)
        except NameError:
            print(f"CRITICAL: Logging failed for error during registration: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/me", response_model=UserResponse)
async def get_current_user(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(db_manager.get_session)
):
    """Get current user endpoint"""
    try:
        tenant = await db.get(Tenant, current_user.tenant_id)
        tenant_status = tenant.status.value if tenant else "unknown"

        return UserResponse(
            id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            tenant_status=tenant_status,
            username=current_user.username,
            email=current_user.email,
            first_name=current_user.first_name,
            last_name=current_user.last_name,
            role=current_user.role,
            is_active=current_user.is_active,
            is_verified=current_user.is_verified,
            failed_login_attempts=current_user.failed_login_attempts,
            locked_until=current_user.locked_until,
            created_at=current_user.created_at
        )
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")