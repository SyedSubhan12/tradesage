# app/routers/v1/schemas.py

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from tenant_service.app.schemas.tenant_schemas import (
    BackupCreate,
    BackupResponse,
    TenantSchemaResponse
)
from tenant_service.app.services.backup_service import TenantBackupService
from tenant_service.app.models.tenant import TenantSchema, TenantBackup
from common.database import db_manager
from common.config import settings
from common.auth import require_admin, get_current_user

logger = structlog.get_logger(__name__)

router = APIRouter()


# Dependency to get database session
async def get_db():
    async with db_manager.get_session() as session:
        yield session


# Dependency to get backup service
def get_backup_service():
    import os
    from tenant_service.app.services.backup_service_ma130 import MA130BackupService
    
    # Use MA130 if enabled, otherwise fall back to S3
    if os.getenv('ENABLE_MA130_BACKUP', 'true').lower() == 'true':
        return MA130BackupService(
            db_config={'dsn': settings.database_url},
            ma130_config={
                'host': os.getenv('MA130_HOST', '192.168.1.100'),
                'port': int(os.getenv('MA130_PORT', '22')),
                'username': os.getenv('MA130_USERNAME', 'tradesage_backup'),
                'key_path': os.getenv('MA130_KEY_PATH', '/app/keys/ma130_rsa'),
                'backup_path': os.getenv('MA130_BACKUP_PATH', '/data/tradesage/backups')
            }
        )
    else:
        return TenantBackupService(
            db_config={'dsn': settings.database_url},
            s3_config={
                'bucket': settings.BACKUP_S3_BUCKET,
                'region_name': settings.AWS_REGION
            }
        )


@router.post("/{tenant_id}/backup", response_model=BackupResponse, status_code=status.HTTP_201_CREATED)
async def create_backup(
    tenant_id: str,
    backup_request: BackupCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    backup_service: TenantBackupService = Depends(get_backup_service),
    current_user = Depends(get_current_user)
):
    """
    Create a backup of tenant schema.
    
    Creates an encrypted backup stored in S3 with retention policy.
    """
    # Verify tenant exists and get schema name
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    tenant_schema = result.scalar_one_or_none()
    
    if not tenant_schema:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    if not tenant_schema.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot backup inactive tenant"
        )
    
    try:
        # Create backup
        backup_result = await backup_service.create_tenant_backup(
            tenant_id,
            tenant_schema.schema_name,
            backup_request.backup_type
        )
        
        # Schedule cleanup of old backups in background
        background_tasks.add_task(backup_service.cleanup_expired_backups)
        
        return BackupResponse(
            id=backup_result["backup_id"],
            tenant_id=backup_result["tenant_id"],
            backup_id=backup_result["backup_id"],
            schema_name=backup_result["schema_name"],
            backup_path=backup_result["backup_path"],
            size_bytes=backup_result["size_bytes"],
            backup_type=backup_result["backup_type"],
            created_at=backup_result["created_at"],
            expires_at=backup_result["expires_at"],
            is_deleted=False
        )
        
    except Exception as e:
        logger.error(
            "Failed to create backup",
            tenant_id=tenant_id,
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create backup: {str(e)}"
        )


@router.get("/{tenant_id}/backups", response_model=List[BackupResponse])
async def list_backups(
    tenant_id: str,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    backup_service: TenantBackupService = Depends(get_backup_service),
    current_user = Depends(get_current_user)
):
    """
    List backups for a tenant.
    
    Returns recent backups sorted by creation date.
    """
    # Verify tenant exists
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    # Get backups
    backups = await backup_service.list_tenant_backups(tenant_id, limit)
    
    return [
        BackupResponse(
            id=b["id"],
            tenant_id=b["tenant_id"],
            backup_id=b["backup_id"],
            schema_name=b["schema_name"],
            backup_path=b["backup_path"],
            size_bytes=b["size_bytes"],
            backup_type=b["backup_type"],
            created_at=b["created_at"],
            expires_at=b["expires_at"],
            is_deleted=b["is_deleted"]
        )
        for b in backups
    ]


@router.post("/{tenant_id}/restore/{backup_id}", status_code=status.HTTP_202_ACCEPTED)
async def restore_backup(
    tenant_id: str,
    backup_id: str,
    target_schema: str = None,
    db: AsyncSession = Depends(get_db),
    backup_service: TenantBackupService = Depends(get_backup_service),
    current_user = Depends(require_admin)
):
    """
    Restore a tenant backup.
    
    Restores backup to a new schema or overwrites existing (if specified).
    This is an admin-only operation.
    """
    # Verify tenant exists
    result = await db.execute(
        select(TenantSchema).where(TenantSchema.tenant_id == tenant_id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {tenant_id} not found"
        )
    
    try:
        # Restore backup
        restore_result = await backup_service.restore_tenant_backup(
            tenant_id,
            backup_id,
            target_schema
        )
        
        logger.info(
            "Backup restore initiated",
            tenant_id=tenant_id,
            backup_id=backup_id,
            target_schema=restore_result["target_schema"]
        )
        
        return {
            "message": "Restore operation completed",
            "backup_id": backup_id,
            "target_schema": restore_result["target_schema"],
            "restored_at": restore_result["restored_at"]
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(
            "Failed to restore backup",
            tenant_id=tenant_id,
            backup_id=backup_id,
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to restore backup: {str(e)}"
        )


@router.delete("/{tenant_id}/backups/{backup_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_backup(
    tenant_id: str,
    backup_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """
    Delete a specific backup.
    
    Marks backup as deleted and removes from S3. Admin only.
    """
    # Get backup
    result = await db.execute(
        select(TenantBackup).where(
            TenantBackup.tenant_id == tenant_id,
            TenantBackup.backup_id == backup_id,
            TenantBackup.is_deleted == False
        )
    )
    backup = result.scalar_one_or_none()
    
    if not backup:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Backup {backup_id} not found"
        )
    
    # Mark as deleted
    backup.is_deleted = True
    await db.commit()
    
    logger.info(
        "Backup marked for deletion",
        tenant_id=tenant_id,
        backup_id=backup_id
    ) 