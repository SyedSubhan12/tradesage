from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID as UUIDType

from common.database import db_manager
from common.models import Tenant

router = APIRouter(prefix="/tenant", tags=["tenant"])

@router.get("/status/{tenant_id}")
async def get_tenant_status(
    tenant_id: UUIDType,
    db: AsyncSession = Depends(db_manager.get_session)
):
    """Retrieve the current status of a tenant."""
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"status": tenant.status.value}