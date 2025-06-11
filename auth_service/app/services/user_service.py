from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
import logging

from fastapi import HTTPException

logger = logging.getLogger("tradesage.auth")

async def handle_db_integrity_error(db: AsyncSession, operation: str, error: IntegrityError):
    """Centralized database integrity error handler"""
    await db.rollback()
    logger.error(f"Database integrity error during {operation}: {str(error)}")
    raise HTTPException(status_code=400, detail=f"Database conflict during {operation}")