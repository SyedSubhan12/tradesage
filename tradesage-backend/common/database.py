from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
import logging
import sqlalchemy.exc
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from common.config import settings
from typing import AsyncGenerator

logger = logging.getLogger(__name__)

Base = declarative_base()

class DatabaseManager:
    def __init__(self, database_url: str):
        self.database_url = database_url
        self._engine = None
        self._async_session = None

    @property
    def engine(self):
        if self._engine is None:
            # Convert Pydantic URL to string if needed
            db_url = str(self.database_url)
            self._engine = create_async_engine(
                db_url,
                echo=False,  # Disable in production
                pool_pre_ping=True,
                pool_recycle=3600,
                pool_size=20,
                max_overflow=30,
                pool_timeout=30
            )
            self.session_factory = async_sessionmaker(
                bind=self._engine, expire_on_commit=False, class_=AsyncSession
            )   
        return self._engine

    @property
    def async_session(self):
        if self._async_session is None:
            # Using async_sessionmaker for creating AsyncSession
            self._async_session = async_sessionmaker(
                self.engine, class_=AsyncSession, expire_on_commit=False
            )
        return self._async_session

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        logger.info("Getting database session")
        async with self.async_session() as session:
            try:
                yield session

                @retry(
                    stop=stop_after_attempt(3),
                    wait=wait_exponential(multiplier=1, min=4, max=10),
                    retry=retry_if_exception_type((sqlalchemy.exc.OperationalError,)),
                    reraise=True
                )
                async def do_commit():
                    await session.commit()

                await do_commit()

            except Exception as e:
                logger.error(f"Failed to commit transaction: {e}")
                await session.rollback()
                raise

    async def set_tenant_schema(self, session: AsyncSession, tenant_id: str):
        schema_name = f"tenant_{tenant_id.replace('-', '_')}"
        try:
            await session.execute(text(f"SET search_path TO {schema_name}"))
            logger.info(f"Set tenant schema to {schema_name}")
        except Exception as e:
            logger.error(f"Failed to set tenant schema: {e}")
            raise

    async def create_tenant_schema(self, session: AsyncSession, tenant_id: str):
        schema_name = f"tenant_{tenant_id.replace('-', '_')}"
        try:
            await session.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}"))
            logger.info(f"Created tenant schema: {schema_name}")
        except Exception as e:
            logger.error(f"Failed to create tenant schema: {e}")
            raise

    async def drop_tenant_schema(self, session: AsyncSession, tenant_id: str):
        schema_name = f"tenant_{tenant_id.replace('-', '_')}"
        try:
            await session.execute(text(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE"))
            await session.commit()
            logger.info(f"Dropped tenant schema: {schema_name}")
        except Exception as e:
            logger.error(f"Failed to drop tenant schema {schema_name}: {e}")
            raise

    async def close(self):
        if self._engine:
            await self._engine.dispose()
            self._engine = None
        logger.info("Database connection closed")

# Factory function to get DatabaseManager instance

def get_db_manager() -> DatabaseManager:
    return DatabaseManager(settings.database_url)

db_manager = get_db_manager()


def commit_transaction(self):
    try:
        self.db.commit()
    except Exception as e:
        logger.error(f"Transaction rollback: {str(e)}")
        self.db.rollback()
        raise DatabaseError(f"Database transaction failed: {str(e)}")