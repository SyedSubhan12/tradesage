from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, DisconnectionError, SQLAlchemyError
import logging
import sqlalchemy.exc
import traceback
from uuid import uuid4
from common.audit import AuditLog  # Import AuditLog model
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from common.config import settings
from typing import AsyncGenerator
from contextlib import contextmanager, asynccontextmanager
from fastapi import HTTPException, status
import structlog

logger = logging.getLogger(__name__)
Base = declarative_base()

class DatabaseManager:
    def __init__(self, database_url: str):
        self.database_url = database_url
        self._engine = None
        self._async_session = None
        self.logger = structlog.get_logger("tradesage.database.manager")
        self.session_logger = logger  # Add this line to fix the undefined session_logger
    
    def initialize(self, database_url: str = None, **kwargs):
        """
        Initialize the database engine and session factory.
        
        :param database_url: Optional database URL to override the one in constructor
        :param kwargs: Additional configuration parameters
        """
        # Use provided database_url or fall back to the one in constructor
        db_url = database_url or self.database_url
        
        engine_kwargs = {
            "pool_size": kwargs.get("pool_size", 20),
            "max_overflow": kwargs.get("max_overflow", 30),
            "pool_timeout": kwargs.get("pool_timeout", 30),
            "pool_recycle": kwargs.get("pool_recycle", 3600),
            "pool_pre_ping": True,  # Validates connections before use
            "echo": kwargs.get("echo", False),
        }
        
        # Create the async engine and session factory
        self._engine = create_async_engine(db_url, **engine_kwargs)
        self._async_session = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False
        )
        
        
        self.logger.info(
            "Database initialized",
            pool_size=engine_kwargs["pool_size"],
            max_overflow=engine_kwargs["max_overflow"]
        )
        
        return self

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
                pool_timeout=30,
            )
            # Ensure async session factory is created alongside the engine
            self._async_session = async_sessionmaker(
                bind=self._engine,
                class_=AsyncSession,
                expire_on_commit=False,
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
        if not self._async_session:
            raise ValueError("Async session not initialized. Call initialize() first.")
        
        session_id = str(uuid4())[:8]
        session_logger = self.logger.bind(session_id=session_id)

        async with self.async_session() as session:
            try:
                session_logger.debug(
                    f"Database connection pool usage: {self.engine.sync_engine.pool.size()} connections in use, "
                    f"{self.engine.sync_engine.pool.checkedin()} connections available"
                )
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

            except sqlalchemy.exc.OperationalError as e:
                session_logger.error(f"Database operational error: {e}")
                raise HTTPException(status_code=500, detail="Database connection error")
            except Exception as e:
                session_logger.error(f"Failed to commit transaction: {e}", exc_info=True)
                await session.rollback()
                raise

    async def set_tenant_schema(self, session: AsyncSession, tenant_id: str):
        schema_name = f"tenant_{tenant_id.replace('-', '_')}"
        try:
            await session.execute(text(f"SET search_path TO {schema_name}"))
            self.logger.info(f"Set tenant schema to {schema_name}")
        except Exception as e:
            self.logger.error(f"Failed to set tenant schema: {e}")
            raise

    async def create_tenant_schema(self, session: AsyncSession, tenant_id: str):
        schema_name = f"tenant_{tenant_id.replace('-', '_')}"
        try:
            await session.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}"))
            self.logger.info(f"Created tenant schema: {schema_name}")
        except Exception as e:
            self.logger.error(f"Failed to create tenant schema: {e}")
            raise

    async def drop_tenant_schema(self, session: AsyncSession, tenant_id: str):
        schema_name = f"tenant_{tenant_id.replace('-', '_')}"
        try:
            await session.execute(text(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE"))
            await session.commit()
            self.logger.info(f"Dropped tenant schema: {schema_name}")
        except Exception as e:
            self.logger.error(f"Failed to drop tenant schema {schema_name}: {e}")
            raise

    async def close(self):
        if self._engine:
            await self._engine.dispose()
            self._engine = None
        self.logger.info("Database connection closed")

    @contextmanager
    def transaction(self):
        """Context manager for database transactions with rollback tracking."""
        try:
            yield
            self.session.commit()
            self.logger.debug("Transaction committed successfully")
        except Exception as e:
            self.session.rollback()
            self.logger.error(f"Transaction rolled back: {e}", exc_info=True)
            raise

def get_db_manager() -> DatabaseManager:
    return DatabaseManager(settings.database_url)

db_manager = get_db_manager()

@asynccontextmanager
async def atomic_session_operation(session: AsyncSession):
    """
    Production-grade atomic transaction context manager with comprehensive error handling
    """
    transaction_id = str(uuid4())[:8]
    # Use structlog logger for proper binding
    operation_logger = structlog.get_logger("tradesage.database.atomic_operation").bind(transaction_id=transaction_id)
    
    try:
        operation_logger.debug("Starting atomic transaction")
        
        # Begin transaction if not already in one
        if not session.in_transaction():
            await session.begin()
        
        yield session
        
        # Commit the transaction
        operation_logger.debug("Committing transaction")
        await session.commit()
        operation_logger.info("Transaction committed successfully")
        
    except IntegrityError as e:
        operation_logger.error(
            "Database integrity error - rolling back",
            error=str(e),
            error_type="IntegrityError"
        )
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Data integrity violation"
        ) from e
        
    except DisconnectionError as e:
        operation_logger.error(
            "Database disconnection error - rolling back",
            error=str(e),
            error_type="DisconnectionError"
        )
        await session.rollback()
        
        # Attempt to reconnect
        try:
            await session.connection()
            operation_logger.info("Database reconnection successful")
        except Exception as reconnect_error:
            operation_logger.error(
                "Database reconnection failed",
                error=str(reconnect_error)
            )
        
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection lost. Please try again."
        ) from e
        
    except SQLAlchemyError as e:
        operation_logger.error(
            "SQLAlchemy error - rolling back",
            error=str(e),
            error_type=type(e).__name__,
            traceback=traceback.format_exc()
        )
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed"
        ) from e
        
    except HTTPException:
        operation_logger.warning("HTTP exception during transaction - rolling back")
        await session.rollback()
        raise
        
    except Exception as e:
        operation_logger.error(
            "Unexpected error during transaction - rolling back",
            error=str(e),
            error_type=type(e).__name__,
            traceback=traceback.format_exc()
        )
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from e

def commit_transaction(self):
    try:
        self.db.commit()
    except Exception as e:
        logger.error(f"Transaction rollback: {str(e)}")
        self.db.rollback()
        raise DatabaseError(f"Database transaction failed: {str(e)}")