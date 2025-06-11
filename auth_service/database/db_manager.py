from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
import os
# Use common Base class instead of local declarative_base
from common.database import Base
from common.database import DatabaseManager

# Use environment variable or default to PostgreSQL connection
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://zs:Zunairasubhan@localhost/tradesage")

# Create async engine
engine = create_async_engine(DATABASE_URL)

# Create async session factory
SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

class AuthDBManager(DatabaseManager):
    def __init__(self, database_url: str = None):
        super().__init__("AUTH_DB_URL", database_url=database_url)

async def get_session():
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# For backward compatibility
db_manager = type('', (), {'get_session': get_session})()