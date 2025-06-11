import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from common.database import Base, async_session

# Replace this URL with your actual test database URL
DATABASE_URL = "postgresql+asyncpg://zsgres:Zunairasubhna@localhost:5432/test_db"

@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """Create a single async engine for the entire test session."""
    engine = create_async_engine(DATABASE_URL, future=True, echo=False)
    # Create all tables once at the start of testing
    async with engine.connect() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    # Drop all tables after the test session is complete
    async with engine.connect() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture(scope="function", autouse=True)
async def reset_database(test_engine):
    """Reset (drop + create) the database schema before each test."""
    # Drop and re-create tables in a fresh connection
    async with test_engine.connect() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Optionally, drop tables after each test
    async with test_engine.connect() as conn:
        await conn.run_sync(Base.metadata.drop_all)
