import pytest
import asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models import BaseUser
from common.models.user_session import UserSession
from common.database import db_manager
from common.auth import auth_manager

# Use a separate test database
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session", autouse=True)
async def setup_database():
    """Set up the test database and tables before tests run."""
    db_manager.database_url = TEST_DATABASE_URL
    async with db_manager.engine.begin() as conn:
        await conn.run_sync(db_manager.Base.metadata.create_all)
    yield
    async with db_manager.engine.begin() as conn:
        await conn.run_sync(db_manager.Base.metadata.drop_all)

@pytest.fixture(scope="function")
async def db_session() -> AsyncSession:
    """Provide a clean database session for each test function."""
    async with db_manager.get_session() as session:
        yield session

@pytest.fixture(scope="function")
async def test_client() -> AsyncClient:
    """Provide an async test client."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.fixture(scope="function")
async def test_user(db_session: AsyncSession) -> BaseUser:
    """Create a test user in the database."""
    user = BaseUser(
        username="testuser",
        email="test@example.com",
        hashed_password=auth_manager.hash_password("testpassword"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.mark.asyncio
async def test_login_and_get_tokens(test_client: AsyncClient, test_user: BaseUser):
    """Test successful user login and token issuance."""
    response = await test_client.post(
        "/auth/login",
        data={"username": "testuser", "password": "testpassword"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert response.cookies.get("refresh_token") is not None

@pytest.mark.asyncio
async def test_logout(test_client: AsyncClient, test_user: BaseUser, db_session: AsyncSession):
    """Test successful user logout, verifying the session is marked inactive."""
    # 1. Login to get tokens and create a session
    login_response = await test_client.post(
        "/auth/login", data={"username": "testuser", "password": "testpassword"}
    )
    access_token = login_response.json()["access_token"]
    
    # Extract session_id from token to verify it's deactivated
    token_data = auth_manager.decode_token(access_token)
    session_id = token_data.session_id

    # 2. Logout
    headers = {"Authorization": f"Bearer {access_token}"}
    logout_response = await test_client.post("/auth/logout", headers=headers)
    
    assert logout_response.status_code == 200
    assert logout_response.json()["message"] == "Logged out successfully"

    # 3. Verify session is inactive in the database
    session = await db_session.get(UserSession, session_id)
    assert session is not None
    assert not session.is_active

@pytest.mark.asyncio
async def test_successful_token_refresh(test_client: AsyncClient, test_user: BaseUser):
    """Test a single, successful token refresh."""
    # 1. Login to get an initial refresh token
    login_response = await test_client.post(
        "/auth/login", data={"username": "testuser", "password": "testpassword"}
    )
    initial_refresh_token = login_response.cookies.get("refresh_token")
    
    # 2. Use the refresh token to get a new access token
    cookies = {"refresh_token": initial_refresh_token}
    refresh_response = await test_client.post("/auth/refresh", cookies=cookies)
    
    assert refresh_response.status_code == 200
    data = refresh_response.json()
    assert "access_token" in data
    # Check that the refresh token was rotated and a new one was sent
    assert "refresh_token" in data
    assert data["refresh_token"] != initial_refresh_token

@pytest.mark.asyncio
async def test_concurrent_token_refresh_race_condition(test_client: AsyncClient, test_user: BaseUser, db_session: AsyncSession):
    """Simulate a race condition by sending multiple refresh requests concurrently."""
    # 1. Login to get a valid refresh token
    login_response = await test_client.post(
        "/auth/login", data={"username": "testuser", "password": "testpassword"}
    )
    refresh_token = login_response.cookies.get("refresh_token")
    cookies = {"refresh_token": refresh_token}

    # 2. Create multiple concurrent refresh requests
    tasks = [test_client.post("/auth/refresh", cookies=cookies) for _ in range(5)]
    
    # 3. Execute them all at once
    responses = await asyncio.gather(*tasks)
    
    # 4. Analyze the results
    status_codes = [res.status_code for res in responses]
    
    # We expect exactly ONE successful request (200)
    assert status_codes.count(200) == 1, "Only one refresh request should succeed."
    
    # The other requests should fail because the token has been used (401 Unauthorized)
    assert status_codes.count(401) == 4, "Other requests should fail as the token is invalidated."

    # Verify that the original session is now inactive
    token_data = auth_manager.decode_token(login_response.json()["access_token"])
    original_session = await db_session.get(UserSession, token_data.session_id)
    assert not original_session.is_active, "The original session should be marked inactive after rotation."
