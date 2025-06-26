import httpx
from typing import Optional, Dict, Any, List
from uuid import UUID
from common.config import settings
import structlog

logger = structlog.get_logger(__name__)

class SessionServiceClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=5.0)

    async def create_session(self, user_id: UUID, client_ip: str, user_agent: str, initial_data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        try:
            headers = {
                "X-Forwarded-For": client_ip,
                "User-Agent": user_agent or ""
            }
            response = await self.client.post(
                "/api/v1/sessions/",
                json={
                    "user_id": str(user_id),
                    "session_data": initial_data or {},
                },
                headers=headers
            )
            response.raise_for_status()
            logger.info(f"Successfully created session for user {user_id}")
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error creating session for user {user_id}: {e.response.status_code}, {e.response.text}", exc_info=True)
        except httpx.RequestError as e:
            logger.error(f"Request error creating session for user {user_id}: {e}", exc_info=True)
        return None

    async def get_session(self, session_id: UUID) -> Optional[Dict[str, Any]]:
        try:
            response = await self.client.get(f"/api/v1/sessions/{session_id}")
            response.raise_for_status()
            logger.info(f"Successfully retrieved session {session_id} from session service")
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"Session {session_id} not found in session service, status code: {e.response.status_code}")
            else:
                logger.error(f"HTTP error getting session {session_id}: {e.response.status_code}, {e.response.text}", exc_info=True)
        except httpx.RequestError as e:
            logger.error(f"Request error getting session {session_id}: {e}", exc_info=True)
        return None

    async def update_session(self, session_token: str, data: Dict[str, Any]) -> bool:
        try:
            response = await self.client.put(
                f"/api/v1/sessions/{session_token}",
                json={"session_data": data}
            )
            response.raise_for_status()
            logger.info(f"Successfully updated session {session_token}")
            return response.status_code == 204
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error updating session {session_token}: {e.response.status_code}, {e.response.text}", exc_info=True)
        except httpx.RequestError as e:
            logger.error(f"Request error updating session {session_token}: {e}", exc_info=True)
        return False

    async def terminate_session(self, session_id: UUID) -> bool:
        try:
            response = await self.client.delete(f"/api/v1/sessions/{session_id}")
            response.raise_for_status()
            logger.info(f"Successfully terminated session {session_id}")
            return response.status_code == 204
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error terminating session {session_id}: {e.response.status_code}, {e.response.text}", exc_info=True)
        except httpx.RequestError as e:
            logger.error(f"Request error terminating session {session_id}: {e}", exc_info=True)
        return False

    async def get_user_sessions(self, user_id: UUID) -> Optional[List[Dict[str, Any]]]:
        try:
            response = await self.client.get(f"/api/v1/sessions/user/{user_id}")
            response.raise_for_status()
            logger.info(f"Successfully retrieved sessions for user {user_id}")
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error getting sessions for user {user_id}: {e.response.status_code}, {e.response.text}", exc_info=True)
        except httpx.RequestError as e:
            logger.error(f"Request error getting sessions for user {user_id}: {e}", exc_info=True)
        return None

session_service_client = SessionServiceClient(base_url=settings.session_service_url)
