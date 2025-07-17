import httpx
from typing import Optional, Dict, Any, List
from uuid import UUID
from common.config import settings
import structlog
import uuid
import asyncio

logger = structlog.get_logger(__name__)

class SessionServiceClient:
    def __init__(self, base_url: str, timeout: float = 10.0, max_retries: int = 3):
        """Create a reusable async HTTP client.

        Args:
            base_url: Fully-qualified base URL of the Session Service.
            timeout: Total timeout in **seconds** for the request (read + connect).
            max_retries: How many attempts to make before surfacing the error.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = httpx.Timeout(timeout)
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        self.max_retries = max_retries

    async def _request_with_retry(self, method: str, url: str, *, correlation_id: Optional[str] = None, **kwargs) -> httpx.Response:
        """Perform an HTTP request with naive exponential back-off retries."""
        correlation_id = correlation_id or str(uuid.uuid4())
        headers = kwargs.pop("headers", {}) or {}
        headers.setdefault("X-Correlation-Id", correlation_id)
        kwargs["headers"] = headers

        backoff = 1.0
        for attempt in range(1, self.max_retries + 1):
            try:
                response = await self.client.request(method, url, **kwargs)
                response.raise_for_status()
                return response
            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.warning(
                    "Attempt %d/%d failed for %s %s – %s",
                    attempt,
                    self.max_retries,
                    method,
                    url,
                    repr(e),
                    correlation_id=correlation_id,
                )
                if attempt == self.max_retries:
                    raise
                await asyncio.sleep(backoff)
                backoff *= 2

    async def create_session(self, user_id: UUID, client_ip: str, user_agent: str, initial_data: Optional[Dict[str, Any]] = None, *, correlation_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            headers = {
                "X-Forwarded-For": client_ip,
                "User-Agent": user_agent or ""
            }
            response = await self._request_with_retry("POST",
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

    async def get_session(self, session_id: UUID, *, correlation_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            response = await self._request_with_retry("GET", f"/api/v1/sessions/{session_id}", correlation_id=correlation_id)
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

    async def update_session(self, session_token: str, data: Dict[str, Any], *, correlation_id: Optional[str] = None) -> bool:
        try:
            response = await self._request_with_retry("PUT",
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

    async def terminate_session(self, session_id: UUID, *, correlation_id: Optional[str] = None) -> bool:
        try:
            response = await self._request_with_retry("DELETE", f"/api/v1/sessions/{session_id}", correlation_id=correlation_id)
            response.raise_for_status()
            logger.info(f"Successfully terminated session {session_id}")
            return response.status_code == 204
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error terminating session {session_id}: {e.response.status_code}, {e.response.text}", exc_info=True)
        except httpx.RequestError as e:
            logger.error(f"Request error terminating session {session_id}: {e}", exc_info=True)
        return False

    async def get_user_sessions(self, user_id: UUID, *, correlation_id: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        try:
            response = await self._request_with_retry("GET", f"/api/v1/sessions/user/{user_id}", correlation_id=correlation_id)
            response.raise_for_status()
            logger.info(f"Successfully retrieved sessions for user {user_id}")
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error getting sessions for user {user_id}: {e.response.status_code}, {e.response.text}", exc_info=True)
        except httpx.RequestError as e:
            logger.error(f"Request error getting sessions for user {user_id}: {e}", exc_info=True)
        return None

session_service_client = SessionServiceClient(base_url=settings.session_service_url)
