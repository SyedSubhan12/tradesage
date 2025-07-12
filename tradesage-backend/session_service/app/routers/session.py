from fastapi import APIRouter, Depends, HTTPException, status, Request
from ..services.session_service import SessionService
from ..dependencies import get_session_service
from ..schemas import SessionCreate, SessionUpdate, SessionResponse
from typing import Dict, Any
from dataclasses import asdict

router = APIRouter()

@router.post("/sessions/", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
async def create_session(
    session_in: SessionCreate,
    request: Request,
    service: SessionService = Depends(get_session_service),
):
    """Create a new session."""
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent")
    new_session = await service.create_session(
        user_id=session_in.user_id, 
        session_data=session_in.session_data, 
        client_ip=client_ip, 
        user_agent=user_agent
    )
    return new_session

@router.get("/sessions/{session_token}", response_model=Dict[str, Any])
async def get_session(
    session_token: str,
    service: SessionService = Depends(get_session_service),
):
    """Retrieve a session by token."""
    session_data = await service.get_session_by_token(session_token)
    if session_data is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return asdict(session_data)

@router.put("/sessions/{session_token}", status_code=status.HTTP_204_NO_CONTENT)
async def update_session(
    session_token: str,
    session_in: SessionUpdate,
    service: SessionService = Depends(get_session_service),
):
    """Update session data."""
    success = await service.update_session_by_token(session_token, session_in.session_data)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

@router.delete("/sessions/{session_token}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(
    session_token: str,
    service: SessionService = Depends(get_session_service),
):
    """Delete a session."""
    success = await service.delete_session(session_token)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return []