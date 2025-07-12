from pydantic import BaseModel
import uuid
from typing import Dict, Any, Optional
from datetime import datetime

class SessionCreate(BaseModel):
    user_id: uuid.UUID
    session_data: Dict[str, Any]
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None

class SessionUpdate(BaseModel):
    session_data: Dict[str, Any]

class SessionResponse(BaseModel):
    session_token: str
    user_id: uuid.UUID
    created_at: datetime
    expires_at: datetime

    class Config:
        orm_mode = True
