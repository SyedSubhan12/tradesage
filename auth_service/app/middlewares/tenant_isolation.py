# tenant_isolation.py - Tenant isolation middleware
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from typing import Callable
import logging

from common.auth import auth_manager

logger = logging.getLogger("tradesage.auth")

class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """Enhanced middleware to ensure tenant isolation in shared schema"""
    
    TENANT_REQUIRED_PATHS = [
        "/token", "/logout", "/password/change", "/password/reset-request", "/password/reset-confirm", "/me", "/refresh"
    ]
    
    PUBLIC_PATHS = [
        "/health", "/docs", "/redoc", "/openapi.json", "/register"
    ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        
        # Skip middleware for public endpoints
        if path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Add tenant context to request state
        request.state.tenant_validation_required = True
        
        # For tenant-required paths, validate tenant_id in request
        if path in self.TENANT_REQUIRED_PATHS:
            tenant_id = None
            
            # Extract tenant_id from request body if POST
            if request.method == "POST":
                try:
                    body = await request.body()
                    if body:
                        import json
                        data = json.loads(body.decode())
                        tenant_id = data.get("tenant_id")
                except:
                    pass
            
            # Extract from Authorization header if available
            if not tenant_id:
                try:
                    auth_header = request.headers.get("Authorization")
                    if auth_header and auth_header.startswith("Bearer "):
                        token = auth_header.split(" ")[1]
                        token_data = auth_manager.verify_token(token)
                        if token_data:
                            tenant_id = token_data.tenant_id
                except:
                    pass
            
            # Store tenant_id in request state for downstream use
            if tenant_id:
                request.state.tenant_id = tenant_id
        
        return await call_next(request)