# rate_limit.py - Rate limiting middleware
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from typing import Callable
import time
import logging

from common.config import settings
from common.redis_client import redis_manager
from common.auth import auth_manager

logger = logging.getLogger("tradesage.auth")

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, rate_limit_per_minute: int = None, rate_limit_window: int = None):
        super().__init__(app)
        self.rate_limit_per_minute = rate_limit_per_minute or getattr(settings, 'RATE_LIMIT_PER_MINUTE', 60)
        self.rate_limit_window = rate_limit_window or getattr(settings, 'RATE_LIMIT_WINDOW', 60)
        self.redis_key_prefix = "rate_limit:"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        
        # Skip rate limiting for health checks and docs
        if path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        now = int(time.time())
        
        # IP-based rate limiting
        ip_key = f"{self.redis_key_prefix}ip:{client_ip}:{path}"
        
        # User-based rate limiting (if authenticated)
        user_key = None
        try:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                token_data = auth_manager.verify_token(token)
                if token_data:
                    user_key = f"{self.redis_key_prefix}user:{token_data.sub}:{path}"
        except:
            pass  # Continue with IP-based limiting only
        
        try:
            redis_client = await redis_manager.get_redis()
            
            # Check both IP and user limits
            for key in [ip_key] + ([user_key] if user_key else []):
                pipe = redis_client.pipeline()
                pipe.zremrangebyscore(key, 0, now - self.rate_limit_window)
                pipe.zcard(key)
                pipe.zadd(key, {str(now): now})
                pipe.expire(key, self.rate_limit_window)
                
                results = await pipe.execute()
                request_count = results[1]
                
                if request_count >= self.rate_limit_per_minute:
                    limit_type = "user" if key == user_key else "IP"
                    logger.warning(f"Rate limit exceeded for {limit_type}: {client_ip}:{path}")
                    return Response(
                        content='{"detail":"Too many requests"}',
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        media_type="application/json"
                    )
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # Continue without rate limiting if Redis is down
        
        return await call_next(request)