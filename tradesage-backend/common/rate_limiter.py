"""
Rate limiting utilities using SlowAPI.
"""
from typing import List, Union
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging

logger = logging.getLogger(__name__)

# Global limiter instance with default rate limits
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# Alias for backward compatibility
rate_limiter = limiter

def get_rate_limiter() -> Limiter:
    """Get the global rate limiter instance.
    
    Returns:
        Limiter: The global rate limiter instance
    """
    return limiter

# Predefined rate limits for common endpoints (requests per minute)
RATE_LIMITS = {
    "auth": {
        "login": "10/minute",
        "register": "5/minute",
        "verify_email": "5/minute",
        "password_reset": "5/hour",
    },
    "oauth": {
        "authorize": "30/minute",
        "token": "30/minute",
        "google_callback": "30/minute",
    },
    "api": {
        "default": "100/minute",
        "high_volume": "1000/minute",
    },
}

def get_rate_limit(scope: str, endpoint: str) -> Union[str, List[str]]:
    """Get rate limit for a specific scope and endpoint.
    
    Returns:
        Union[str, List[str]]: Rate limit string or list of rate limit strings
    """
    limit = RATE_LIMITS.get(scope, {}).get(endpoint, RATE_LIMITS["api"]["default"])
    return limit
