"""
Circuit breaker implementation for resilient service calls.
"""
import logging
from typing import Any, Callable, TypeVar, Optional
from functools import wraps
from circuitbreaker import circuit, CircuitBreakerError
import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log
)

logger = logging.getLogger(__name__)
T = TypeVar('T')

class CircuitBreakerConfig:
    """Configuration for circuit breakers."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exceptions: tuple[type[Exception], ...] = (Exception,),
        name: Optional[str] = None
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exceptions = expected_exceptions
        self.name = name or "unnamed_circuit"

def create_circuit_breaker(
    func: Optional[Callable[..., T]] = None,
    config: Optional[CircuitBreakerConfig] = None
) -> Callable[..., T]:
    config = config or CircuitBreakerConfig()
    
    def decorator(f: Callable[..., T]) -> Callable[..., T]:
        @wraps(f)
        @circuit(
            failure_threshold=config.failure_threshold,
            recovery_timeout=config.recovery_timeout,
            name=config.name
        )
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=4, max=10),
            retry=retry_if_exception_type(config.expected_exceptions),
            before_sleep=before_sleep_log(logger, logging.WARNING)
        )
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            return await f(*args, **kwargs)
        
        return wrapper
    
    return decorator(func) if func else decorator


def circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: int = 60,
    expected_exceptions: tuple[type[Exception], ...] = (Exception,),
    name: Optional[str] = None
) -> Callable[..., Callable[..., Any]]:
    """
    Decorator factory for circuit breakers with retry logic.
    
    Args:
        failure_threshold: Number of failures before opening the circuit
        recovery_timeout: Time in seconds to wait before attempting recovery
        expected_exceptions: Exceptions that should trigger the circuit breaker
        name: Name for the circuit (for monitoring)
        
    Returns:
        Decorator function
    """
    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        recovery_timeout=recovery_timeout,
        expected_exceptions=expected_exceptions,
        name=name
    )
    return create_circuit_breaker(config=config)


# Common circuit breakers
class CircuitBreakers:
    """Pre-configured circuit breakers for common use cases."""
    
    @staticmethod
    def oauth_provider() -> Callable[..., Callable[..., Any]]:
        """Circuit breaker for OAuth provider calls."""
        return circuit_breaker(
            failure_threshold=3,
            recovery_timeout=300,  # 5 minutes
            expected_exceptions=(
                httpx.RequestError,
                httpx.HTTPStatusError,
                TimeoutError,
                OSError
            ),
            name="oauth_provider_circuit"
        )
    
    @staticmethod
    def database() -> Callable[..., Callable[..., Any]]:
        """Circuit breaker for database operations."""
        return circuit_breaker(
            failure_threshold=5,
            recovery_timeout=60,  # 1 minute
            expected_exceptions=(
                sqlalchemy.exc.OperationalError,
                sqlalchemy.exc.TimeoutError,
                sqlalchemy.exc.DatabaseError
            ),
            name="database_circuit"
        )
