import time
import asyncio
from functools import wraps

class CircuitBreaker:
    """A simple asynchronous circuit breaker decorator."""

    def __init__(self, threshold: int = 5, timeout: int = 30):
        self.threshold = threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # States: CLOSED, OPEN, HALF_OPEN

    def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if self.state == "OPEN":
                if self.last_failure_time and (time.time() - self.last_failure_time) > self.timeout:
                    self.state = "HALF_OPEN"
                else:
                    raise Exception("Circuit is open")

            try:
                result = await func(*args, **kwargs)
                self.reset()
                return result
            except Exception as e:
                self.record_failure()
                raise e
        return wrapper

    def record_failure(self):
        """Records a failure and trips the circuit if the threshold is exceeded."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.threshold:
            self.trip()

    def reset(self):
        """Resets the circuit to a closed state."""
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"

    async def call(self, func, *args, **kwargs):
        """
        Execute the provided coroutine within the circuit-breaker context.

        Example
        -------
        >>> result = await self.circuit_breaker.call(some_async_fn, arg1, arg2)
        """
        wrapped = self(func)  # apply circuit-breaker decorator dynamically
        return await wrapped(*args, **kwargs)

    def trip(self):
        print("🚨 Tripping circuit to OPEN.")
        self.state = "OPEN"
        self.success_count = 0
    def record_failure(self):
        self.failure_count += 1        
        self.last_failure_time = time.time()
        if self.failure_count >= self.threshold:
            self.state = "OPEN"
    
    def reset(self):    
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"