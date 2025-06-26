from cryptography.fernet import Fernet

@dataclass
class SessionConfig:
    """Session Presistence Configuration"""
    redis_url: str = "redis://localhost:6379"
    postgres_url: str = "postgresql+asyncpg://zs:Zunairasubhan@localhost:5432/tradesage"
    encryption_key: bytes = Fernet.generate_key()

    # performance cache
    cache_ttl: int = 60 * 60 * 24 * 30  # 30 days to match session timeout
    auto_save_interval:int = 5 # seconds
    state_compression: bool = True
    max_retries:int = 3
    circuit_breaker_threshold:int = 5

    #security settings
    max_concurrent_sessions:int = 10
    session_timeout:int = 60 * 60 * 24 * 30 # 30 days to match refresh token expiration
    token_length: int =32

    # Added missing attributes to fix error
    session_token_expire_minutes: int = 60 * 24 * 30  # 30 days in minutes
    redis_session_ttl_seconds: int = 60 * 60 * 24 * 30  # 30 days in seconds
