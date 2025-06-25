from cryptography.fernet import Fernet

@dataclass
class SessionConfig:
    """Session Presistence Configuration"""
    redis_url: str = "redis://localhost:6379"
    postgres_url: str = "postgresql://localhost:5432/session_service"
    encryption_key: bytes = Fernet.generate_key()

    # performance cache
    cache_ttl: int = 3600 # 1 hour
    auto_save_interval:int = 5 # seconds
    state_compression: bool = True
    max_retries:int = 3
    circuit_breaker_threshold:int = 5

    #security settings
    max_concurrent_sessions:int = 10
    session_timeout:int = 60 * 60 * 24 # 1 day
    token_length: int =32
    
    
    