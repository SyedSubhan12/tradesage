import os
from pydantic_settings import BaseSettings
from typing import Optional, List

class Settings(BaseSettings):
    # Database
    database_url: Optional[str] = os.environ.get("DATABASE_URL")

    # Security
    jwt_secret_key: str = "super-secret"
    jwt_algorithm: str = "ES256"

    # In your settings/config file
    jwt_private_key_path: str = "certs/jwt_private_key.pem"
    jwt_public_key_path: str = "certs/jwt_public_key.pem"
    # (Remove the duplicate “jwt_algorithm” here—keep only the one with annotation above)

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    access_token_audience: str = "trade-sage-access-token"
    refresh_token_audience: str = "trade-sage-refresh-token"
    bcrypt_rounds: int = 12

    # Redis
    redis_url: Optional[str] = os.environ.get("REDIS_URL")

    # Kafka
    kafka_bootstrap_servers: Optional[str] = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")

    # Service URLs
    auth_service_url: Optional[str] = os.environ.get("AUTH_SERVICE_URL")
    user_service_url: Optional[str] = os.environ.get("USER_SERVICE_URL")
    tenant_service_url: Optional[str] = os.environ.get("TENANT_SERVICE_URL")

    # CORS settings
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]

    # Environment
    environment: str = "development"
    debug: bool = True

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
