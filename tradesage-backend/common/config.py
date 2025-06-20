import os
from pydantic_settings import BaseSettings
from typing import Optional, List, Dict, Any

class Settings(BaseSettings):
    # Database
    database_url: Optional[str] = os.environ.get("DATABASE_URL")

    # Security
    jwt_secret_key: str = "super-secret"
    jwt_algorithm: str = "ES256"

    # In your settings/config file
    jwt_private_key_path: str = "certs/ecdsa-private.pem"
    jwt_public_key_path: str = "certs/ecdsa-public.pem"
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
        "http://localhost:8080",
        "http://127.0.0.1:8080"
    ]
    
    # Frontend URL for OAuth redirects
    frontend_url: str = "http://localhost:8080"

    # Environment
    environment: str = "development"
    debug: bool = True
    
    # Google OAuth
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    google_redirect_uri: str = "http://localhost:8080/oauth/google/callback"
    google_auth_uri: str = "https://accounts.google.com/o/oauth2/auth"
    google_token_uri: str = "https://oauth2.googleapis.com/token"
    google_user_info_uri: str = "https://www.googleapis.com/oauth2/v3/userinfo"

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
