# =============================================================================
# PRODUCTION MONITORING, ALERTING & CONFIGURATION
# =============================================================================

import os
from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import structlog
from prometheus_client import CollectorRegistry, generate_latest
import asyncio
from datetime import datetime, timezone, timedelta

# =============================================================================
# ENHANCED SETTINGS FOR PRODUCTION - UPDATE YOUR CONFIG.PY
# =============================================================================

import os
from pydantic_settings import BaseSettings
from typing import Optional, List, Dict, Any

class Settings(BaseSettings):
    # Database
    database_url: Optional[str] = os.environ.get("DATABASE_URL")
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_POOL_RECYCLE: int = 3600

    # API Gateway
    AUTH_SERVICE_URL: str = "http://127.0.0.1:8000"
    CORS_ALLOWED_ORIGINS: str = "*"
    API_GATEWAY_PUBLIC_PATHS: str = "/api/auth/*,/api/users/register,/api/tenant/status,/docs,/openapi.json"

    # Security
    jwt_secret_key: str = "super-secret"
    jwt_algorithm: str = "ES256"
    API_GATEWAY_AUDIENCE: str = "tradesage-api-gateway"

    # JWT Keys
    jwt_private_key_path: str = "certs/ecdsa-private.pem"
    jwt_public_key_path: str = "certs/ecdsa-public.pem"

    # Token Settings
    access_token_expire_minutes: int = 15
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # For compatibility
    refresh_token_expire_days: int = 30
    refresh_token_expire_minutes: Optional[int] = None
    refresh_token_grace_period_seconds: int = 60
    jwt_issuer: str = "tradesage-auth-service"
    bcrypt_rounds: int = 12

    # Session Service
    session_encryption_key: str
    session_token_expire_minutes: int = 60 * 24 * 30
    redis_session_ttl_seconds: int = 60 * 60 * 24 * 30
    session_cache_prefix: str = "session:"
    auto_save_interval: int = 5

    # Redis
    redis_url: Optional[str] = os.environ.get("REDIS_URL")
    REDIS_POOL_SIZE: int = 50
    REDIS_RETRY_ON_TIMEOUT: bool = True
    REDIS_SOCKET_KEEPALIVE: bool = True

    # Kafka
    kafka_bootstrap_servers: Optional[str] = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")

    # Service URLs
    auth_service_url: Optional[str] = os.environ.get("AUTH_SERVICE_URL")
    user_service_url: Optional[str] = os.environ.get("USER_SERVICE_URL")
    tenant_service_url: Optional[str] = os.environ.get("TENANT_SERVICE_URL")
    session_service_url: str = os.environ.get("SESSION_SERVICE_URL", "http://127.0.0.1:8082")

    # CORS settings
    cors_origins: List[str] = [
        "http://localhost:8080",
        "http://127.0.0.1:8080"
    ]
    
    # Frontend URL for OAuth redirects
    frontend_url: str = "http://localhost:8080"
    
    # Google OAuth Settings
    GOOGLE_OAUTH_CLIENT_ID: str = ""
    GOOGLE_OAUTH_CLIENT_SECRET: str = ""
    GOOGLE_OAUTH_REDIRECT_URI: str = ""
    
    # Token validation settings
    TOKEN_VALIDATION_LEEWAY: int = 30

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

    # =============================================================================
    # PRODUCTION MONITORING & LOGGING SETTINGS
    # =============================================================================
    
    # Logging Configuration
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.environ.get("LOG_FORMAT", "json")  # json, text
    LOG_TO_FILE: bool = os.environ.get("LOG_TO_FILE", "false").lower() == "true"
    LOG_FILE_PATH: str = os.environ.get("LOG_FILE_PATH", "/var/log/tradesage/auth.log")
    LOG_ROTATION_SIZE: str = os.environ.get("LOG_ROTATION_SIZE", "100MB")
    LOG_RETENTION_DAYS: int = int(os.environ.get("LOG_RETENTION_DAYS", "30"))
    
    # Structured Logging
    ENABLE_STRUCTURED_LOGGING: bool = os.environ.get("ENABLE_STRUCTURED_LOGGING", "true").lower() == "true"
    LOG_CORRELATION_ID_HEADER: str = "X-Correlation-ID"
    LOG_REQUEST_ID_HEADER: str = "X-Request-ID"
    
    # Monitoring & Metrics
    ENABLE_METRICS: bool = os.environ.get("ENABLE_METRICS", "true").lower() == "true"
    METRICS_PORT: int = int(os.environ.get("METRICS_PORT", "9090"))
    METRICS_PATH: str = os.environ.get("METRICS_PATH", "/metrics")
    PROMETHEUS_REGISTRY: str = "default"
    
    # Health Checks
    HEALTH_CHECK_TIMEOUT: int = int(os.environ.get("HEALTH_CHECK_TIMEOUT", "30"))
    HEALTH_CHECK_INTERVAL: int = int(os.environ.get("HEALTH_CHECK_INTERVAL", "60"))
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
    RATE_LIMIT_LOGIN_ATTEMPTS: str = os.environ.get("RATE_LIMIT_LOGIN_ATTEMPTS", "5/minute")
    RATE_LIMIT_PASSWORD_RESET: str = os.environ.get("RATE_LIMIT_PASSWORD_RESET", "3/minute")
    RATE_LIMIT_TOKEN_REFRESH: str = os.environ.get("RATE_LIMIT_TOKEN_REFRESH", "20/minute")
    
    # Security Headers
    SECURITY_HEADERS_ENABLED: bool = os.environ.get("SECURITY_HEADERS_ENABLED", "true").lower() == "true"
    HSTS_MAX_AGE: int = int(os.environ.get("HSTS_MAX_AGE", "31536000"))  # 1 year
    CSP_POLICY: str = os.environ.get("CSP_POLICY", "default-src 'self'")
    
    # Cookie Settings
    COOKIE_SECURE: bool = True 
    #os.environ.get("COOKIE_SECURE", "true").lower() == "true"
    COOKIE_SAMESITE: str = os.environ.get("COOKIE_SAMESITE", "lax")
    COOKIE_PATH: str = os.environ.get("COOKIE_PATH", "/auth")
    COOKIE_DOMAIN: Optional[str] = os.environ.get("COOKIE_DOMAIN")
    
    # Email Configuration (for production)
    MAIL_USERNAME: str = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = os.environ.get("MAIL_PASSWORD", "")
    MAIL_FROM: str = os.environ.get("MAIL_FROM", "noreply@tradesage.com")
    MAIL_PORT: int = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_SERVER: str = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_STARTTLS: bool = os.environ.get("MAIL_STARTTLS", "true").lower() == "true"
    MAIL_SSL_TLS: bool = os.environ.get("MAIL_SSL_TLS", "false").lower() == "true"
    MAIL_USE_CREDENTIALS: bool = os.environ.get("MAIL_USE_CREDENTIALS", "true").lower() == "true"
    MAIL_VALIDATE_CERTS: bool = os.environ.get("MAIL_VALIDATE_CERTS", "true").lower() == "true"
    MAIL_DEBUG: int = int(os.environ.get("MAIL_DEBUG", "0"))
    MAIL_SUPPRESS_SEND: int = int(os.environ.get("MAIL_SUPPRESS_SEND", "0"))
    
    # Alerting Configuration
    ALERTING_ENABLED: bool = os.environ.get("ALERTING_ENABLED", "false").lower() == "true"
    SLACK_WEBHOOK_URL: Optional[str] = os.environ.get("SLACK_WEBHOOK_URL")
    ALERT_EMAIL_RECIPIENTS: str = os.environ.get("ALERT_EMAIL_RECIPIENTS", "")
    ALERT_THRESHOLD_ERROR_RATE: float = float(os.environ.get("ALERT_THRESHOLD_ERROR_RATE", "0.05"))  # 5%
    ALERT_THRESHOLD_RESPONSE_TIME: float = float(os.environ.get("ALERT_THRESHOLD_RESPONSE_TIME", "2.0"))  # 2 seconds
    
    # Circuit Breaker Settings
    CIRCUIT_BREAKER_ENABLED: bool = os.environ.get("CIRCUIT_BREAKER_ENABLED", "true").lower() == "true"
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = int(os.environ.get("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5"))
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = int(os.environ.get("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "60"))
    CIRCUIT_BREAKER_EXPECTED_EXCEPTION: str = os.environ.get("CIRCUIT_BREAKER_EXPECTED_EXCEPTION", "aiohttp.ClientError")
    
    # Retry Configuration
    RETRY_ENABLED: bool = os.environ.get("RETRY_ENABLED", "true").lower() == "true"
    RETRY_MAX_ATTEMPTS: int = int(os.environ.get("RETRY_MAX_ATTEMPTS", "3"))
    RETRY_BASE_DELAY: float = float(os.environ.get("RETRY_BASE_DELAY", "1.0"))
    RETRY_MAX_DELAY: float = float(os.environ.get("RETRY_MAX_DELAY", "60.0"))
    RETRY_EXPONENTIAL_BASE: float = float(os.environ.get("RETRY_EXPONENTIAL_BASE", "2.0"))
    
    # Caching Configuration
    CACHE_ENABLED: bool = os.environ.get("CACHE_ENABLED", "true").lower() == "true"
    CACHE_TTL_SECONDS: int = int(os.environ.get("CACHE_TTL_SECONDS", "300"))  # 5 minutes
    CACHE_MAX_SIZE: int = int(os.environ.get("CACHE_MAX_SIZE", "1000"))
    
    # Background Tasks
    BACKGROUND_TASK_ENABLED: bool = os.environ.get("BACKGROUND_TASK_ENABLED", "true").lower() == "true"
    BACKGROUND_TASK_INTERVAL: int = int(os.environ.get("BACKGROUND_TASK_INTERVAL", "300"))  # 5 minutes
    
    # Audit Logging
    AUDIT_LOG_ENABLED: bool = os.environ.get("AUDIT_LOG_ENABLED", "true").lower() == "true"
    AUDIT_LOG_RETENTION_DAYS: int = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", "90"))
    AUDIT_LOG_INCLUDE_REQUEST_BODY: bool = os.environ.get("AUDIT_LOG_INCLUDE_REQUEST_BODY", "false").lower() == "true"
    
    # Performance Settings
    MAX_CONCURRENT_REQUESTS: int = int(os.environ.get("MAX_CONCURRENT_REQUESTS", "1000"))
    REQUEST_TIMEOUT_SECONDS: int = int(os.environ.get("REQUEST_TIMEOUT_SECONDS", "30"))
    KEEP_ALIVE_TIMEOUT: int = int(os.environ.get("KEEP_ALIVE_TIMEOUT", "5"))
    
    # Development/Testing Overrides
    TESTING: bool = os.environ.get("TESTING", "false").lower() == "true"
    MOCK_EXTERNAL_SERVICES: bool = os.environ.get("MOCK_EXTERNAL_SERVICES", "false").lower() == "true"
    
    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()

# =============================================================================
# ALERTING SYSTEM
# =============================================================================

import aiohttp
import asyncio
from datetime import datetime, timezone

class AlertManager:
    """Production-grade alerting system"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = structlog.get_logger("tradesage.alerts")
        
    async def send_alert(
        self,
        alert_type: str,
        message: str,
        severity: str = "warning",
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Send alert through configured channels"""
        if not self.settings.ALERTING_ENABLED:
            return
            
        alert_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
            "service": "tradesage-auth-service",
            "environment": self.settings.environment,
            "metadata": metadata or {}
        }
        
        # Send to Slack
        if self.settings.SLACK_WEBHOOK_URL:
            await self._send_slack_alert(alert_data)
            
        # Send email alerts
        if self.settings.ALERT_EMAIL_RECIPIENTS:
            await self._send_email_alert(alert_data)
            
        # Log the alert
        self.logger.warning(
            "Alert triggered",
            **alert_data
        )
    
    async def _send_slack_alert(self, alert_data: Dict[str, Any]):
        """Send alert to Slack webhook"""
        try:
            color_map = {
                "critical": "#ff0000",
                "warning": "#ffaa00",
                "info": "#00ff00"
            }
            
            slack_payload = {
                "text": f"🚨 TradeSage Auth Alert: {alert_data['alert_type']}",
                "attachments": [
                    {
                        "color": color_map.get(alert_data['severity'], "#ffaa00"),
                        "fields": [
                            {
                                "title": "Message",
                                "value": alert_data['message'],
                                "short": False
                            },
                            {
                                "title": "Severity",
                                "value": alert_data['severity'].upper(),
                                "short": True
                            },
                            {
                                "title": "Environment",
                                "value": alert_data['environment'],
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": alert_data['timestamp'],
                                "short": False
                            }
                        ]
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.settings.SLACK_WEBHOOK_URL,
                    json=slack_payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        self.logger.error(
                            "Failed to send Slack alert",
                            status=response.status,
                            response=await response.text()
                        )
                        
        except Exception as e:
            self.logger.error(
                "Error sending Slack alert",
                error=str(e)
            )
    
    async def _send_email_alert(self, alert_data: Dict[str, Any]):
        """Send email alert"""
        try:
            recipients = [
                email.strip() 
                for email in self.settings.ALERT_EMAIL_RECIPIENTS.split(',')
                if email.strip()
            ]
            
            if not recipients:
                return
                
            subject = f"🚨 TradeSage Auth Alert: {alert_data['alert_type']}"
            body = f"""
            Alert Details:
            
            Type: {alert_data['alert_type']}
            Severity: {alert_data['severity'].upper()}
            Message: {alert_data['message']}
            Environment: {alert_data['environment']}
            Timestamp: {alert_data['timestamp']}
            
            Metadata: {alert_data['metadata']}
            """
            
            # Here you would integrate with your email service
            # For now, we'll just log that an email would be sent
            self.logger.info(
                "Email alert would be sent",
                recipients=recipients,
                subject=subject
            )
            
        except Exception as e:
            self.logger.error(
                "Error sending email alert",
                error=str(e)
            )

# =============================================================================
# HEALTH CHECK SYSTEM
# =============================================================================

class HealthChecker:
    """Comprehensive health checking system"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = structlog.get_logger("tradesage.health")
        
    async def check_overall_health(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        health_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "healthy",
            "version": "1.0.0",
            "environment": self.settings.environment,
            "checks": {}
        }
        
        # Database health
        health_data["checks"]["database"] = await self._check_database()
        
        # Redis health
        health_data["checks"]["redis"] = await self._check_redis()
        
        # Session service health
        health_data["checks"]["session_service"] = await self._check_session_service()
        
        # Memory usage
        health_data["checks"]["memory"] = await self._check_memory()
        
        # Disk space
        health_data["checks"]["disk"] = await self._check_disk_space()
        
        # Determine overall status
        failed_checks = [
            name for name, check in health_data["checks"].items()
            if check["status"] != "healthy"
        ]
        
        if failed_checks:
            health_data["status"] = "degraded" if len(failed_checks) < len(health_data["checks"]) else "unhealthy"
            health_data["failed_checks"] = failed_checks
        
        return health_data
    
    async def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity and performance"""
        try:
            start_time = time.time()
            
            from common.database import db_manager
            async with db_manager.get_session() as db:
                await db.execute("SELECT 1")
                
            response_time = time.time() - start_time
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time * 1000, 2),
                "details": "Database connection successful"
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "details": "Database connection failed"
            }
    
    async def _check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity and performance"""
        try:
            start_time = time.time()
            
            from common.redis_client import redis_manager
            redis_client = await redis_manager.get_redis()
            
            if not redis_client:
                return {
                    "status": "unavailable",
                    "details": "Redis client not available"
                }
            
            await redis_client.ping()
            response_time = time.time() - start_time
            
            # Get Redis info
            info = await redis_client.info()
            memory_usage = info.get('used_memory_human', 'unknown')
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time * 1000, 2),
                "memory_usage": memory_usage,
                "details": "Redis connection successful"
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "details": "Redis connection failed"
            }
    
    async def _check_session_service(self) -> Dict[str, Any]:
        """Check session service connectivity"""
        try:
            start_time = time.time()
            
            # This would be a health check specific to your session service
            # For now, we'll simulate a basic connectivity check
            async with aiohttp.ClientSession() as session:
                health_url = f"{self.settings.session_service_url}/health"
                async with session.get(
                    health_url,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    response_time = time.time() - start_time
                    
                    if response.status == 200:
                        return {
                            "status": "healthy",
                            "response_time_ms": round(response_time * 1000, 2),
                            "details": "Session service responding"
                        }
                    else:
                        return {
                            "status": "unhealthy",
                            "status_code": response.status,
                            "details": "Session service returned error"
                        }
                        
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "details": "Session service unreachable"
            }
    
    async def _check_memory(self) -> Dict[str, Any]:
        """Check memory usage"""
        try:
            import psutil
            
            memory = psutil.virtual_memory()
            
            return {
                "status": "healthy" if memory.percent < 90 else "warning",
                "usage_percent": memory.percent,
                "available_gb": round(memory.available / (1024**3), 2),
                "total_gb": round(memory.total / (1024**3), 2),
                "details": f"Memory usage: {memory.percent}%"
            }
            
        except ImportError:
            return {
                "status": "unknown",
                "details": "psutil not available for memory monitoring"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "details": "Failed to check memory usage"
            }
    
    async def _check_disk_space(self) -> Dict[str, Any]:
        """Check disk space"""
        try:
            import psutil
            
            disk = psutil.disk_usage('/')
            usage_percent = (disk.used / disk.total) * 100
            
            return {
                "status": "healthy" if usage_percent < 90 else "warning",
                "usage_percent": round(usage_percent, 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "total_gb": round(disk.total / (1024**3), 2),
                "details": f"Disk usage: {usage_percent:.1f}%"
            }
            
        except ImportError:
            return {
                "status": "unknown",
                "details": "psutil not available for disk monitoring"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "details": "Failed to check disk usage"
            }

# =============================================================================
# CIRCUIT BREAKER IMPLEMENTATION
# =============================================================================

import time
from enum import Enum
from typing import Callable, Any
import asyncio

class CircuitBreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    """Production-grade circuit breaker for external service calls"""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitBreakerState.CLOSED
        self.logger = structlog.get_logger("tradesage.circuit_breaker")
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        
        if self.state == CircuitBreakerState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitBreakerState.HALF_OPEN
                self.logger.info("Circuit breaker entering half-open state")
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
            self._on_success()
            return result
            
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        return (
            time.time() - self.last_failure_time > self.recovery_timeout
        )
    
    def _on_success(self):
        """Handle successful call"""
        self.failure_count = 0
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.CLOSED
            self.logger.info("Circuit breaker closed after successful call")
    
    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            self.logger.warning(
                "Circuit breaker opened",
                failure_count=self.failure_count,
                threshold=self.failure_threshold
            )

# =============================================================================
# INITIALIZATION HELPERS
# =============================================================================

# Global instances (initialize in your main application)
alert_manager: Optional[AlertManager] = None
health_checker: Optional[HealthChecker] = None

def initialize_monitoring(settings: Settings):
    """Initialize monitoring components"""
    global alert_manager, health_checker
    
    alert_manager = AlertManager(settings)
    health_checker = HealthChecker(settings)
    
    logger = structlog.get_logger("tradesage.monitoring")
    logger.info(
        "Monitoring initialized",
        alerting_enabled=settings.ALERTING_ENABLED,
        metrics_enabled=settings.ENABLE_METRICS,
        environment=settings.environment
    )

# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
# In your main FastAPI application:

from monitoring_config import initialize_monitoring, alert_manager, health_checker

@app.on_event("startup")
async def startup_event():
    initialize_monitoring(settings)

# In your route handlers:

@router.get("/health")
async def health_check():
    return await health_checker.check_overall_health()

# For sending alerts:
await alert_manager.send_alert(
    alert_type="high_error_rate",
    message="Authentication error rate exceeded threshold",
    severity="warning",
    metadata={"error_rate": 0.15, "threshold": 0.05}
)
"""