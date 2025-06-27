import re
import json
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from urllib.parse import unquote, quote
from enum import Enum

import structlog
from fastapi import Request, Response, HTTPException, status
from pydantic import BaseModel, Field

from common.config import settings

# =============================================================================
# ENUMS AND MODELS
# =============================================================================

class CookieSameSite(str, Enum):
    """Cookie SameSite attribute values"""
    STRICT = "strict"
    LAX = "lax"
    NONE = "none"

class CookieSecurityLevel(str, Enum):
    """Cookie security levels for different environments"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class CookieConfig(BaseModel):
    """Cookie configuration model"""
    name: str
    secure: bool = True
    httponly: bool = True
    samesite: CookieSameSite = CookieSameSite.LAX
    path: str = "/"
    domain: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[datetime] = None

class CookieExtractionResult(BaseModel):
    """Result of cookie extraction attempt"""
    token: Optional[str] = None
    method: str = "none"
    success: bool = False
    debug_info: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)

# =============================================================================
# PRODUCTION COOKIE MANAGER CLASS
# =============================================================================

class CookieManager:
    """
    Enterprise-grade cookie manager for authentication tokens with:
    - Multiple extraction methods with fallbacks
    - Comprehensive security controls
    - Environment-aware configuration
    - Detailed logging and debugging
    - Token integrity validation
    - Anti-tampering mechanisms
    """
    
    def __init__(self, settings_obj=None):
        self.settings = settings_obj or settings
        self.logger = structlog.get_logger("tradesage.cookies")
        self.security_level = self._determine_security_level()
        
        # Initialize cookie configurations
        self.refresh_token_config = self._create_refresh_token_config()
        self.session_config = self._create_session_config()
        
        self.logger.info(
            "Cookie manager initialized",
            security_level=self.security_level,
            environment=self.settings.environment,
            secure_cookies=self.refresh_token_config.secure
        )
    
    def _determine_security_level(self) -> CookieSecurityLevel:
        """Determine security level based on environment"""
        env = getattr(self.settings, 'environment', 'development').lower()
        
        if env == 'production':
            return CookieSecurityLevel.PRODUCTION
        elif env in ['staging', 'test']:
            return CookieSecurityLevel.STAGING
        else:
            return CookieSecurityLevel.DEVELOPMENT
    
    def _create_refresh_token_config(self) -> CookieConfig:
        """Create refresh token cookie configuration"""
        is_production = self.security_level == CookieSecurityLevel.PRODUCTION
        
        return CookieConfig(
            name="refresh_token",
            secure=is_production or getattr(self.settings, 'COOKIE_SECURE', True),
            httponly=True,
            samesite=CookieSameSite(getattr(self.settings, 'COOKIE_SAMESITE', 'lax')),
            path=getattr(self.settings, 'COOKIE_PATH', '/auth'),
            domain=getattr(self.settings, 'COOKIE_DOMAIN', None) if is_production else None
        )
    
    def _create_session_config(self) -> CookieConfig:
        """Create session cookie configuration"""
        is_production = self.security_level == CookieSecurityLevel.PRODUCTION
        
        return CookieConfig(
            name="session_id",
            secure=is_production or getattr(self.settings, 'COOKIE_SECURE', True),
            httponly=True,
            samesite=CookieSameSite(getattr(self.settings, 'COOKIE_SAMESITE', 'lax')),
            path="/",
            domain=getattr(self.settings, 'COOKIE_DOMAIN', None) if is_production else None
        )
    
    # =============================================================================
    # REFRESH TOKEN MANAGEMENT
    # =============================================================================
    
    def set_refresh_token_cookie(
        self,
        response: Response,
        token: str,
        expires_at: datetime,
        request: Optional[Request] = None
    ) -> bool:
        """
        Set refresh token cookie with production security settings
        
        Args:
            response: FastAPI Response object
            token: Refresh token value
            expires_at: Token expiration datetime
            request: Optional Request object for context
            
        Returns:
            bool: True if cookie was set successfully
        """
        try:
            # Validate token
            if not self._validate_token_format(token):
                self.logger.error("Invalid token format for cookie setting")
                return False
            
            # Create cookie configuration
            config = self.refresh_token_config.copy()
            config.expires = expires_at
            config.max_age = int((expires_at - datetime.now(timezone.utc)).total_seconds())
            
            # Add integrity check in development
            if self.security_level == CookieSecurityLevel.DEVELOPMENT:
                token = self._add_integrity_check(token)
            
            # Set the cookie
            cookie_kwargs = {
                "key": config.name,
                "value": token,
                "httponly": config.httponly,
                "secure": config.secure,
                "samesite": config.samesite.value,
                "path": config.path,
                "max_age": config.max_age
            }
            
            # Add domain only if specified and in production
            if config.domain and self.security_level == CookieSecurityLevel.PRODUCTION:
                cookie_kwargs["domain"] = config.domain
            
            response.set_cookie(**cookie_kwargs)
            
            # Audit logging
            self.logger.info(
                "Refresh token cookie set successfully",
                path=config.path,
                secure=config.secure,
                samesite=config.samesite.value,
                expires=expires_at.isoformat(),
                max_age=config.max_age,
                token_length=len(token),
                has_domain=bool(config.domain),
                correlation_id=self._get_correlation_id(request) if request else None
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to set refresh token cookie",
                error=str(e),
                token_length=len(token) if token else 0
            )
            return False
    
    def extract_refresh_token(self, request: Request) -> CookieExtractionResult:
        """
        Extract refresh token with multiple fallback methods and comprehensive debugging
        
        Args:
            request: FastAPI Request object
            
        Returns:
            CookieExtractionResult: Extraction result with token and metadata
        """
        result = CookieExtractionResult()
        correlation_id = self._get_correlation_id(request)
        
        self.logger.debug(
            "Starting refresh token extraction",
            correlation_id=correlation_id,
            user_agent=request.headers.get("user-agent", "unknown"),
            origin=request.headers.get("origin", "unknown")
        )
        
        # Method 1: Standard FastAPI cookie extraction
        result = self._extract_via_standard_method(request, result)
        
        # Method 2: Manual header parsing (fallback)
        if not result.success:
            result = self._extract_via_header_parsing(request, result)
        
        # Method 3: URL decoding (if needed)
        if result.success and result.token:
            result = self._apply_url_decoding(result)
        
        # Method 4: Integrity check validation (development)
        if result.success and self.security_level == CookieSecurityLevel.DEVELOPMENT:
            result = self._validate_integrity_check(result)
        
        # Method 5: JSON body fallback (for specific clients)
        if not result.success:
            result = self._extract_from_json_body(request, result)
        
        # Comprehensive logging
        self.logger.debug(
            "Refresh token extraction completed",
            method=result.method,
            success=result.success,
            token_length=len(result.token) if result.token else 0,
            errors=result.errors,
            correlation_id=correlation_id,
            **result.debug_info
        )
        
        # Development debugging
        if self.security_level == CookieSecurityLevel.DEVELOPMENT and not result.success:
            self._log_development_debug_info(request, result)
        
        return result
    
    def clear_refresh_token_cookie(self, response: Response) -> bool:
        """
        Clear refresh token cookie securely
        
        Args:
            response: FastAPI Response object
            
        Returns:
            bool: True if cookie was cleared successfully
        """
        try:
            config = self.refresh_token_config
            
            delete_kwargs = {
                "key": config.name,
                "path": config.path
            }
            
            # Add domain only if specified and in production
            if config.domain and self.security_level == CookieSecurityLevel.PRODUCTION:
                delete_kwargs["domain"] = config.domain
            
            response.delete_cookie(**delete_kwargs)
            
            self.logger.info(
                "Refresh token cookie cleared successfully",
                path=config.path,
                has_domain=bool(config.domain)
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to clear refresh token cookie",
                error=str(e)
            )
            return False
    
    # =============================================================================
    # SESSION MANAGEMENT
    # =============================================================================
    
    def set_session_cookie(
        self,
        response: Response,
        session_id: str,
        expires_at: Optional[datetime] = None,
        request: Optional[Request] = None
    ) -> bool:
        """Set session cookie with appropriate security settings"""
        try:
            config = self.session_config.copy()
            
            if expires_at:
                config.expires = expires_at
                config.max_age = int((expires_at - datetime.now(timezone.utc)).total_seconds())
            
            cookie_kwargs = {
                "key": config.name,
                "value": session_id,
                "httponly": config.httponly,
                "secure": config.secure,
                "samesite": config.samesite.value,
                "path": config.path
            }
            
            if config.max_age:
                cookie_kwargs["max_age"] = config.max_age
            
            if config.domain and self.security_level == CookieSecurityLevel.PRODUCTION:
                cookie_kwargs["domain"] = config.domain
            
            response.set_cookie(**cookie_kwargs)
            
            self.logger.info(
                "Session cookie set successfully",
                session_id=session_id[:8] + "...",  # Partial session ID for security
                path=config.path,
                correlation_id=self._get_correlation_id(request) if request else None
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to set session cookie",
                error=str(e),
                session_id=session_id[:8] + "..." if session_id else None
            )
            return False
    
    def extract_session_id(self, request: Request) -> Optional[str]:
        """Extract session ID from cookie"""
        try:
            session_id = request.cookies.get(self.session_config.name)
            
            self.logger.debug(
                "Session ID extraction",
                found=bool(session_id),
                session_preview=session_id[:8] + "..." if session_id else None
            )
            
            return session_id
            
        except Exception as e:
            self.logger.error(
                "Failed to extract session ID",
                error=str(e)
            )
            return None
    
    def clear_session_cookie(self, response: Response) -> bool:
        """Clear session cookie"""
        try:
            config = self.session_config
            
            delete_kwargs = {
                "key": config.name,
                "path": config.path
            }
            
            if config.domain and self.security_level == CookieSecurityLevel.PRODUCTION:
                delete_kwargs["domain"] = config.domain
            
            response.delete_cookie(**delete_kwargs)
            
            self.logger.info("Session cookie cleared successfully")
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to clear session cookie",
                error=str(e)
            )
            return False
    
    # =============================================================================
    # EXTRACTION METHODS (PRIVATE)
    # =============================================================================
    
    def _extract_via_standard_method(self, request: Request, result: CookieExtractionResult) -> CookieExtractionResult:
        """Method 1: Standard FastAPI cookie extraction"""
        try:
            token = request.cookies.get(self.refresh_token_config.name)
            if token:
                result.token = token
                result.method = "standard"
                result.success = True
                result.debug_info["standard_extraction"] = "success"
            else:
                result.debug_info["standard_extraction"] = "no_token"
                result.debug_info["available_cookies"] = list(request.cookies.keys())
                
        except Exception as e:
            result.errors.append(f"Standard extraction failed: {str(e)}")
            result.debug_info["standard_extraction"] = f"error: {str(e)}"
        
        return result
    
    def _extract_via_header_parsing(self, request: Request, result: CookieExtractionResult) -> CookieExtractionResult:
        """Method 2: Manual header parsing"""
        try:
            cookie_header = request.headers.get("cookie", "")
            result.debug_info["cookie_header_present"] = bool(cookie_header)
            result.debug_info["cookie_header_length"] = len(cookie_header)
            
            if cookie_header:
                # Look for refresh_token in cookie header
                pattern = rf'{self.refresh_token_config.name}=([^;]+)'
                match = re.search(pattern, cookie_header)
                
                if match:
                    result.token = match.group(1)
                    result.method = "manual_header"
                    result.success = True
                    result.debug_info["manual_extraction"] = "success"
                else:
                    result.debug_info["manual_extraction"] = "no_match"
                    # Log all cookies found for debugging
                    all_cookies = re.findall(r'(\w+)=([^;]+)', cookie_header)
                    result.debug_info["all_cookies_found"] = [name for name, _ in all_cookies]
            else:
                result.debug_info["manual_extraction"] = "no_header"
                
        except Exception as e:
            result.errors.append(f"Header parsing failed: {str(e)}")
            result.debug_info["manual_extraction"] = f"error: {str(e)}"
        
        return result
    
    def _apply_url_decoding(self, result: CookieExtractionResult) -> CookieExtractionResult:
        """Method 3: URL decoding if necessary"""
        try:
            if result.token:
                decoded_token = unquote(result.token)
                if decoded_token != result.token:
                    result.token = decoded_token
                    result.method = "url_decoded"
                    result.debug_info["url_decoding"] = "applied"
                else:
                    result.debug_info["url_decoding"] = "not_needed"
                    
        except Exception as e:
            result.errors.append(f"URL decoding failed: {str(e)}")
            result.debug_info["url_decoding"] = f"error: {str(e)}"
        
        return result
    
    def _extract_from_json_body(self, request: Request, result: CookieExtractionResult) -> CookieExtractionResult:
        """Method 5: JSON body fallback (for specific clients)"""
        try:
            content_type = request.headers.get("content-type", "")
            result.debug_info["content_type"] = content_type
            
            if "application/json" in content_type:
                # Note: This is a fallback method for clients that can't send cookies
                # In practice, you'd need to modify this based on your specific needs
                result.debug_info["json_body_check"] = "content_type_json_detected"
                # Implementation would depend on whether you want to support this pattern
            else:
                result.debug_info["json_body_check"] = "not_json_content"
                
        except Exception as e:
            result.errors.append(f"JSON body extraction failed: {str(e)}")
            result.debug_info["json_body_check"] = f"error: {str(e)}"
        
        return result
    
    # =============================================================================
    # INTEGRITY AND VALIDATION METHODS
    # =============================================================================
    
    def _validate_token_format(self, token: str) -> bool:
        """Validate token format (JWT structure)"""
        if not token:
            return False
        
        # Basic JWT format validation (3 parts separated by dots)
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Check if parts are not empty
        return all(part for part in parts)
    
    def _add_integrity_check(self, token: str) -> str:
        """Add integrity check to token (development only)"""
        try:
            # Create a simple checksum
            checksum = hashlib.md5(token.encode()).hexdigest()[:8]
            return f"{token}.{checksum}"
        except Exception:
            return token
    
    def _validate_integrity_check(self, result: CookieExtractionResult) -> CookieExtractionResult:
        """Validate integrity check (development only)"""
        try:
            if result.token and '.' in result.token:
                # Check if this looks like a token with integrity check
                parts = result.token.rsplit('.', 1)
                if len(parts) == 2 and len(parts[1]) == 8:
                    token_part, checksum = parts
                    expected_checksum = hashlib.md5(token_part.encode()).hexdigest()[:8]
                    
                    if checksum == expected_checksum:
                        result.token = token_part
                        result.debug_info["integrity_check"] = "valid"
                    else:
                        result.debug_info["integrity_check"] = "invalid"
                        result.errors.append("Integrity check failed")
                        result.success = False
                else:
                    result.debug_info["integrity_check"] = "not_present"
                    
        except Exception as e:
            result.errors.append(f"Integrity validation failed: {str(e)}")
            result.debug_info["integrity_check"] = f"error: {str(e)}"
        
        return result
    
    # =============================================================================
    # UTILITY METHODS
    # =============================================================================
    
    def _get_correlation_id(self, request: Optional[Request]) -> Optional[str]:
        """Extract correlation ID from request"""
        if not request:
            return None
        
        return (request.headers.get("X-Correlation-ID") or 
                request.headers.get("X-Request-ID") or 
                "unknown")
    
    def _log_development_debug_info(self, request: Request, result: CookieExtractionResult):
        """Log comprehensive debugging info for development"""
        debug_data = {
            "all_request_cookies": dict(request.cookies),
            "cookie_header": request.headers.get("cookie", ""),
            "user_agent": request.headers.get("user-agent", ""),
            "origin": request.headers.get("origin", ""),
            "referer": request.headers.get("referer", ""),
            "content_type": request.headers.get("content-type", ""),
            "request_method": getattr(request, 'method', 'unknown'),
            "request_url": str(getattr(request, 'url', 'unknown')),
            "extraction_errors": result.errors,
            "extraction_debug": result.debug_info
        }
        
        self.logger.debug(
            "Development debugging - comprehensive request info",
            **debug_data
        )
    
    # =============================================================================
    # SECURITY AND MONITORING METHODS
    # =============================================================================
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get recommended security headers for cookie protection"""
        headers = {}
        
        if self.security_level == CookieSecurityLevel.PRODUCTION:
            headers.update({
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin"
            })
        
        return headers
    
    def validate_cookie_security(self, request: Request) -> Dict[str, Any]:
        """Validate cookie security configuration"""
        validation_result = {
            "secure": True,
            "issues": [],
            "recommendations": []
        }
        
        # Check if HTTPS is being used in production
        if self.security_level == CookieSecurityLevel.PRODUCTION:
            is_https = (
                request.url.scheme == "https" or
                request.headers.get("x-forwarded-proto") == "https" or
                request.headers.get("x-forwarded-ssl") == "on"
            )
            
            if not is_https:
                validation_result["secure"] = False
                validation_result["issues"].append("HTTPS not detected in production")
        
        # Check for secure cookie configuration
        if not self.refresh_token_config.secure and self.security_level == CookieSecurityLevel.PRODUCTION:
            validation_result["issues"].append("Secure flag not set for cookies in production")
        
        # Check SameSite configuration
        if self.refresh_token_config.samesite == CookieSameSite.NONE and not self.refresh_token_config.secure:
            validation_result["issues"].append("SameSite=None requires Secure flag")
        
        return validation_result
    
    def get_cookie_metrics(self) -> Dict[str, Any]:
        """Get cookie-related metrics for monitoring"""
        return {
            "security_level": self.security_level.value,
            "refresh_token_config": {
                "secure": self.refresh_token_config.secure,
                "samesite": self.refresh_token_config.samesite.value,
                "httponly": self.refresh_token_config.httponly,
                "path": self.refresh_token_config.path,
                "has_domain": bool(self.refresh_token_config.domain)
            },
            "session_config": {
                "secure": self.session_config.secure,
                "samesite": self.session_config.samesite.value,
                "httponly": self.session_config.httponly,
                "path": self.session_config.path,
                "has_domain": bool(self.session_config.domain)
            }
        }

# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def create_cookie_manager(settings_obj=None) -> CookieManager:
    """Factory function to create a cookie manager instance"""
    return CookieManager(settings_obj)

# =============================================================================
# GLOBAL INSTANCE (SINGLETON PATTERN)
# =============================================================================

# Global cookie manager instance
_cookie_manager_instance: Optional[CookieManager] = None

def get_cookie_manager() -> CookieManager:
    """Get global cookie manager instance (singleton)"""
    global _cookie_manager_instance
    
    if _cookie_manager_instance is None:
        _cookie_manager_instance = CookieManager()
    
    return _cookie_manager_instance

# =============================================================================
# FASTAPI DEPENDENCY
# =============================================================================

def get_cookie_manager_dependency() -> CookieManager:
    """FastAPI dependency to inject cookie manager"""
    return get_cookie_manager()