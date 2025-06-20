# TradeSage Authentication Service Documentation
## Overview
The TradeSage Authentication Service is a robust microservice responsible for user authentication, authorization, and tenant management. It provides a comprehensive set of features for secure user management in a multi-tenant environment.

## Core Features
### 1. User Authentication
- Login System : Secure JWT-based authentication with access and refresh tokens
- Token Management : Creation, validation, and refreshing of JWT tokens
- Session Management : Tracking of active user sessions
- Account Security : Progressive account lockout after failed login attempts
### 2. User Management
- User Registration : Creation of new user accounts with automatic tenant creation
- Profile Management : Retrieval of user profile information
- Password Management : Secure password change and reset functionality
### 3. Tenant Management
- Multi-tenancy Support : Isolation of data between different tenants
- Tenant Status : Tracking and validation of tenant status (active, suspended, etc.)
### 4. OAuth 2.0 Support
- OAuth Client Management : Creation and management of OAuth clients
- Authorization Code Flow : Complete implementation of OAuth 2.0 authorization code flow
- Refresh Token Flow : Support for OAuth 2.0 refresh token flow
- Client Credentials Flow : Support for OAuth 2.0 client credentials flow
### 5. Security Features
- Rate Limiting : Protection against brute force attacks
- Tenant Isolation : Middleware to ensure tenant data isolation
- Token Blacklisting : Prevention of token reuse after logout
- Audit Logging : Comprehensive logging of security-related events
## Implementation Details
### Architecture
The auth service is built using FastAPI and follows a modular architecture:

- Routers : Endpoint definitions organized by feature
  
  - auth.py : Authentication endpoints (login, logout, token refresh, etc.)
  - users.py : User management endpoints (registration, profile)
  - tenant.py : Tenant management endpoints
  - oauth.py : OAuth 2.0 endpoints
- Services : Business logic layer
  
  - auth_service.py : Authentication-related business logic
  - user_service.py : User-related business logic
- Models : Database models
  
  - User, Tenant, TokenBlacklist, UserSession, etc.
- Schemas : Pydantic models for request/response validation
  
  - UserLogin, TokenResponse, PasswordReset, etc.
- Middlewares : Request processing middleware
  
  - RateLimitMiddleware : Rate limiting implementation
  - TenantIsolationMiddleware : Tenant isolation implementation
### Key Endpoints Authentication
- POST /auth/token : Login and get access/refresh tokens
- POST /auth/logout : Logout and invalidate tokens
- POST /auth/refresh : Refresh access token
- GET /auth/verify-token : Verify token validity Password Management
- POST /auth/password/change : Change password (authenticated)
- POST /auth/password/reset-request : Request password reset
- POST /auth/password/reset-confirm : Confirm password reset User Management
- POST /users/register : Register new user
- GET /users/me : Get current user profile Tenant Management
- GET /tenant/status/{tenant_id} : Get tenant status OAuth 2.0
- POST /oauth/clients : Create OAuth client
- GET /oauth/clients : List OAuth clients
- GET /oauth/authorize : OAuth authorization endpoint
- POST /oauth/token : OAuth token endpoint
### Security Mechanisms Account Lockout
Progressive account lockout after failed login attempts:

- 3 failed attempts: 1 minute lockout
- 5 failed attempts: 5 minutes lockout
- 7 failed attempts: 30 minutes lockout
- 10 failed attempts: 24 hours lockout
- 15 failed attempts: Permanent lockout (requires admin intervention) Rate Limiting
Requests are limited to 60 per minute per client IP and endpoint, with exceptions for health checks and documentation endpoints.
 Tenant Isolation
The TenantIsolationMiddleware ensures tenant data isolation by extracting tenant_id from request bodies or authorization headers and storing it in the request state.