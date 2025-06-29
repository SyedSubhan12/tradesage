# Tradesage Application - Comprehensive System Overview

## Table of Contents
1. [System Architecture](#system-architecture)
2. [Authentication & Authorization](#authentication--authorization)
3. [Session Management](#session-management)
4. [Data Flow & Processing](#data-flow--processing)
5. [Security Implementation](#security-implementation)
6. [Performance & Scalability](#performance--scalability)
7. [Monitoring & Observability](#monitoring--observability)
8. [Deployment Architecture](#deployment-architecture)

---

## System Architecture

### Overview
Tradesage is a **microservices-based financial trading platform** built with modern technologies and production-grade security. The system follows a **3-tier architecture** with clear separation of concerns.

### Core Components

#### Frontend Layer
- **Technology**: React 18 + TypeScript + Vite
- **State Management**: Context API for authentication
- **HTTP Client**: Axios with interceptors for token management
- **Build Tool**: Vite for fast development and production builds
- **Styling**: Tailwind CSS for responsive design

#### API Gateway Layer
- **Technology**: FastAPI (Python 3.10+)
- **Role**: Central entry point, authentication middleware, service routing
- **Features**: CORS handling, rate limiting, request/response transformation
- **Security**: JWT validation, request sanitization

#### Microservices Layer
- **Auth Service**: User authentication, token management, security
- **Session Service**: Session lifecycle, state management, caching
- **User Service**: User profile management, account operations
- **Tenant Service**: Multi-tenancy support, organization management

#### Data Layer
- **Primary Database**: PostgreSQL 14+ with async support
- **Cache Layer**: Redis 6+ for sessions, tokens, rate limiting
- **Encryption**: Fernet symmetric encryption for sensitive data

---

## Authentication & Authorization

### JWT Implementation

#### Token Structure
```yaml
Access Token:
  Algorithm: ES256 (ECDSA with P-256)
  Expiry: 15 minutes
  Audience: tradesage-api-gateway
  Claims: user_id, email, tenant_id, roles, session_id

Refresh Token:
  Algorithm: ES256 (ECDSA with P-256)  
  Expiry: 30 days
  Audience: tradesage-api-gateway
  Claims: user_id, session_id, token_type
```

#### Key Management
- **Private Key**: ECDSA P-256 for token signing
- **Public Key**: ECDSA P-256 for token verification
- **Key Storage**: File-based with proper permissions
- **Key Rotation**: Manual process (planned automation)

### Authentication Flow

#### Login Process
1. **Credential Validation**: Username/password validation with bcrypt
2. **Progressive Lockout**: 1min → 5min → 30min → 24hr → permanent
3. **Session Creation**: Create encrypted session in Redis + PostgreSQL
4. **Token Generation**: Generate JWT access + refresh tokens
5. **Secure Storage**: Store refresh token hash in session
6. **Cookie Setting**: HttpOnly secure cookie for refresh token

#### Token Refresh Process
1. **Token Extraction**: From cookie (preferred) or Authorization header
2. **Format Validation**: JWT structure and encoding validation
3. **Blacklist Check**: Verify token not revoked
4. **Signature Verification**: ES256 signature validation
5. **Claims Validation**: Standard + custom claims check
6. **Session Validation**: Verify session exists and is valid
7. **Security Checks**: IP validation, expiry checks
8. **Token Generation**: Create new access + refresh tokens
9. **Token Rotation**: Store new token, blacklist old token

### Authorization Model
- **Role-Based Access Control (RBAC)**: Admin, Trader, Viewer, API User
- **Multi-Tenancy**: Tenant-based isolation and access control
- **Scope-Based Permissions**: Granular permission system
- **Session-Based Validation**: Continuous session state verification

---

## Session Management

### Architecture
- **Dual Storage**: Redis (fast access) + PostgreSQL (persistence)
- **Encryption**: Fernet symmetric encryption for all session data
- **TTL Management**: 30-day expiration with automatic cleanup
- **Circuit Breaker**: Fault tolerance for database operations

### Session Lifecycle

#### Creation
```python
SessionData:
  session_id: UUID4 identifier
  user_id: Associated user
  client_ip: Request IP address
  user_agent: Browser fingerprint
  refresh_token_hash: SHA256 hash
  created_at: Creation timestamp
  expires_at: 30-day expiration
  version: Optimistic locking
  is_active: Session state
```

#### Validation
- **IP Address Check**: Validate against session IP
- **User Agent Check**: Browser fingerprint validation (currently disabled)
- **Expiry Check**: Automatic expiration handling
- **State Check**: Active session verification

#### Termination
- **Graceful Cleanup**: Mark inactive, audit logging
- **Cache Invalidation**: Remove from Redis cache
- **Token Revocation**: Blacklist associated tokens
- **Database Update**: Update session state in PostgreSQL

### Security Features
- **Encrypted Storage**: All session data encrypted at rest
- **IP Validation**: Session tied to originating IP address
- **Concurrent Session Limits**: Per-user session management
- **Automatic Cleanup**: Background job for expired sessions

---

## Data Flow & Processing

### Request Processing Pipeline

#### Inbound Request Flow
1. **CORS Validation**: Origin and method validation
2. **Rate Limiting**: IP and user-based rate limits
3. **Authentication**: JWT token validation
4. **Authorization**: Role and permission checks
5. **Service Routing**: Route to appropriate microservice
6. **Request Processing**: Execute business logic
7. **Response Generation**: Format and return response

#### Error Handling Pipeline
1. **Error Classification**: Categorize error types
2. **Audit Logging**: Log security and operational events
3. **Metrics Update**: Update Prometheus metrics
4. **Error Response**: Return appropriate HTTP status

### Inter-Service Communication
- **Synchronous**: HTTP/REST for real-time operations
- **Service Discovery**: Direct URL configuration
- **Health Checks**: Endpoint monitoring for dependencies
- **Circuit Breaker**: Fault tolerance for service calls

---

## Security Implementation

### Cryptographic Security
- **Algorithm**: ES256 (ECDSA with P-256 curve)
- **Key Management**: File-based private/public key storage
- **Encryption**: Fernet symmetric encryption for session data
- **Hashing**: SHA256 for token hashes, bcrypt for passwords

### Application Security

#### Input Validation
- **JWT Format**: 3-part structure validation
- **Payload Validation**: Pydantic models for request validation
- **SQL Injection**: SQLAlchemy ORM with parameterized queries
- **XSS Protection**: Content-Type validation and encoding

#### Access Control
- **Authentication**: Multi-factor JWT validation
- **Authorization**: Role-based access control
- **Session Security**: IP and browser validation
- **Token Management**: Rotation and blacklisting

#### Security Headers
```python
Security Headers:
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  X-XSS-Protection: 1; mode=block
  Strict-Transport-Security: max-age=31536000
  Content-Security-Policy: default-src 'self'
```

### Audit & Monitoring
- **Security Events**: Login attempts, token validation, errors
- **Audit Trail**: Comprehensive logging with structured format
- **Prometheus Metrics**: Real-time security metrics
- **Rate Limiting**: Protection against brute force attacks

---

## Performance & Scalability

### Caching Strategy
- **Redis Cache**: Session data, rate limiting, token storage
- **Database Indexing**: Optimized queries for user and session data
- **Connection Pooling**: Async database connections
- **Query Optimization**: Efficient SQL with proper indexes

### Asynchronous Processing
- **Async/Await**: Non-blocking I/O throughout the application
- **Background Tasks**: Session cleanup, audit processing
- **Circuit Breaker**: Fault tolerance for external dependencies
- **Retry Logic**: Resilient session service communication

### Scalability Considerations
- **Horizontal Scaling**: Stateless microservices design
- **Database Scaling**: Read replicas for session queries
- **Cache Scaling**: Redis clustering for high availability
- **Load Balancing**: Gateway can handle multiple service instances

---

## Monitoring & Observability

### Metrics Collection
- **Prometheus Integration**: Custom metrics throughout the application
- **Performance Metrics**: Request duration, error rates
- **Security Metrics**: Failed authentication attempts, token validation
- **Business Metrics**: Active sessions, user activity

### Logging Strategy
- **Structured Logging**: JSON format with contextual information
- **Log Levels**: Debug, Info, Warning, Error with appropriate usage
- **Audit Trails**: Security events with full context
- **Performance Logging**: Request tracing and timing

### Health Monitoring
```python
Health Check Endpoints:
  /health: Basic service health
  /health/detailed: Comprehensive dependency check
  Database Health: Connection and query validation
  Redis Health: Cache connectivity and performance
  Service Dependencies: Inter-service health validation
```

---

## Deployment Architecture

### Environment Configuration
- **Development**: Local development with Docker Compose
- **Staging**: Production-like environment for testing
- **Production**: High-availability deployment with monitoring

### Infrastructure Components
- **Application Servers**: FastAPI with Uvicorn ASGI server
- **Database**: PostgreSQL with connection pooling
- **Cache**: Redis with persistence and clustering
- **Load Balancer**: Nginx or cloud load balancer
- **Monitoring**: Prometheus + Grafana stack

### Security Configuration
- **HTTPS Only**: TLS 1.3 encryption for all communications
- **Certificate Management**: Automated certificate renewal
- **Network Security**: VPC with private subnets
- **Secret Management**: Environment-based configuration

---

## Technology Stack Summary

### Backend Technologies
- **Framework**: FastAPI (Python 3.10+)
- **Database**: PostgreSQL 14+ with asyncpg
- **Cache**: Redis 6+ with asyncio support
- **ORM**: SQLAlchemy 2.0 with async support
- **Authentication**: JWT with ES256 algorithm
- **Monitoring**: Prometheus metrics integration

### Frontend Technologies
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite for development and production
- **HTTP Client**: Axios with request/response interceptors
- **State Management**: React Context API
- **Styling**: Tailwind CSS for responsive design

### Development Tools
- **Package Management**: UV for Python, NPM for Node.js
- **Code Quality**: ESLint, Prettier for frontend
- **Testing**: Pytest for backend, Jest for frontend
- **Documentation**: Markdown with Mermaid diagrams

---

## Configuration Management

### Environment Variables
```yaml
Core Configuration:
  DATABASE_URL: PostgreSQL connection string
  REDIS_URL: Redis connection string
  JWT_PRIVATE_KEY_PATH: Path to private key file
  JWT_PUBLIC_KEY_PATH: Path to public key file
  
Security Configuration:
  ACCESS_TOKEN_EXPIRE_MINUTES: 2
  REFRESH_TOKEN_EXPIRE_DAYS: 30
  BCRYPT_ROUNDS: 12
  
Service Configuration:
  AUTH_SERVICE_URL: Auth service endpoint
  SESSION_SERVICE_URL: Session service endpoint
  USER_SERVICE_URL: User service endpoint
```

### Security Settings
- **CORS Origins**: Configurable allowed origins
- **Rate Limits**: Per-endpoint rate limiting configuration
- **Session Settings**: TTL and cleanup intervals
- **Encryption Keys**: Secure key management

This system overview provides a comprehensive understanding of the Tradesage application architecture, security implementation, and operational characteristics. The system is designed for production use with enterprise-grade security and scalability features.
