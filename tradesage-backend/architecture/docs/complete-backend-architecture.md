# TradeSage Complete Backend Architecture

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Principles](#architecture-principles)
3. [Microservices Overview](#microservices-overview)
4. [Service Descriptions](#service-descriptions)
5. [Data Flow Architecture](#data-flow-architecture)
6. [Security Architecture](#security-architecture)
7. [Infrastructure Components](#infrastructure-components)
8. [Communication Patterns](#communication-patterns)
9. [Deployment Architecture](#deployment-architecture)

## System Overview

TradeSage is a multi-tenant SaaS trading platform built using a microservices architecture. The system is designed to handle high-frequency trading operations with absolute data isolation between tenants, enterprise-grade security, and horizontal scalability.

### Key Characteristics
- **Multi-Tenant**: Complete data isolation using PostgreSQL schemas
- **Microservices**: Loosely coupled services with single responsibilities
- **Event-Driven**: Asynchronous communication for scalability
- **Security-First**: Multiple layers of authentication and authorization
- **Cloud-Native**: Containerized services ready for Kubernetes deployment

## Architecture Principles

### 1. Domain-Driven Design (DDD)
Each microservice represents a bounded context:
- **Auth Domain**: Authentication and authorization
- **Tenant Domain**: Multi-tenant management
- **User Domain**: User profiles and preferences
- **Trading Domain**: Portfolio and trading operations
- **Market Data Domain**: Real-time market information

### 2. API-First Design
- All services expose RESTful APIs
- OpenAPI/Swagger documentation
- Versioned endpoints (/api/v1/)
- Consistent error responses

### 3. Security by Design
- Zero-trust architecture
- mTLS between services
- JWT tokens with tenant context
- Row-level security in database

### 4. Scalability Patterns
- Horizontal scaling for all services
- Database read replicas
- Redis caching layer
- Message queue for async operations

## Microservices Overview

### Current Implementation Status

| Service  | Port | Technology Stack | Purpose |
|---------|------|------------------|----------|
| API Gateway | 8001 | FastAPI + HTTPX | Request routing, authentication |
| Auth Service  | 8000 | FastAPI + JWT + PostgreSQL | Authentication & authorization |
| Tenant Service | 8003 | FastAPI + AsyncPG | Multi-tenant management |
| User Service  | 8004 | FastAPI (planned) | User profiles & preferences |
| Session Service  | 8002 | FastAPI + Redis | Session management |
| Trading Service | 8005 | FastAPI (planned) | Trading operations |
| Market Service | 8006 | FastAPI (planned) | Market data |

## Service Descriptions

### 1. API Gateway (Port: 8001)
**Status**: Running..

The API Gateway serves as the single entry point for all client requests. It handles request routing, authentication verification, and provides a unified interface to the microservices ecosystem.

#### Key Responsibilities:
- **Request Routing**: Forwards requests to appropriate backend services
- **Authentication**: Validates JWT tokens before routing
- **Rate Limiting**: Controls request rates per tenant/user
- **CORS Management**: Handles cross-origin requests
- **Load Balancing**: Distributes requests across service instances
- **Circuit Breaking**: Prevents cascade failures

#### Current Implementation:
```python
# Path-based routing
/api/auth/*     → Auth Service (8000)
/api/tenants/*  → Tenant Service (8003)
/api/users/*    → User Service (8004)
/api/sessions/* → Session Service (8002)
```

#### Missing Features:
- Per-tenant rate limiting
- Request/response logging
- Circuit breaker patterns
- WebSocket support

### 2. Auth Service (Port: 8000)
**Status**: Running..

Handles all authentication and authorization operations for the platform.

#### Key Features:
- **JWT Token Management**: Issues and validates access/refresh tokens
- **User Authentication**: Login, logout, registration
- **OAuth Integration**: Google OAuth implemented
- **Password Security**: Bcrypt hashing, reset functionality
- **Account Security**: Failed login tracking, account lockout
- **Session Management**: Multi-device session support

#### API Endpoints:
```
POST /api/v1/auth/register       - User registration
POST /api/v1/auth/login          - User login
POST /api/v1/auth/logout         - User logout
POST /api/v1/auth/refresh        - Refresh access token
POST /api/v1/auth/verify-email   - Email verification
POST /api/v1/auth/reset-password - Password reset
GET  /api/v1/auth/me            - Get current user
```

#### Security Features:
- Progressive login delays after failed attempts
- Account lockout after 5 failed attempts
- Token blacklisting for logout
- IP address tracking for audit

### 3. Tenant Service (Port: 8003)
**Status**: Running..

Manages the multi-tenant infrastructure with automated schema provisioning and complete data isolation.

#### Key Features:
- **Rapid Schema Provisioning**: Creates isolated schemas in <10 seconds
- **Template Management**: Pre-configured schema templates (basic, professional, enterprise)
- **Security Isolation**: PostgreSQL schemas + RLS + tenant-specific users
- **Resource Monitoring**: Real-time usage tracking per tenant
- **Automated Backups**: Daily backups to S3 with retention policies

#### Core Components:
1. **Schema Provisioner**
   - Cryptographic schema naming (SHA256)
   - Parallel table creation for performance
   - Automatic security policy application
   - TimescaleDB integration for time-series data

2. **Monitoring Service**
   - Schema size tracking
   - Connection count monitoring
   - Query performance metrics
   - Resource limit enforcement

3. **Backup Service**
   - Automated daily backups
   - Point-in-time recovery
   - MA130 storage integration
   - Configurable retention periods

#### API Endpoints:
```
POST   /api/v1/tenants              - Create new tenant
GET    /api/v1/tenants/{id}         - Get tenant details
PUT    /api/v1/tenants/{id}         - Update tenant config
DELETE /api/v1/tenants/{id}         - Deactivate tenant
GET    /api/v1/tenants/{id}/health  - Health metrics
POST   /api/v1/tenants/{id}/backup  - Manual backup
```

### 4. User Service (Port: 8004)
**Status**: Running...

Will manage user profiles, preferences, and permissions.

#### Planned Features:
- User profile management
- Preference storage (trading preferences, UI settings)
- Activity tracking and analytics
- Hierarchical permission system
- Multi-device preference sync

#### Planned Endpoints:
```
GET  /api/v1/users/{id}                  - Get user profile
PUT  /api/v1/users/{id}                  - Update profile
GET  /api/v1/users/{id}/preferences      - Get preferences
PUT  /api/v1/users/{id}/preferences      - Update preferences
GET  /api/v1/users/{id}/activity         - Activity history
GET  /api/v1/users/{id}/permissions      - Effective permissions
```

### 5. Session Service (Port: 8002)
**Status**: Running...

Manages user sessions across devices with Redis backend.

#### Current Features:
- Basic session storage in Redis
- Session expiration handling
- Health check endpoint

#### Planned Enhancements:
- Device fingerprinting
- Concurrent session limits
- Geographic session monitoring
- Session activity tracking
- Real-time session updates via WebSocket

### 6. Trading Service (Port: 8005)
**Status**: Will be implemented soon

Will handle all trading operations and portfolio management.

#### Planned Features:
- Portfolio CRUD operations
- Order management (place, modify, cancel)
- Position tracking with real-time P&L
- Trade execution and routing
- Risk management and limits
- Trade history and analytics

### 7. Market Data Service (Port: 8006)
**Status**: In process..

Will manage real-time and historical market data.

#### Planned Features:
- Real-time price feed integration
- Historical data storage (TimescaleDB)
- Market data distribution via WebSocket
- Technical indicators calculation
- Market analytics and aggregations

## Data Flow Architecture

### 1. Authentication Flow

```
Client → API Gateway → Auth Service → PostgreSQL/Redis
                                   ↓
                              JWT Token
                                   ↓
                         Client (Store Token)
```

**Steps:**
1. Client sends login credentials to API Gateway
2. Gateway forwards to Auth Service
3. Auth Service validates against PostgreSQL
4. On success, generates JWT token with tenant context
5. Stores session in Redis
6. Returns tokens to client

### 2. Tenant Provisioning Flow

```
Admin → API Gateway → Tenant Service → PostgreSQL
                                    ↓
                          Schema Creation (<10s)
                                    ↓
                              S3 Backup
```

**Steps:**
1. Admin creates new tenant via API
2. Tenant Service generates secure schema name
3. Creates isolated PostgreSQL schema
4. Applies security policies and RLS
5. Creates tenant-specific database user
6. Schedules automated backups

### 3. API Request Flow with Tenant Context

```
Client (JWT) → API Gateway → Service → PostgreSQL (Tenant Schema)
                    ↓
            Extract Tenant ID
                    ↓
            Validate Permissions
                    ↓
            Route to Service
```

## Security Architecture

### Multi-Layer Security Model

1. **Network Layer**
   - TLS 1.3 for all external communications
   - mTLS between microservices (planned)
   - Network segmentation in Kubernetes

2. **Application Layer**
   - JWT authentication with short-lived tokens
   - Role-based access control (RBAC)
   - API rate limiting per tenant

3. **Data Layer**
   - PostgreSQL schema isolation
   - Row-level security (RLS)
   - Encrypted connections
   - Audit logging

### Security Components

```
┌────────────────────────────────────────────────────┐
│                  Security Perimeter                 │
├────────────────────────────────────────────────────┤
│  WAF  │  DDoS Protection  │  Rate Limiting  │  IDS │
└────────────────────────────────────────────────────┘
                          │
┌────────────────────────────────────────────────────┐
│                   API Gateway                       │
│  • JWT Validation  • Request Sanitization          │
│  • Tenant Context  • Audit Logging                 │
└────────────────────────────────────────────────────┘
                          │
┌────────────────────────────────────────────────────┐
│                Service Security                     │
│  • mTLS Certificates  • Service Mesh               │
│  • Network Policies   • Secret Management          │
└────────────────────────────────────────────────────┘
                          │
┌────────────────────────────────────────────────────┐
│                 Data Security                       │
│  • Schema Isolation  • RLS Policies                │
│  • Encrypted Storage • Backup Encryption           │
└────────────────────────────────────────────────────┘
```

## Infrastructure Components

### 1. Databases

#### PostgreSQL Cluster (15+)
- **Primary**: Handles all write operations
- **Read Replica 1**: Load balancing for read queries
- **Read Replica 2**: Analytics and reporting
- **TimescaleDB**: Time-series data for market information

**Configuration:**
```yaml
max_connections: 1000
shared_buffers: 32GB
effective_cache_size: 96GB
work_mem: 256MB
```

#### Redis Cluster
- **Session Storage**: User sessions with TTL
- **Cache Layer**: API response caching
- **Pub/Sub**: Real-time event distribution

### 2. Storage

#### MA130
- `tradesage-backups/`: Tenant backup storage
- `tradesage-logs/`: Audit and application logs
- `tradesage-documents/`: User documents

### 3. Message Queue (Planned)
- **Technology**: RabbitMQ or Apache Kafka
- **Use Cases**: Async processing, event streaming

### 4. Monitoring Stack
- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboards
- **AlertManager**: Alert routing
- **ELK Stack**: Log aggregation (planned)

## Communication Patterns

### 1. Synchronous (REST)
- **Protocol**: HTTP/HTTPS
- **Format**: JSON
- **Authentication**: Bearer token (JWT)
- **Timeout**: 30 seconds

### 2. Asynchronous (Events)
- **Pattern**: Publish-Subscribe
- **Broker**: RabbitMQ (planned)
- **Format**: JSON/Protobuf

### 3. Real-time (WebSocket)
- **Use Cases**: Price feeds, notifications
- **Scaling**: Redis Pub/Sub

## Development & Deployment

### Local Development
```bash
# Start all services
docker-compose up -d

# Start individual service
cd auth_service
uvicorn app.main:app --reload --port 8000

# Run tests
pytest tests/ -v
```

### Container Strategy
Each microservice has its own Dockerfile:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: tradesage/auth-service:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
```

## API Standards

### Request Format
```json
{
  "data": {
    "type": "order",
    "attributes": {
      "symbol": "AAPL",
      "quantity": 100,
      "side": "buy"
    }
  }
}
```

### Response Format
```json
{
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "type": "order",
    "attributes": {
      "status": "filled",
      "executed_price": 150.25
    }
  },
  "meta": {
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_abc123"
  }
}
```

### Error Format
```json
{
  "error": {
    "code": "INSUFFICIENT_FUNDS",
    "message": "Not enough balance to execute order",
    "details": {
      "required": 15025.00,
      "available": 10000.00
    }
  }
}
```

## Performance Metrics

### Target SLAs
- **API Response Time**: p99 < 500ms
- **Auth Service**: 1000+ logins/sec
- **Tenant Provisioning**: <10 seconds
- **System Uptime**: 99.9%

### Monitoring Metrics
- Request rate per service
- Response time percentiles
- Error rates by endpoint
- Database connection pool usage
- Cache hit rates
- Queue depth and processing time

## Summary

The TradeSage backend architecture is designed for:
1. **Multi-tenancy**: Complete data isolation with rapid provisioning
2. **Scalability**: Horizontal scaling of all components
3. **Security**: Multiple layers of protection
4. **Performance**: Optimized for high-frequency trading
5. **Maintainability**: Clear service boundaries and responsibilities

The architecture follows cloud-native principles and is ready for deployment on Kubernetes with proper monitoring, security, and scalability features built-in from the ground up.

## Architecture Diagram

See the detailed visual representation in [backend-architecture-flow.svg](./backend-architecture-flow.svg)
