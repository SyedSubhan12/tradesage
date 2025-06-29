# Tradesage System Architecture Diagrams

## Overall System Architecture

graph TB
    subgraph "Frontend Layer"
        FE["React Frontend<br/>TypeScript/Vite"]
        FE_API["API Client<br/>Axios Instance"]
        FE_AUTH["Auth Context<br/>Token Management"]
    end
    
    subgraph "API Gateway Layer"
        GW["API Gateway<br/>FastAPI"]
        GW_AUTH["Auth Middleware<br/>JWT Validation"]
        GW_PROXY["Reverse Proxy<br/>Service Router"]
    end
    
    subgraph "Microservices"
        AUTH["Auth Service<br/>FastAPI"]
        SESSION["Session Service<br/>FastAPI"]
        USER["User Service<br/>FastAPI"]
        TENANT["Tenant Service<br/>FastAPI"]
    end
    
    subgraph "Data Layer"
        PG[("PostgreSQL<br/>Primary Database")]
        REDIS[("Redis<br/>Session Cache<br/>Token Storage")]
    end
    
    subgraph "Security Components"
        JWT["JWT Manager<br/>ES256 Algorithm"]
        RATE["Rate Limiter<br/>Redis-based"]
        AUDIT["Audit Logger<br/>Security Events"]
        BLACKLIST["Token Blacklist<br/>Revoked Tokens"]
    end
    
    FE --> FE_API
    FE_API --> FE_AUTH
    FE_AUTH --> GW
    
    GW --> GW_AUTH
    GW_AUTH --> JWT
    GW --> GW_PROXY
    GW_PROXY --> AUTH
    GW_PROXY --> SESSION
    GW_PROXY --> USER
    GW_PROXY --> TENANT
    
    AUTH --> PG
    AUTH --> REDIS
    AUTH --> JWT
    AUTH --> RATE
    AUTH --> AUDIT
    AUTH --> BLACKLIST
    
    SESSION --> PG
    SESSION --> REDIS
    
    USER --> PG
    TENANT --> PG
    
    RATE --> REDIS
    BLACKLIST --> PG