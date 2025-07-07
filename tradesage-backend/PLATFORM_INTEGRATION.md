# TradeSage Platform Integration Guide

## 🏗️ Complete Architecture Overview

The TradeSage platform is a microservices-based trading system with complete tenant isolation, automated backups, and comprehensive monitoring. This guide explains how all services are connected and work together.

## 📊 Service Architecture

### Core Services

1. **API Gateway (Port 8000)**
   - Central entry point for all client requests
   - Routes requests to appropriate services
   - Handles rate limiting and request validation

2. **Auth Service (Port 8001)**
   - User registration and authentication
   - JWT token generation and validation
   - OAuth integration support

3. **Session Service (Port 8002)**
   - Session management and persistence
   - Token validation and caching
   - Activity tracking

4. **Tenant Service (Port 8003)**
   - Multi-tenant schema provisioning
   - Resource monitoring and health checks
   - Automated backups to MA130 server
   - Tenant isolation management

5. **Trading Service (Port 8004)**
   - Order and trade management
   - Portfolio tracking
   - Risk management

6. **Market Data Service (Port 8005)**
   - Real-time market data feeds
   - Historical data storage
   - Market analysis

7. **Analytics Service (Port 8006)**
   - Performance reporting
   - Risk analysis
   - Custom dashboards

## 🔄 Complete Request Flow

### 1. User Registration Flow
```
Client → API Gateway → Auth Service → Database
                    ↓
              Session Service → Redis Cache
                    ↓
              Tenant Service → Create Schema
                    ↓
              MA130 Server ← Initial Backup
```

### 2. Authentication Flow
```
Client → API Gateway → Auth Service → Validate Credentials
                    ↓
              Session Service → Create Session
                    ↓
              Redis Cache ← Store Session
                    ↓
              Return JWT Token → Client
```

### 3. Trading Operation Flow
```
Client (with JWT) → API Gateway → Session Service (Validate)
                               ↓
                        Tenant Service → Get Schema
                               ↓
                        Trading Service → Execute Trade
                               ↓
                        PostgreSQL (Tenant Schema)
                               ↓
                        Redis Cache ← Update Real-time Data
```

### 4. Backup Flow
```
Cron Job → Tenant Service → List Active Tenants
                         ↓
                   For Each Tenant:
                         ↓
                   pg_dump Schema → Compress
                         ↓
                   SSH/SFTP → MA130 Server
                         ↓
                   Verify Backup → Update Metadata
```

## 🔐 Security Architecture

### Multi-Layer Security
1. **Network Level**
   - Firewall rules
   - VPC isolation
   - Service mesh security

2. **Application Level**
   - JWT authentication
   - Role-based access control
   - API rate limiting

3. **Database Level**
   - Schema isolation per tenant
   - Row-level security
   - Encrypted connections

4. **Backup Level**
   - SSH key authentication
   - Encrypted transfers
   - Compressed & encrypted backups

## 💾 MA130 Integration

### Configuration
```yaml
MA130_HOST: 192.168.1.100
MA130_PORT: 22
MA130_USERNAME: tradesage_backup
MA130_KEY_PATH: /app/keys/ma130_rsa
MA130_BACKUP_PATH: /data/tradesage/backups
```

### Backup Structure
```
/data/tradesage/backups/
├── 2024/
│   ├── 01/
│   │   ├── 15/
│   │   │   ├── backup_tenant1_20240115_023000_abc123.sql.gz
│   │   │   └── backup_tenant2_20240115_023005_def456.sql.gz
```

### Setup Steps
1. Run setup script on MA130: `bash setup_ma130.sh`
2. Copy SSH public key to MA130
3. Configure environment variables
4. Test connection from tenant service

## 🚀 Quick Start Guide

### 1. Initial Setup
```bash
cd tradesage-backend
make setup          # Create directories and generate keys
cp env.example .env # Copy environment file
# Edit .env with your configuration
```

### 2. Configure MA130
```bash
# On MA130 server:
sudo bash setup_ma130.sh

# Copy SSH key from your local machine:
cat keys/ma130_rsa.pub | ssh root@MA130_IP 'cat >> /home/tradesage_backup/.ssh/authorized_keys'
```

### 3. Start Services
```bash
make prod           # Start all services in production mode
# OR
make dev            # Start core services in development mode
```

### 4. Initialize Database
```bash
make db-init        # Create extensions and roles
```

### 5. Run Integration Tests
```bash
make test           # Run complete integration test suite
```

## 📊 Monitoring

### Health Checks
```bash
make health         # Check all service health endpoints
```

### Logs
```bash
make logs           # View all service logs
make auth-logs      # View auth service logs
make tenant-logs    # View tenant service logs
```

### Dashboards
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)

## 🔧 Common Operations

### Manual Backup
```bash
# Trigger backup for specific tenant
curl -X POST http://localhost:8003/api/v1/schemas/{tenant_id}/backup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "uuid", "backup_type": "manual"}'
```

### Provision New Tenant
```bash
# Create new tenant schema
curl -X POST http://localhost:8003/api/v1/tenants/provision \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "uuid",
    "organization_name": "New Org",
    "template": "trading"
  }'
```

### Check Tenant Health
```bash
curl http://localhost:8003/api/v1/monitoring/{tenant_id}/health \
  -H "Authorization: Bearer $TOKEN"
```

## 🔍 Troubleshooting

### Service Connection Issues
1. Check service health: `make health`
2. View logs: `make logs`
3. Verify network: `docker network ls`
4. Check environment variables: `docker-compose config`

### MA130 Backup Issues
1. Test SSH connection: `ssh tradesage_backup@MA130_IP`
2. Check disk space: `df -h /data/tradesage/backups`
3. Verify permissions: `ls -la /data/tradesage/backups`
4. Review backup logs: `make tenant-logs | grep backup`

### Database Issues
1. Connect to database: `make db-shell`
2. List schemas: `\dn`
3. Check connections: `SELECT * FROM pg_stat_activity;`
4. View locks: `SELECT * FROM pg_locks;`

## 📈 Performance Optimization

### Database
- Connection pooling configured per service
- Prepared statements for common queries
- Indexes on frequently queried columns
- Partitioning for large tables

### Caching
- Redis for session data (30-day TTL)
- Metrics cached for 5 minutes
- Real-time data with pub/sub

### Backup Performance
- Compressed backups (gzip -9)
- Parallel table operations
- Off-peak scheduling
- Incremental backups (future)

## 🎯 Best Practices

1. **Security**
   - Rotate JWT secrets regularly
   - Update SSH keys periodically
   - Monitor failed login attempts
   - Regular security audits

2. **Monitoring**
   - Set up alerts for high resource usage
   - Monitor backup success/failure
   - Track tenant growth
   - Review performance metrics

3. **Maintenance**
   - Regular backup testing
   - Database vacuum and analyze
   - Log rotation
   - Update dependencies

4. **Scaling**
   - Horizontal scaling for stateless services
   - Read replicas for database
   - Redis cluster for caching
   - Load balancing for API gateway

## 📝 Configuration Reference

### Environment Variables
See `env.example` for complete list of configuration options.

### Service Ports
- API Gateway: 8000
- Auth Service: 8001
- Session Service: 8002
- Tenant Service: 8003
- Trading Service: 8004
- Market Data: 8005
- Analytics: 8006
- PostgreSQL: 5432
- Redis: 6379
- Prometheus: 9090
- Grafana: 3000

## 🆘 Support

For issues or questions:
1. Check the logs first
2. Run integration tests
3. Review this documentation
4. Check service health endpoints

---

**Platform Version**: 1.0.0  
**Last Updated**: 2024-01-15 