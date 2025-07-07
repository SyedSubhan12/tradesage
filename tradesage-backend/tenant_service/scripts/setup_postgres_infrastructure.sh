#!/bin/bash
# PostgreSQL Multi-Tenant Infrastructure Setup Script

set -e

echo "=== TradeSage PostgreSQL Multi-Tenant Infrastructure Setup ==="

# Configuration
DB_NAME="tradesage_production"
DB_USER="tradesage_admin"
DB_PORT=5432
REPLICA1_PORT=5433
REPLICA2_PORT=5434

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check prerequisites
echo "Checking prerequisites..."

if ! command_exists psql; then
    print_error "PostgreSQL client not found. Please install PostgreSQL 15+"
    exit 1
fi

if ! command_exists pg_config; then
    print_error "PostgreSQL development files not found"
    exit 1
fi

print_status "PostgreSQL client found"

# Create database and enable extensions
echo -e "\n${GREEN}Step 1: Creating database and extensions${NC}"

sudo -u postgres psql <<EOF
-- Create database
CREATE DATABASE ${DB_NAME} 
    WITH 
    OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1;

-- Connect to database
\c ${DB_NAME}

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Check if TimescaleDB is available and install
DO \$\$
BEGIN
    CREATE EXTENSION IF NOT EXISTS timescaledb;
    RAISE NOTICE 'TimescaleDB extension installed successfully';
EXCEPTION
    WHEN OTHERS THEN
        RAISE WARNING 'TimescaleDB not available - time-series features will be limited';
END\$\$;

-- Create admin user
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '${DB_USER}') THEN
        CREATE USER ${DB_USER} WITH ENCRYPTED PASSWORD 'ChangeMeInProduction!';
        GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
        ALTER USER ${DB_USER} CREATEDB;
    END IF;
END\$\$;

GRANT ALL ON SCHEMA public TO ${DB_USER};
EOF

print_status "Database created and extensions enabled"

# Create system tables
echo -e "\n${GREEN}Step 2: Creating system tables${NC}"

sudo -u postgres psql -d ${DB_NAME} <<'EOF'
-- Tenant credentials table (would use Vault in production)
CREATE TABLE IF NOT EXISTS tenant_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    schema_name VARCHAR(100) UNIQUE NOT NULL,
    db_user VARCHAR(100) NOT NULL,
    db_password_encrypted TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Provisioning failures log
CREATE TABLE IF NOT EXISTS provisioning_failures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    error_message TEXT NOT NULL,
    stack_trace TEXT,
    failed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log table
CREATE TABLE IF NOT EXISTS system_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    tenant_id VARCHAR(255),
    schema_name VARCHAR(100),
    user_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_tenant_credentials_tenant_id ON tenant_credentials(tenant_id);
CREATE INDEX idx_provisioning_failures_tenant_id ON provisioning_failures(tenant_id);
CREATE INDEX idx_system_audit_log_tenant_id ON system_audit_log(tenant_id, created_at DESC);
EOF

print_status "System tables created"

# Create template schemas
echo -e "\n${GREEN}Step 3: Creating template schemas${NC}"

sudo -u postgres psql -d ${DB_NAME} <<'EOF'
-- Create trading template schema
CREATE SCHEMA IF NOT EXISTS template_trading;

SET search_path TO template_trading;

-- Portfolios table
CREATE TABLE IF NOT EXISTS portfolios (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    base_currency CHAR(3) DEFAULT 'USD',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Positions table
CREATE TABLE IF NOT EXISTS positions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID REFERENCES portfolios(id) ON DELETE CASCADE,
    symbol VARCHAR(20) NOT NULL,
    quantity DECIMAL(20,8) NOT NULL,
    avg_price DECIMAL(20,8) NOT NULL,
    current_price DECIMAL(20,8),
    realized_pnl DECIMAL(20,8) DEFAULT 0,
    unrealized_pnl DECIMAL(20,8) DEFAULT 0,
    opened_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Trades table
CREATE TABLE IF NOT EXISTS trades (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID REFERENCES portfolios(id) ON DELETE CASCADE,
    symbol VARCHAR(20) NOT NULL,
    side VARCHAR(4) CHECK (side IN ('BUY', 'SELL')),
    quantity DECIMAL(20,8) NOT NULL,
    price DECIMAL(20,8) NOT NULL,
    commission DECIMAL(20,8) DEFAULT 0,
    executed_at TIMESTAMPTZ NOT NULL,
    order_id VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Market data table
CREATE TABLE IF NOT EXISTS market_data (
    symbol VARCHAR(20),
    timestamp TIMESTAMPTZ,
    open DECIMAL(20,8),
    high DECIMAL(20,8),
    low DECIMAL(20,8),
    close DECIMAL(20,8),
    volume BIGINT,
    PRIMARY KEY (symbol, timestamp)
);

-- Create indexes
CREATE INDEX idx_portfolios_user_id ON portfolios(user_id);
CREATE INDEX idx_positions_portfolio_id ON positions(portfolio_id);
CREATE INDEX idx_positions_symbol ON positions(symbol);
CREATE INDEX idx_trades_portfolio_id ON trades(portfolio_id);
CREATE INDEX idx_trades_executed_at ON trades(executed_at DESC);
CREATE INDEX idx_market_data_symbol ON market_data(symbol, timestamp DESC);

-- Reset search path
SET search_path TO public;
EOF

print_status "Template schemas created"

# Configure PostgreSQL for multi-tenancy
echo -e "\n${GREEN}Step 4: Configuring PostgreSQL for multi-tenancy${NC}"

# Create configuration file
cat > /tmp/postgresql_multitenant.conf <<'EOF'
# Multi-tenant optimizations
max_connections = 1000
shared_buffers = 8GB
effective_cache_size = 24GB
maintenance_work_mem = 2GB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 256MB
min_wal_size = 1GB
max_wal_size = 4GB

# Enable query tracking
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.max = 10000
pg_stat_statements.track = all

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_line_prefix = '%t [%p]: user=%u,db=%d,app=%a,client=%h '
log_checkpoints = on
log_connections = on
log_disconnections = on
log_duration = off
log_lock_waits = on
log_statement = 'ddl'
log_temp_files = 0

# Connection pooling readiness
max_prepared_transactions = 100
EOF

print_warning "PostgreSQL configuration generated at /tmp/postgresql_multitenant.conf"
print_warning "Please review and apply to your postgresql.conf"

# Create PgBouncer configuration
echo -e "\n${GREEN}Step 5: Creating PgBouncer configuration${NC}"

cat > /tmp/pgbouncer.ini <<EOF
[databases]
${DB_NAME} = host=localhost port=${DB_PORT} dbname=${DB_NAME}

[pgbouncer]
listen_port = 6432
listen_addr = *
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = session
max_client_conn = 5000
default_pool_size = 25
reserve_pool_size = 5
reserve_pool_timeout = 3
server_lifetime = 3600
server_idle_timeout = 600
log_connections = 1
log_disconnections = 1
log_pooler_errors = 1
stats_period = 60

# Per-database limits
max_db_connections = 100
EOF

print_status "PgBouncer configuration created at /tmp/pgbouncer.ini"

# Create monitoring queries
echo -e "\n${GREEN}Step 6: Creating monitoring functions${NC}"

sudo -u postgres psql -d ${DB_NAME} <<'EOF'
-- Function to monitor schema sizes
CREATE OR REPLACE FUNCTION get_tenant_schema_sizes()
RETURNS TABLE(schema_name text, size_pretty text, size_bytes bigint)
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        n.nspname::text as schema_name,
        pg_size_pretty(sum(pg_total_relation_size(c.oid))::bigint) as size_pretty,
        sum(pg_total_relation_size(c.oid))::bigint as size_bytes
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname LIKE 'tenant_%'
    GROUP BY n.nspname
    ORDER BY size_bytes DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to check active connections per schema
CREATE OR REPLACE FUNCTION get_tenant_connections()
RETURNS TABLE(schema_name text, connection_count bigint)
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        schemaname::text,
        count(*)::bigint
    FROM pg_stat_activity
    JOIN pg_stat_user_tables ON datname = current_database()
    WHERE schemaname LIKE 'tenant_%'
    GROUP BY schemaname;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permissions
GRANT EXECUTE ON FUNCTION get_tenant_schema_sizes() TO ${DB_USER};
GRANT EXECUTE ON FUNCTION get_tenant_connections() TO ${DB_USER};
EOF

print_status "Monitoring functions created"

# Create backup script
echo -e "\n${GREEN}Step 7: Creating backup script${NC}"

cat > /tmp/backup_tenant.sh <<'EOF'
#!/bin/bash
# Tenant backup script

TENANT_ID=$1
SCHEMA_NAME=$2
BACKUP_DIR="/var/backups/tradesage/tenants"

if [ -z "$TENANT_ID" ] || [ -z "$SCHEMA_NAME" ]; then
    echo "Usage: $0 <tenant_id> <schema_name>"
    exit 1
fi

# Create backup directory
mkdir -p "${BACKUP_DIR}/${TENANT_ID}"

# Backup file name with timestamp
BACKUP_FILE="${BACKUP_DIR}/${TENANT_ID}/backup_$(date +%Y%m%d_%H%M%S).dump"

# Perform backup
pg_dump \
    --dbname=tradesage_production \
    --schema=${SCHEMA_NAME} \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    --verbose \
    --file="${BACKUP_FILE}"

if [ $? -eq 0 ]; then
    echo "Backup successful: ${BACKUP_FILE}"
    
    # Upload to S3 (if configured)
    if command -v aws >/dev/null 2>&1; then
        aws s3 cp "${BACKUP_FILE}" "s3://tradesage-backups/tenants/${TENANT_ID}/"
    fi
else
    echo "Backup failed!"
    exit 1
fi
EOF

chmod +x /tmp/backup_tenant.sh
print_status "Backup script created at /tmp/backup_tenant.sh"

# Summary
echo -e "\n${GREEN}=== Setup Complete ===${NC}"
echo -e "\nNext steps:"
echo "1. Review and apply PostgreSQL configuration from /tmp/postgresql_multitenant.conf"
echo "2. Set up PgBouncer with configuration from /tmp/pgbouncer.ini"
echo "3. Configure replication for read replicas"
echo "4. Set up automated backups using /tmp/backup_tenant.sh"
echo "5. Install TimescaleDB if not already installed"
echo -e "\n${YELLOW}Remember to change all default passwords before production use!${NC}"

# Test query
echo -e "\n${GREEN}Testing installation:${NC}"
sudo -u postgres psql -d ${DB_NAME} -c "SELECT version();"
sudo -u postgres psql -d ${DB_NAME} -c "SELECT extname FROM pg_extension;" 