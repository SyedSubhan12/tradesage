# TradeSage Platform Makefile
# Simplifies common development and deployment tasks

.PHONY: help setup dev prod test clean logs

# Default target
help:
	@echo "TradeSage Platform Management Commands"
	@echo "====================================="
	@echo "make setup          - Initial setup (create directories, copy env files)"
	@echo "make dev           - Start all services in development mode"
	@echo "make prod          - Start all services in production mode"
	@echo "make test          - Run integration tests"
	@echo "make logs          - Show logs from all services"
	@echo "make stop          - Stop all services"
	@echo "make clean         - Clean up containers and volumes"
	@echo "make db-init       - Initialize database schema"
	@echo "make ma130-setup   - Setup MA130 backup server"
	@echo "make backup        - Create manual backup for all tenants"
	@echo "make monitoring    - Open monitoring dashboards"

# Setup environment
setup:
	@echo "Setting up TradeSage platform..."
	@mkdir -p keys monitoring/prometheus monitoring/grafana/dashboards monitoring/grafana/datasources
	@if [ ! -f .env ]; then cp env.example .env && echo "Created .env file - please update with your values"; fi
	@if [ ! -f keys/ma130_rsa ]; then ssh-keygen -t rsa -b 4096 -f keys/ma130_rsa -N "" && echo "Generated MA130 SSH key"; fi
	@echo "Setup complete! Edit .env file with your configuration."

# Development mode
dev:
	@echo "Starting TradeSage in development mode..."
	docker-compose up -d postgres redis
	@echo "Waiting for database..."
	@sleep 5
	docker-compose up -d auth-service session-service tenant-service
	@echo "Services starting... Check logs with: make logs"

# Production mode
prod:
	@echo "Starting TradeSage in production mode..."
	docker-compose up -d
	@echo "All services starting... Monitor with: make monitoring"

# Run integration tests
test:
	@echo "Running integration tests..."
	@python3 scripts/test_integration_flow.py

# Show logs
logs:
	docker-compose logs -f --tail=100

# Stop services
stop:
	@echo "Stopping all services..."
	docker-compose stop

# Clean up
clean:
	@echo "Cleaning up containers and volumes..."
	docker-compose down -v
	@echo "Clean complete. Run 'make setup' to start fresh."

# Database initialization
db-init:
	@echo "Initializing database schema..."
	docker-compose up -d postgres
	@sleep 5
	docker-compose exec postgres psql -U tradesage_user -d tradesage -c "\
		CREATE EXTENSION IF NOT EXISTS 'uuid-ossp'; \
		CREATE EXTENSION IF NOT EXISTS 'pg_stat_statements'; \
		CREATE ROLE tenant_role WITH LOGIN PASSWORD 'tenant_password'; \
		GRANT CONNECT ON DATABASE tradesage TO tenant_role;"
	@echo "Database initialized"

# Setup MA130 backup server
ma130-setup:
	@echo "Setting up MA130 backup server..."
	@echo "Copy and run this on your MA130 server:"
	@echo "scp scripts/setup_ma130.sh root@$(MA130_HOST):/tmp/"
	@echo "ssh root@$(MA130_HOST) 'bash /tmp/setup_ma130.sh'"
	@echo ""
	@echo "Then copy the SSH public key:"
	@echo "cat keys/ma130_rsa.pub | ssh root@$(MA130_HOST) 'cat >> /home/tradesage_backup/.ssh/authorized_keys'"

# Manual backup
backup:
	@echo "Creating manual backup for all tenants..."
	@docker-compose exec tenant-service python -c "\
		import asyncio; \
		from app.services.backup_service_ma130 import MA130BackupService; \
		# Add backup logic here"

# Open monitoring dashboards
monitoring:
	@echo "Opening monitoring dashboards..."
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3000 (admin/$(GRAFANA_PASSWORD))"
	@echo "Services:"
	@echo "  - API Gateway: http://localhost:8000"
	@echo "  - Auth Service: http://localhost:8001"
	@echo "  - Session Service: http://localhost:8002"
	@echo "  - Tenant Service: http://localhost:8003"

# Service-specific targets
auth-logs:
	docker-compose logs -f auth-service

session-logs:
	docker-compose logs -f session-service

tenant-logs:
	docker-compose logs -f tenant-service

# Health checks
health:
	@echo "Checking service health..."
	@curl -s http://localhost:8001/health | jq '.' || echo "Auth Service: Not responding"
	@curl -s http://localhost:8002/health | jq '.' || echo "Session Service: Not responding"
	@curl -s http://localhost:8003/health | jq '.' || echo "Tenant Service: Not responding"

# Database operations
db-shell:
	docker-compose exec postgres psql -U tradesage_user -d tradesage

redis-cli:
	docker-compose exec redis redis-cli

# Development helpers
rebuild:
	docker-compose build --no-cache

restart: stop prod

# Create monitoring configuration
monitoring-setup:
	@echo "Creating Prometheus configuration..."
	@cat > monitoring/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service:8001']
    metrics_path: '/metrics'
    
  - job_name: 'session-service'
    static_configs:
      - targets: ['session-service:8002']
    metrics_path: '/metrics'
    
  - job_name: 'tenant-service'
    static_configs:
      - targets: ['tenant-service:8003']
    metrics_path: '/metrics'
EOF
	@echo "Monitoring configuration created"

# Quick start
quickstart: setup db-init dev
	@echo "TradeSage is starting up!"
	@echo "Wait a few seconds, then run: make test" 