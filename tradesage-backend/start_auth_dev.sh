#!/bin/bash

# Development script to start auth service with correct environment variables

echo "Starting Auth Service with 2-minute token expiration for testing..."

# Set environment variables
export DATABASE_URL=postgresql+asyncpg://zs:Zunairasubhan@localhost:5432/tradesage

# Security
export SECRET_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
export ALGORITHM=HS256
export ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Redis
export REDIS_URL=redis://localhost:6379
export GOOGLE_CLIENT_ID=246078119801-7ltjprdnaaafbbe3lqt09eg91alejnta.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=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
export GOOGLE_REDIRECT_URI=http://localhost:8080/oauth/google/callback

# Environment
export ENVIRONMENT=development
export DEBUG=true

# Logging
export LOG_LEVEL=INFO
export SESSION_ENCRYPTION_KEY=4uZiBQQOAEaj3LOC7T7sFCW8nRcAMGXIP9ZHtmVdP+4=

# Activate virtual environment if it exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Start the auth service
echo "ACCESS_TOKEN_EXPIRE_MINUTES is set to: $ACCESS_TOKEN_EXPIRE_MINUTES"
uvicorn auth_service.app.main:app --reload --host 127.0.0.1 --port 8000 