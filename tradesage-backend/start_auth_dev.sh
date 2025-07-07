#!/bin/bash
set -euo pipefail

echo "Loading env variables..."
set -a 
source .env
set +a

echo "Activating virtual environment..."
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Function to start a service in background and track its PID
start_service() {
    local service_name=$1
    local cmd=$2
    echo "Starting ${service_name}..."
    
    # Start in background, log output, store PID
    bash -c "$cmd" > "logs/${service_name// /_}.log" 2>&1 &
    pids+=($!)
}

# Ensure logs folder exists
mkdir -p logs

# Array to track service process IDs
pids=()

start_service "Auth Service" "uvicorn auth_service.app.main:app --reload --host 127.0.0.1 --port 8000"
start_service "Session Service" "cd session_service && uvicorn main:app --reload --port 8082"
start_service "Api Gateway" "uvicorn api_gateway.main:app --reload --port 8081"
start_service "Tenant Service" "uvicorn tenant_service.main:app --reload --port 8003"

echo "All services started successfully. Logs are in ./logs/"
echo "Press Ctrl+C to stop."

# Trap Ctrl+C to shut down all child processes
trap "echo; echo 'Shutting down…'; kill ${pids[*]}; exit 0" SIGINT SIGTERM

# Wait for all background services
wait
