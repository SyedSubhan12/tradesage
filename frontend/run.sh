#!/bin/bash

# Ensure script fails on any error
set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check directory exists and is accessible
check_directory() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        log "Directory $dir does not exist. Creating it..."
        mkdir -p "$dir"
    fi
    if [ ! -w "$dir" ]; then
        log "ERROR: Directory $dir is not writable!"
        return 1
    fi
    return 0
}

# Function to validate npm and node installation
validate_environment() {
    if ! command -v node >/dev/null 2>&1; then
        log "ERROR: Node.js is not installed!"
        exit 1
    fi
    
    if ! command -v npm >/dev/null 2>&1; then
        log "ERROR: npm is not installed!"
        exit 1
    fi
    
    log "Node version: $(node --version)"
    log "npm version: $(npm --version)"
}

# Function to setup WSL environment
setup_wsl_environment() {
    # Check if running in WSL
    if grep -q Microsoft /proc/version || grep -q microsoft /proc/version; then
        log "WSL environment detected, setting up specific configurations..."
        
        # Ensure SHELL is set to bash
        export SHELL="/bin/bash"
        
        # Add common Linux paths to PATH if not already present
        for path in "/usr/local/sbin" "/usr/local/bin" "/usr/sbin" "/usr/bin" "/sbin" "/bin"; do
            if [[ ":$PATH:" != *":$path:"* ]]; then
                export PATH="$path:$PATH"
            fi
        done
        
        # Set DISPLAY for any GUI applications
        if [ -z "$DISPLAY" ]; then
            export DISPLAY=:0
        fi
        
        # Ensure proper file permissions in WSL
        umask 022
        
        # Set NODE_OPTIONS for WSL
        export NODE_OPTIONS="--max-old-space-size=4096 --no-warnings"
        
        log "WSL environment configured successfully"
    fi
}

# Main execution
main() {
    log "Starting application setup..."
    
    # Setup WSL environment if needed
    setup_wsl_environment
    
    # Validate environment
    validate_environment
    
    # Ensure we're in the frontend directory
    cd "$SCRIPT_DIR"
    
    # Verify current directory
    if [ ! -f "package.json" ]; then
        log "ERROR: package.json not found in current directory!"
        exit 1
    fi
    
    # Create necessary directories
    local dirs=("node_modules" "logs" "dist")
    for dir in "${dirs[@]}"; do
        if ! check_directory "$dir"; then
            log "ERROR: Failed to setup directory: $dir"
            exit 1
        fi
    done
    
    # Set NODE_ENV if not already set
    export NODE_ENV=${NODE_ENV:-development}
    
    # Get the command to run
    local command="$1"
    shift
    
    case "$command" in
        "start")
            log "Starting application in production mode..."
            exec npm start
            ;;
        "dev")
            log "Starting application in development mode..."
            if [ -x "$(command -v bun)" ]; then
                log "Using bun for development..."
                exec bun run dev
            else
                log "Using npm for development..."
                # Force use of bash for npm scripts in WSL
                SHELL=/bin/bash exec npm run dev
            fi
            ;;
        "validate")
            log "Validating environment..."
            exec npm run validate:env
            ;;
        *)
            log "Unknown command: $command"
            echo "Usage: $0 {start|dev|validate}"
            echo "Available npm scripts:"
            npm run | grep -A 100 "Scripts available"
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@" 