#!/bin/bash
# Script to start the Network Feature Extractor

# Get the base directory
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$BASE_DIR"

# Create directories
mkdir -p logs output

# Function to check if the extractor is already running
is_running() {
    if [ -f "run.pid" ]; then
        PID=$(cat run.pid)
        if ps -p "$PID" > /dev/null; then
            return 0
        else
            # Remove stale PID file
            rm run.pid
        fi
    fi
    return 1
}

# Check if already running
if is_running; then
    echo "Network Feature Extractor is already running. PID: $(cat run.pid)"
    exit 1
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not found. Please install Python 3."
    exit 1
fi

# Check for configuration file
CONFIG_FILE="$BASE_DIR/config/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Start the extractor
echo "Starting Network Feature Extractor..."
nohup python3 -m src.main --config "$CONFIG_FILE" > logs/stdout.log 2> logs/stderr.log &
PID=$!

# Save PID to file
echo $PID > run.pid

# Check if started successfully
sleep 2
if ps -p "$PID" > /dev/null; then
    echo "Network Feature Extractor started successfully with PID: $PID"
    echo "Logs are being written to logs/stdout.log and logs/stderr.log"
    exit 0
else
    echo "Failed to start Network Feature Extractor. Check logs for details."
    exit 1
fi
