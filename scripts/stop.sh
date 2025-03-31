#!/bin/bash
# Script to stop the Network Feature Extractor

# Get the base directory
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$BASE_DIR"

# Check if PID file exists
if [ ! -f "run.pid" ]; then
    echo "Network Feature Extractor does not appear to be running."
    exit 0
fi

# Get PID from file
PID=$(cat run.pid)

# Check if process is running
if ! ps -p "$PID" > /dev/null; then
    echo "Process with PID $PID is not running."
    rm run.pid
    exit 0
fi

# Send SIGTERM to gracefully stop the process
echo "Stopping Network Feature Extractor (PID: $PID)..."
kill -TERM "$PID"

# Wait for process to stop
TIMEOUT=30
for ((i=0; i<TIMEOUT; i++)); do
    if ! ps -p "$PID" > /dev/null; then
        echo "Network Feature Extractor stopped successfully."
        rm run.pid
        exit 0
    fi
    sleep 1
done

# If process didn't stop, try SIGKILL
echo "Process did not stop gracefully. Sending SIGKILL..."
kill -KILL "$PID"

# Final check
sleep 2
if ps -p "$PID" > /dev/null; then
    echo "Failed to stop process with PID $PID."
    exit 1
else
    echo "Network Feature Extractor forcefully stopped."
    rm run.pid
    exit 0
fi
