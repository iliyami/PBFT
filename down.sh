#!/bin/bash

# PBFT System Port Cleanup Script
# This script kills processes using ports 5001-5007 (servers) and 8001-8010 (clients)

echo "🔧 Cleaning up PBFT system ports..."

# Function to kill process on a specific port
kill_port() {
    local port=$1
    local pid=$(lsof -ti:$port 2>/dev/null)
    if [ ! -z "$pid" ]; then
        echo "  Killing process $pid on port $port"
        kill -9 $pid 2>/dev/null
    else
        echo "  Port $port is free"
    fi
}

echo "📡 Cleaning server ports (5001-5007)..."
for port in {5001..5007}; do
    kill_port $port
done

echo "👥 Cleaning client ports (8001-8010)..."
for port in {8001..8010}; do
    kill_port $port
done

echo "🧹 Cleaning test client ports (9001-9010)..."
for port in {9001..9010}; do
    kill_port $port
done

# Also kill any python processes that might be running our PBFT system
echo "🐍 Cleaning up Python PBFT processes..."
pkill -f "python.*main.py" 2>/dev/null
pkill -f "python3.*main.py" 2>/dev/null

# Wait a moment for processes to terminate
sleep 1

echo "✅ Port cleanup completed!"
echo "💡 You can now run your PBFT tests without port conflicts."
