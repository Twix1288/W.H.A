#!/bin/bash

echo "🚀 Starting Smoke Test..."

# 1. Start the shield-agent in the background
./shield-agent &
AGENT_PID=$!

# Wait for the Unix socket to be created
echo "⏳ Waiting for socket initialization..."
sleep 2

# 2. Connect to the socket using netcat and stream output to a log file
echo "🔌 Connecting to /tmp/shield-agent.sock..."
nc -U /tmp/shield-agent.sock > /tmp/output.log &
NC_PID=$!

# Give the Go binary time to attach eBPF probes after accepting the connection
sleep 3

# 3. Trigger a network connection using curl
echo "🌐 Triggering outbound network call to 1.1.1.1:443..."
curl -s -m 2 https://1.1.1.1 > /dev/null

# Wait for the ring buffer to flush to the socket
sleep 2

# 4. Read the output log to verify the NDJSON event
echo "📊 Smoke Test Results:"
echo "----------------------------------------"
cat /tmp/output.log
echo "----------------------------------------"

# Cleanup
kill $NC_PID
kill $AGENT_PID
