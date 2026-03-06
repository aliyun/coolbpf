#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.

set -e

echo "Testing AgentSight Docker with Binary Path Mapping"
echo "==================================================="
echo ""
echo "This approach:"
echo "  - Runs agentsight in Docker with --pid=host"
echo "  - Maps host Python binary into container"
echo "  - Uses --binary-path to attach eBPF to host binary"
echo "  - Runs Python test on host (not in container)"
echo ""

# Configuration
IMAGE_NAME="ghcr.io/eunomia-bpf/agentsight:latest"
CONTAINER_NAME="agentsight-test-$$"
HOST_PORT=7395
LOG_DIR="$(pwd)/test-logs"
SCRIPT_DIR="$(dirname "$0")"

# Find Python binary
PYTHON_BIN=$(which python3)
echo "Host Python binary: $PYTHON_BIN"

# Create log directory
mkdir -p "$LOG_DIR"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

# Check if .env exists
if [ ! -f "$SCRIPT_DIR/../script/test-python/.env" ]; then
    echo "Error: .env file not found at $SCRIPT_DIR/../script/test-python/.env"
    echo "Please create it with your OPENAI_API_KEY"
    exit 1
fi

echo ""
echo "Step 1: Starting AgentSight in Docker with --pid=host..."
echo "   Image: $IMAGE_NAME"
echo "   Port: $HOST_PORT"
echo "   Note: With --pid=host, eBPF attaches to host processes using host paths"
echo "   No binary path mapping needed - sslsniff finds libssl.so.3 automatically"

# Start agentsight with --pid=host and mount host libraries
# eBPF uprobes need to read the library files to attach, so mount /lib and /usr/lib
docker run -d \
    --name "$CONTAINER_NAME" \
    --privileged \
    --pid=host \
    --network=host \
    -v /sys:/sys:ro \
    -v /lib:/lib:ro \
    -v /usr/lib:/usr/lib:ro \
    -v "$LOG_DIR:/logs" \
    "$IMAGE_NAME" \
    record --comm python3 --server-port "$HOST_PORT" --log-file /logs/capture.log

echo "   Container started: $CONTAINER_NAME"
echo "   Waiting 5 seconds for eBPF initialization..."
sleep 5

# Check if container is still running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "   ⚠️  Container exited unexpectedly"
    echo ""
    echo "Container logs:"
    docker logs "$CONTAINER_NAME"
    exit 1
fi

echo ""
echo "Step 2: Running Python OpenAI test on host..."
echo "   This will generate SSL traffic that AgentSight should capture"

# Check if venv exists
if [ ! -d "$SCRIPT_DIR/../script/test-python/venv" ]; then
    echo "   Creating Python virtual environment..."
    cd "$SCRIPT_DIR/../script/test-python" && bash setup_venv.sh
    cd - > /dev/null
fi

# Run the test script on host
"$SCRIPT_DIR/../script/test-python/venv/bin/python3" "$SCRIPT_DIR/../script/test-python/test_openai.py"

echo ""
echo "Step 3: Waiting for capture to complete..."
sleep 5

echo ""
echo "Step 4: Analyzing captured traffic..."

if [ -f "$LOG_DIR/capture.log" ]; then
    echo "   Log file size: $(du -h "$LOG_DIR/capture.log" | cut -f1)"

    # Count events
    SSL_EVENTS=$(grep -c '"source":"ssl"' "$LOG_DIR/capture.log" 2>/dev/null || echo "0")
    HTTP_EVENTS=$(grep -c '"event_type":"http"' "$LOG_DIR/capture.log" 2>/dev/null || echo "0")
    PROCESS_EVENTS=$(grep -c '"source":"process"' "$LOG_DIR/capture.log" 2>/dev/null || echo "0")

    echo "   SSL events captured: $SSL_EVENTS"
    echo "   HTTP events captured: $HTTP_EVENTS"
    echo "   Process events captured: $PROCESS_EVENTS"

    if [ "$SSL_EVENTS" -gt 0 ] || [ "$HTTP_EVENTS" -gt 0 ]; then
        echo ""
        echo "✅ SUCCESS: AgentSight captured SSL/HTTP traffic using binary path mapping!"
        echo ""

        # Extract interesting information
        echo "Captured HTTP requests:"
        grep '"event_type":"http"' "$LOG_DIR/capture.log" 2>/dev/null | \
            jq -r '"\(.data.request.method) \(.data.request.path)"' 2>/dev/null | \
            head -n 5 || echo "  (Could not parse HTTP events)"

        echo ""
        echo "View results:"
        echo "   - Web UI: http://localhost:$HOST_PORT"
        echo "   - Log file: $LOG_DIR/capture.log"

        # Show sample SSL event
        echo ""
        echo "Sample SSL event:"
        grep '"source":"ssl"' "$LOG_DIR/capture.log" 2>/dev/null | head -n 1 | jq -C '.' || true

    elif [ "$PROCESS_EVENTS" -gt 0 ]; then
        echo ""
        echo "⚠️  PARTIAL: Captured process events but no SSL/HTTP traffic"
        echo "   Process events: $PROCESS_EVENTS"
        echo ""
        echo "Possible reasons:"
        echo "   - SSL library not found or different version"
        echo "   - Python uses different SSL implementation"
        echo "   - eBPF uprobes couldn't attach to SSL functions"
        echo ""
        echo "Sample process event:"
        grep '"source":"process"' "$LOG_DIR/capture.log" | head -n 1 | jq -C '.'
    else
        echo ""
        echo "❌ FAILED: No events captured"
    fi

    echo ""
    echo "Full event breakdown:"
    echo "   Total events: $(wc -l < "$LOG_DIR/capture.log")"
    echo "   SSL events: $SSL_EVENTS"
    echo "   HTTP events: $HTTP_EVENTS"
    echo "   Process events: $PROCESS_EVENTS"

else
    echo "   ⚠️  Log file not created: $LOG_DIR/capture.log"
    echo ""
    echo "Container logs:"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -n 20
fi

echo ""
echo "Test complete. Container will be stopped and removed."
