#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.

# Run sslsniff and capture OpenAI traffic to a temp file

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEMP_FILE="/tmp/agentsight_capture_$$.json"

echo "AgentSight OpenAI Traffic Capture Test"
echo "========================================"
echo ""
echo "Capture file: $TEMP_FILE"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (for eBPF)"
    echo "Usage: sudo $0"
    exit 1
fi

# Start sslsniff in background, capturing to file
echo "Starting sslsniff..."
timeout 30 "$ROOT_DIR/bpf/sslsniff" -c python > "$TEMP_FILE" 2>&1 &
SNIFFER_PID=$!

# Wait for sniffer to initialize
sleep 2
echo "SSL sniffer running (PID: $SNIFFER_PID)"
echo ""

# Run the test
echo "Running OpenAI test..."
# Use venv python if available
if [ -f "$SCRIPT_DIR/venv/bin/python" ]; then
    PYTHON="$SCRIPT_DIR/venv/bin/python"
else
    PYTHON="python3"
fi
"$PYTHON" "$SCRIPT_DIR/test_openai.py"
echo ""

# Wait a bit for final events
sleep 2

# Stop sniffer
echo "Stopping sniffer..."
kill -INT $SNIFFER_PID 2>/dev/null || true
wait $SNIFFER_PID 2>/dev/null || true

echo ""
echo "Capture complete! File: $TEMP_FILE"
echo ""

# Show file stats
LINE_COUNT=$(wc -l < "$TEMP_FILE")
FILE_SIZE=$(du -h "$TEMP_FILE" | cut -f1)
echo "Captured $LINE_COUNT JSON events ($FILE_SIZE)"
echo ""

# Now decode the captured data
echo "Decoding captured traffic..."
echo "========================================"
"$PYTHON" "$SCRIPT_DIR/decode_capture.py" "$TEMP_FILE"

echo ""
echo "Test complete!"
echo "Raw capture file preserved at: $TEMP_FILE"
