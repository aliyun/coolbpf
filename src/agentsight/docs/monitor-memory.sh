#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.


# Memory monitoring script for process and subprocesses
# Usage: ./monitor-memory.sh -p PID [-i interval] [-o output.csv] [-t threshold] [-a] [-n name]

set -e

# Default values
INTERVAL=2
OUTPUT_FILE=""
THRESHOLD=0
ALERT=0
PROCESS_NAME=""
PID=""
INCLUDE_CHILDREN=1
HUMAN_READABLE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    cat << EOF
Memory Monitor - Track memory usage for processes and their children

Usage: $0 [OPTIONS]

Options:
    -p PID          Process ID to monitor
    -n NAME         Process name to monitor (alternative to -p)
    -i INTERVAL     Monitoring interval in seconds (default: 2)
    -o FILE         Output to CSV file
    -t THRESHOLD    Alert when memory exceeds threshold (MB)
    -a              Enable alerts (beep on threshold)
    -c              Exclude children processes
    -h              Human-readable output (MB/GB)
    --help          Show this help message

Examples:
    $0 -p 1234 -i 5 -o memory.csv
    $0 -n "node" -t 500 -a
    $0 -p 5678 -h -c

EOF
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--pid)
            PID="$2"
            shift 2
            ;;
        -n|--name)
            PROCESS_NAME="$2"
            shift 2
            ;;
        -i|--interval)
            INTERVAL="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -t|--threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        -a|--alert)
            ALERT=1
            shift
            ;;
        -c|--no-children)
            INCLUDE_CHILDREN=0
            shift
            ;;
        -h|--human)
            HUMAN_READABLE=1
            shift
            ;;
        --help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate input
if [ -z "$PID" ] && [ -z "$PROCESS_NAME" ]; then
    echo "Error: Either PID (-p) or process name (-n) must be specified"
    usage
fi

# Function to find PID by name
find_pid_by_name() {
    local name="$1"
    local pid=$(pgrep -f "$name" | head -1)
    if [ -z "$pid" ]; then
        echo "Error: No process found matching '$name'"
        exit 1
    fi
    echo $pid
}

# Get PID if name was provided
if [ -n "$PROCESS_NAME" ]; then
    PID=$(find_pid_by_name "$PROCESS_NAME")
    echo "Found process: $PROCESS_NAME (PID: $PID)"
fi

# Verify PID exists
if ! kill -0 $PID 2>/dev/null; then
    echo "Error: Process $PID does not exist"
    exit 1
fi

# Function to get all child PIDs recursively
get_all_children() {
    local parent=$1
    local children=""

    for child in $(pgrep -P $parent 2>/dev/null); do
        children="$children $child"
        local grandchildren=$(get_all_children $child)
        children="$children $grandchildren"
    done

    echo $children
}

# Function to calculate total memory
calculate_memory() {
    local pid=$1
    local include_children=$2
    local total_rss=0
    local total_vsz=0
    local pids="$pid"

    if [ $include_children -eq 1 ]; then
        local children=$(get_all_children $pid)
        if [ -n "$children" ]; then
            pids="$pids $children"
        fi
    fi

    for p in $pids; do
        if kill -0 $p 2>/dev/null; then
            local mem_info=$(ps -p $p -o rss=,vsz= 2>/dev/null || echo "0 0")
            local rss=$(echo $mem_info | awk '{print $1}')
            local vsz=$(echo $mem_info | awk '{print $2}')
            total_rss=$((total_rss + rss))
            total_vsz=$((total_vsz + vsz))
        fi
    done

    echo "$total_rss $total_vsz"
}

# Function to format memory
format_memory() {
    local kb=$1
    if [ $HUMAN_READABLE -eq 1 ]; then
        if [ $kb -ge 1048576 ]; then
            echo "$((kb/1048576)).$(((kb%1048576)*100/1048576)) GB"
        elif [ $kb -ge 1024 ]; then
            echo "$((kb/1024)).$(((kb%1024)*100/1024)) MB"
        else
            echo "$kb KB"
        fi
    else
        echo "$kb KB"
    fi
}

# Function to get process info
get_process_info() {
    local pid=$1
    ps -p $pid -o comm= 2>/dev/null || echo "unknown"
}

# Initialize CSV file
if [ -n "$OUTPUT_FILE" ]; then
    echo "Timestamp,PID,Process,RSS_KB,VSZ_KB,Children_Count,Total_RSS_KB,Total_VSZ_KB" > "$OUTPUT_FILE"
    echo "Logging to: $OUTPUT_FILE"
fi

# Print header
echo "==========================================="
echo "Memory Monitor - PID: $PID"
echo "Process: $(get_process_info $PID)"
echo "Interval: ${INTERVAL}s"
[ $INCLUDE_CHILDREN -eq 1 ] && echo "Mode: Including children" || echo "Mode: Parent only"
[ -n "$THRESHOLD" ] && [ $THRESHOLD -gt 0 ] && echo "Threshold: ${THRESHOLD} MB"
echo "==========================================="
printf "%-20s %-8s %-10s %-10s %-8s %-12s %-12s\n" \
    "Timestamp" "PID" "RSS" "VSZ" "Children" "Total RSS" "Total VSZ"
echo "-------------------------------------------"

# Monitoring loop
while true; do
    # Check if process still exists
    if ! kill -0 $PID 2>/dev/null; then
        echo -e "${RED}Process $PID has terminated${NC}"
        # Try to find new PID by name if specified
        if [ -n "$PROCESS_NAME" ]; then
            sleep 2
            NEW_PID=$(pgrep -f "$PROCESS_NAME" | head -1)
            if [ -n "$NEW_PID" ]; then
                PID=$NEW_PID
                echo -e "${GREEN}Found new process: $PROCESS_NAME (PID: $PID)${NC}"
                continue
            fi
        fi
        break
    fi

    # Get current timestamp
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    # Get children count
    CHILDREN=""
    CHILDREN_COUNT=0
    if [ $INCLUDE_CHILDREN -eq 1 ]; then
        CHILDREN=$(get_all_children $PID)
        CHILDREN_COUNT=$(echo $CHILDREN | wc -w)
    fi

    # Calculate memory
    MEM_INFO=$(calculate_memory $PID $INCLUDE_CHILDREN)
    TOTAL_RSS=$(echo $MEM_INFO | awk '{print $1}')
    TOTAL_VSZ=$(echo $MEM_INFO | awk '{print $2}')

    # Get parent process memory
    PARENT_MEM=$(ps -p $PID -o rss=,vsz= 2>/dev/null || echo "0 0")
    PARENT_RSS=$(echo $PARENT_MEM | awk '{print $1}')
    PARENT_VSZ=$(echo $PARENT_MEM | awk '{print $2}')

    # Format output
    RSS_FORMATTED=$(format_memory $PARENT_RSS)
    VSZ_FORMATTED=$(format_memory $PARENT_VSZ)
    TOTAL_RSS_FORMATTED=$(format_memory $TOTAL_RSS)
    TOTAL_VSZ_FORMATTED=$(format_memory $TOTAL_VSZ)

    # Check threshold
    COLOR=$NC
    TOTAL_RSS_MB=$((TOTAL_RSS / 1024))
    if [ $THRESHOLD -gt 0 ] && [ $TOTAL_RSS_MB -gt $THRESHOLD ]; then
        COLOR=$RED
        if [ $ALERT -eq 1 ]; then
            echo -e "\a" # Beep
        fi
    fi

    # Print current stats
    printf "${COLOR}%-20s %-8s %-10s %-10s %-8s %-12s %-12s${NC}\n" \
        "$TIMESTAMP" \
        "$PID" \
        "$RSS_FORMATTED" \
        "$VSZ_FORMATTED" \
        "$CHILDREN_COUNT" \
        "$TOTAL_RSS_FORMATTED" \
        "$TOTAL_VSZ_FORMATTED"

    # Write to CSV if specified
    if [ -n "$OUTPUT_FILE" ]; then
        PROCESS_NAME_CSV=$(get_process_info $PID)
        echo "$TIMESTAMP,$PID,$PROCESS_NAME_CSV,$PARENT_RSS,$PARENT_VSZ,$CHILDREN_COUNT,$TOTAL_RSS,$TOTAL_VSZ" >> "$OUTPUT_FILE"
    fi

    # Sleep for interval
    sleep $INTERVAL
done

# Summary on exit
echo "==========================================="
if [ -n "$OUTPUT_FILE" ]; then
    echo "Memory data saved to: $OUTPUT_FILE"
    echo "Total samples collected: $(tail -n +2 "$OUTPUT_FILE" | wc -l)"
fi
echo "Monitoring ended at: $(date '+%Y-%m-%d %H:%M:%S')"
echo "==========================================="