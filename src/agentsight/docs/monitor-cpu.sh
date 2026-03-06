#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.


# CPU monitoring script for process and subprocesses
# Usage: ./monitor-cpu.sh -p PID [-i interval] [-o output.csv] [-t threshold] [-a] [-n name]

set -e

# Default values
INTERVAL=2
OUTPUT_FILE=""
THRESHOLD=0
ALERT=0
PROCESS_NAME=""
PID=""
INCLUDE_CHILDREN=1
SHOW_THREADS=0
TOP_MODE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    cat << EOF
CPU Monitor - Track CPU usage for processes and their children

Usage: $0 [OPTIONS]

Options:
    -p PID          Process ID to monitor
    -n NAME         Process name to monitor (alternative to -p)
    -i INTERVAL     Monitoring interval in seconds (default: 2)
    -o FILE         Output to CSV file
    -t THRESHOLD    Alert when CPU exceeds threshold (%)
    -a              Enable alerts (beep on threshold)
    -c              Exclude children processes
    -T              Show thread-level CPU usage
    -m              Top mode (show top CPU consumers)
    --help          Show this help message

Examples:
    $0 -p 1234 -i 5 -o cpu.csv
    $0 -n "python" -t 80 -a
    $0 -p 5678 -T -m

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
        -T|--threads)
            SHOW_THREADS=1
            shift
            ;;
        -m|--top-mode)
            TOP_MODE=1
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

# Function to calculate CPU usage
calculate_cpu() {
    local pid=$1
    local include_children=$2
    local total_cpu=0
    local pids="$pid"
    local cpu_data=""

    if [ $include_children -eq 1 ]; then
        local children=$(get_all_children $pid)
        if [ -n "$children" ]; then
            pids="$pids $children"
        fi
    fi

    for p in $pids; do
        if kill -0 $p 2>/dev/null; then
            local cpu=$(ps -p $p -o pcpu= 2>/dev/null || echo "0")
            # Remove any whitespace
            cpu=$(echo $cpu | tr -d ' ')
            if [ -n "$cpu" ]; then
                # Use awk for floating point addition
                total_cpu=$(awk "BEGIN {print $total_cpu + $cpu}")
                cpu_data="$cpu_data $p:$cpu"
            fi
        fi
    done

    echo "$total_cpu|$cpu_data"
}

# Function to get CPU time
get_cpu_time() {
    local pid=$1
    ps -p $pid -o time= 2>/dev/null || echo "00:00:00"
}

# Function to get process info
get_process_info() {
    local pid=$1
    ps -p $pid -o comm= 2>/dev/null || echo "unknown"
}

# Function to get thread count
get_thread_count() {
    local pid=$1
    if [ -d /proc/$pid/task ]; then
        ls /proc/$pid/task | wc -l
    else
        echo "1"
    fi
}

# Function to show thread details
show_thread_details() {
    local pid=$1
    if [ $SHOW_THREADS -eq 1 ]; then
        echo ""
        echo "Thread Details for PID $pid:"
        ps -L -p $pid -o tid,pcpu,time,comm | head -10
    fi
}

# Function to get system CPU info
get_system_cpu_info() {
    local cores=$(nproc)
    local load=$(uptime | awk -F'load average:' '{print $2}')
    echo "CPU Cores: $cores | Load Average:$load"
}

# Initialize CSV file
if [ -n "$OUTPUT_FILE" ]; then
    echo "Timestamp,PID,Process,CPU%,Time,Children_Count,Total_CPU%,Threads" > "$OUTPUT_FILE"
    echo "Logging to: $OUTPUT_FILE"
fi

# Initialize previous values for delta calculation
declare -A prev_utime
declare -A prev_stime
declare -A prev_time

# Function to get CPU stats from /proc
get_proc_cpu_stats() {
    local pid=$1
    if [ -f /proc/$pid/stat ]; then
        local stats=$(cat /proc/$pid/stat)
        local utime=$(echo "$stats" | awk '{print $14}')
        local stime=$(echo "$stats" | awk '{print $15}')
        echo "$utime $stime"
    else
        echo "0 0"
    fi
}

# Print header
echo "==========================================="
echo "CPU Monitor - PID: $PID"
echo "Process: $(get_process_info $PID)"
echo "$(get_system_cpu_info)"
echo "Interval: ${INTERVAL}s"
[ $INCLUDE_CHILDREN -eq 1 ] && echo "Mode: Including children" || echo "Mode: Parent only"
[ $SHOW_THREADS -eq 1 ] && echo "Thread monitoring: Enabled"
[ -n "$THRESHOLD" ] && [ $THRESHOLD -gt 0 ] && echo "Threshold: ${THRESHOLD}%"
echo "==========================================="
printf "%-20s %-8s %-15s %-8s %-10s %-8s %-10s %-8s\n" \
    "Timestamp" "PID" "Process" "CPU%" "Time" "Children" "Total%" "Threads"
echo "-------------------------------------------"

# Monitoring loop
LOOP_COUNT=0
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

    # Calculate CPU
    CPU_INFO=$(calculate_cpu $PID $INCLUDE_CHILDREN)
    TOTAL_CPU=$(echo $CPU_INFO | cut -d'|' -f1)
    CPU_DETAILS=$(echo $CPU_INFO | cut -d'|' -f2)

    # Get parent process CPU
    PARENT_CPU=$(ps -p $PID -o pcpu= 2>/dev/null | tr -d ' ' || echo "0")
    PARENT_TIME=$(get_cpu_time $PID)
    PROCESS_NAME_DISPLAY=$(get_process_info $PID)
    THREAD_COUNT=$(get_thread_count $PID)

    # Check threshold
    COLOR=$NC
    TOTAL_CPU_INT=$(echo "$TOTAL_CPU" | cut -d'.' -f1)
    if [ $THRESHOLD -gt 0 ] && [ $TOTAL_CPU_INT -ge $THRESHOLD ]; then
        COLOR=$RED
        if [ $ALERT -eq 1 ]; then
            echo -e "\a" # Beep
        fi
    elif [ $TOTAL_CPU_INT -ge 50 ]; then
        COLOR=$YELLOW
    fi

    # Print current stats
    printf "${COLOR}%-20s %-8s %-15s %-8s %-10s %-8s %-10s %-8s${NC}\n" \
        "$TIMESTAMP" \
        "$PID" \
        "${PROCESS_NAME_DISPLAY:0:15}" \
        "${PARENT_CPU}%" \
        "$PARENT_TIME" \
        "$CHILDREN_COUNT" \
        "${TOTAL_CPU}%" \
        "$THREAD_COUNT"

    # Show top CPU consumers if in top mode
    if [ $TOP_MODE -eq 1 ] && [ -n "$CHILDREN" ]; then
        echo "  Top CPU consumers:"
        ALL_PIDS="$PID $CHILDREN"
        for p in $ALL_PIDS; do
            if kill -0 $p 2>/dev/null; then
                CPU=$(ps -p $p -o pcpu= 2>/dev/null | tr -d ' ')
                COMM=$(ps -p $p -o comm= 2>/dev/null)
                if [ -n "$CPU" ] && [ "$(awk "BEGIN {print ($CPU > 1)}")" = "1" ]; then
                    printf "    PID %-8s %-15s %6s%%\n" "$p" "${COMM:0:15}" "$CPU"
                fi
            fi
        done | sort -k4 -rn | head -5
    fi

    # Show thread details if requested
    if [ $SHOW_THREADS -eq 1 ] && [ $((LOOP_COUNT % 5)) -eq 0 ]; then
        show_thread_details $PID
    fi

    # Write to CSV if specified
    if [ -n "$OUTPUT_FILE" ]; then
        echo "$TIMESTAMP,$PID,$PROCESS_NAME_DISPLAY,$PARENT_CPU,$PARENT_TIME,$CHILDREN_COUNT,$TOTAL_CPU,$THREAD_COUNT" >> "$OUTPUT_FILE"
    fi

    # Show system load periodically
    if [ $((LOOP_COUNT % 10)) -eq 0 ] && [ $LOOP_COUNT -gt 0 ]; then
        echo "-------------------------------------------"
        echo "$(get_system_cpu_info)"
        echo "-------------------------------------------"
    fi

    LOOP_COUNT=$((LOOP_COUNT + 1))

    # Sleep for interval
    sleep $INTERVAL
done

# Summary on exit
echo "==========================================="
echo "Monitoring Summary"
echo "-------------------------------------------"

# Calculate average CPU if CSV exists
if [ -n "$OUTPUT_FILE" ] && [ -f "$OUTPUT_FILE" ]; then
    AVG_CPU=$(tail -n +2 "$OUTPUT_FILE" | awk -F',' '{sum+=$7; count++} END {if(count>0) printf "%.2f", sum/count; else print "0"}')
    MAX_CPU=$(tail -n +2 "$OUTPUT_FILE" | awk -F',' '{if($7>max) max=$7} END {print max}')
    SAMPLES=$(tail -n +2 "$OUTPUT_FILE" | wc -l)

    echo "CPU data saved to: $OUTPUT_FILE"
    echo "Total samples: $SAMPLES"
    echo "Average total CPU: ${AVG_CPU}%"
    echo "Peak total CPU: ${MAX_CPU}%"
fi

echo "Monitoring ended at: $(date '+%Y-%m-%d %H:%M:%S')"
echo "==========================================="