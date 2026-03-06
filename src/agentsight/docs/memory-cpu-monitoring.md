# Memory and CPU Monitoring for Processes and Subprocesses

This guide provides comprehensive methods to monitor both memory and CPU usage for processes and their children.

## Quick Reference

### Memory Metrics
- **RSS**: Resident Set Size - Physical memory currently used
- **VSZ**: Virtual Size - Total virtual memory allocated
- **PSS**: Proportional Set Size - Shared memory divided among processes
- **USS**: Unique Set Size - Memory unique to process

### CPU Metrics
- **%CPU**: Percentage of CPU time used
- **TIME**: Total CPU time consumed
- **User Time**: Time spent in user mode
- **System Time**: Time spent in kernel mode

## Memory Monitoring Commands

### Basic Memory Checks
```bash
# Process tree with memory
ps auxf --sort=-rss | head -20

# Specific process and children
ps aux --forest | grep processname

# Memory for PID and children
pstree -p PID | grep -oP '\d+' | xargs ps -o pid,comm,rss,vsz -p

# Sum RSS for parent and children
ps --ppid PARENT_PID -o rss= | awk '{sum+=$1} END {print sum " KB"}'
```

### Advanced Memory Analysis
```bash
# Detailed memory maps
sudo pmap -x PID

# Memory from /proc
cat /proc/PID/status | grep -E "Vm|Rss"

# Shared memory analysis
cat /proc/PID/smaps_rollup
```

## CPU Monitoring Commands

### Basic CPU Checks
```bash
# Process tree with CPU usage
ps auxf --sort=-pcpu | head -20

# CPU usage for specific process and children
ps aux --forest | grep processname

# Real-time CPU monitoring
top -H -p PID

# CPU time for process tree
ps -eo pid,ppid,pcpu,time,comm --forest | grep -A10 -B2 PID
```

### Advanced CPU Analysis
```bash
# Per-thread CPU usage
ps -eLf | grep PID

# CPU affinity
taskset -cp PID

# Detailed CPU stats from /proc
cat /proc/PID/stat | awk '{print "User time: "$14" System time: "$15}'

# CPU usage over time
pidstat -p PID 1
```

## Combined Memory and CPU Monitoring

### One Command for Both
```bash
# Memory and CPU for process tree
ps auxf | awk 'NR==1 || /processname/'

# Detailed stats for PID and children
ps -eo pid,ppid,pcpu,rss,vsz,time,comm --forest | grep -A20 -B2 PID

# Watch both metrics
watch -n 1 'ps aux --forest | grep -E "(processname|PID)"'
```

### Using /proc for Both Metrics
```bash
# Function to get both metrics
get_process_stats() {
    local pid=$1
    if [ -f /proc/$pid/status ]; then
        echo "PID: $pid"
        grep "VmRSS\|VmSize" /proc/$pid/status
        ps -p $pid -o pcpu,time --no-headers
    fi
}
```

## System Tools for Monitoring

### htop
```bash
# Interactive process viewer with tree
htop -t

# Monitor specific PID
htop -p PID
```

### glances
```bash
# System-wide monitoring
glances

# Export to CSV
glances --export csv --export-csv-file /tmp/stats.csv
```

### pidstat
```bash
# CPU and memory statistics
pidstat -r -u -p PID 1

# Include children
pidstat -r -u -T ALL -p PID 1
```

### systemd-cgtop
```bash
# Monitor cgroups (services)
systemd-cgtop

# Sort by memory
systemd-cgtop -m

# Sort by CPU
systemd-cgtop -p
```

## Practical Examples

### Monitor Node.js Application
```bash
# Find Node.js process
NODE_PID=$(pgrep -f "node.*app.js")

# Show complete stats
ps -p $NODE_PID -o pid,ppid,pcpu,rss,vsz,time,comm --forest

# Monitor with children
watch -n 2 "ps --ppid $NODE_PID -o pid,pcpu,rss,comm"
```

### Monitor Python with Workers
```bash
# Get main process
PYTHON_PID=$(pgrep -f "python.*main.py" | head -1)

# Show worker stats
ps --ppid $PYTHON_PID -o pid,tid,pcpu,rss,comm

# Calculate totals
ps --ppid $PYTHON_PID -o pcpu=,rss= | awk '{cpu+=$1; mem+=$2} END {print "Total CPU: "cpu"% Memory: "mem" KB"}'
```

### Monitor Java Application
```bash
# Find Java process
JAVA_PID=$(pgrep -f "java.*MainClass")

# Show thread-level CPU
ps -eLf | grep $JAVA_PID | awk '{print $2, $4, $5, $10}'

# JVM-specific monitoring
jstat -gcutil $JAVA_PID 1000
```

## Resource Limits and Control

### Check Limits
```bash
# Current limits for process
cat /proc/PID/limits

# System limits
ulimit -a
```

### Control with cgroups
```bash
# Create cgroup for memory limit
sudo cgcreate -g memory:/myapp
echo 500M > /sys/fs/cgroup/memory/myapp/memory.limit_in_bytes

# Create cgroup for CPU limit
sudo cgcreate -g cpu:/myapp
echo 50000 > /sys/fs/cgroup/cpu/myapp/cpu.cfs_quota_us
```

## Integration with AgentSight

### Combined Monitoring
```bash
# Start AgentSight
sudo ./agentsight trace --ssl --process --comm node --server &

# Monitor resources alongside
watch -n 2 'echo "=== AgentSight Process Resources ==="; \
    ps aux | grep -E "(agentsight|node)" | grep -v grep; \
    echo "=== Memory Summary ==="; \
    ps aux | grep -E "(agentsight|node)" | awk "{sum+=\$6} END {print \"Total RSS: \"sum/1024\" MB\"}"; \
    echo "=== CPU Summary ==="; \
    ps aux | grep -E "(agentsight|node)" | awk "{sum+=\$3} END {print \"Total CPU: \"sum\"%\"}"'
```

### Correlate Events with Resources
```bash
# Log resources when events occur
tail -f agentsight.log | while read line; do
    if echo "$line" | grep -q "SSL_write\|SSL_read"; then
        timestamp=$(date +%s)
        pid=$(echo "$line" | grep -oP '"pid":\K\d+')
        if [ ! -z "$pid" ]; then
            cpu=$(ps -p $pid -o pcpu= 2>/dev/null)
            mem=$(ps -p $pid -o rss= 2>/dev/null)
            echo "$timestamp,$pid,$cpu,$mem" >> resource_events.csv
        fi
    fi
done
```

## Scripts

Two monitoring scripts are available in this directory:
- `monitor-memory.sh`: Tracks memory usage for process and children
- `monitor-cpu.sh`: Tracks CPU usage for process and children

Both scripts support:
- Real-time monitoring
- CSV export
- Process tree analysis
- Threshold alerts

Usage:
```bash
# Monitor memory
./monitor-memory.sh -p PID -i 2 -o memory.csv

# Monitor CPU
./monitor-cpu.sh -p PID -i 2 -o cpu.csv

# Monitor by name
./monitor-memory.sh -n "node" -i 5

# With thresholds
./monitor-cpu.sh -p PID -t 80 -a
```