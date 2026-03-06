# Memory Monitoring for Processes and Subprocesses

This guide provides various methods to check memory usage for a process and all its subprocesses/children.

## Quick Commands

### 1. Using `ps` with Process Tree
```bash
# Show process tree with memory sorted by RSS (Resident Set Size)
ps auxf --sort=-rss | head -20

# For a specific process and its children
ps aux --forest | grep processname
```

### 2. For a Specific Process and All Children
```bash
# Get process tree memory for a PID
pstree -p PID | grep -oP '\d+' | xargs ps -o pid,comm,rss,vsz -p

# Sum RSS for parent and all children
ps --ppid PARENT_PID -o rss= | awk '{sum+=$1} END {print sum " KB"}'
```

### 3. Using `/proc` Filesystem
```bash
# Check RSS for a specific PID
cat /proc/PID/status | grep VmRSS

# Check detailed memory maps
cat /proc/PID/smaps_rollup
```

### 4. Using `pmap` for Detailed Memory
```bash
# Show memory mapping for a process
sudo pmap -x PID

# Summary only
sudo pmap -x PID | tail -1
```

## Advanced Methods

### 5. Bash Function to Calculate Total Memory for Process Tree
```bash
get_process_tree_memory() {
    local pid=$1
    local total=0

    # Get memory for the parent process
    parent_mem=$(ps -o rss= -p $pid 2>/dev/null || echo 0)
    total=$((total + parent_mem))

    # Get all child PIDs recursively
    for p in $(pgrep -P $pid); do
        child_mem=$(ps -o rss= -p $p 2>/dev/null || echo 0)
        total=$((total + child_mem))
        # Recursive call for grandchildren
        subtotal=$(get_process_tree_memory $p)
        total=$((total + subtotal))
    done

    echo $total
}

# Usage
get_process_tree_memory PID
```

### 6. Using `smem` for Proportional Set Size (PSS)
```bash
# Install if needed
sudo apt install smem

# Show memory with totals for a process name
smem -t -P processname

# Show process tree with PSS
smem -t --tree
```

### 7. Using `systemd-cgtop` for Cgroups
```bash
# Monitor memory usage per service/cgroup
systemd-cgtop -m

# For specific service
systemctl status servicename | grep Memory
```

### 8. One-liner to Get Total RSS for Process and Children
```bash
# For a specific PID and all its descendants
ps -eo pid,ppid,rss --no-headers | awk -v pid=PID '
function get_children(p) {
    for (i in ppid) if (ppid[i] == p) {
        total += rss[i];
        get_children(i);
    }
}
BEGIN { total = 0 }
{ ppid[$1] = $2; rss[$1] = $3 }
END { total = rss[pid]; get_children(pid); print total " KB" }'
```

## Memory Metrics Explained

- **RSS (Resident Set Size)**: Physical memory currently used by the process
- **VSZ (Virtual Size)**: Virtual memory allocated (includes swapped out memory)
- **PSS (Proportional Set Size)**: RSS divided among processes sharing the same memory
- **USS (Unique Set Size)**: Memory unique to a process (not shared)

## Practical Examples

### Monitor Node.js Application with Children
```bash
# Find Node.js process
NODE_PID=$(pgrep -f "node.*app.js")

# Show tree with memory
ps auxf | grep -A10 -B2 $NODE_PID

# Calculate total memory
ps --ppid $NODE_PID -o rss= | awk '{sum+=$1} END {print "Children: " sum " KB"}'
ps -o rss= -p $NODE_PID | awk '{print "Parent: " $1 " KB"}'
```

### Monitor Python Application with Workers
```bash
# For a Python app with multiple workers
pgrep -f "python.*main.py" | while read pid; do
    echo "PID $pid: $(ps -o rss= -p $pid) KB"
    children=$(pgrep -P $pid | wc -l)
    echo "  Children: $children"
    if [ $children -gt 0 ]; then
        child_mem=$(pgrep -P $pid | xargs ps -o rss= -p | awk '{sum+=$1} END {print sum}')
        echo "  Children memory: $child_mem KB"
    fi
done
```

### Real-time Monitoring
```bash
# Watch memory usage every 2 seconds
watch -n 2 'ps aux --forest | grep -E "(processname|PID)" | head -20'

# Using top with tree view
top -H -p PID

# Using htop (if installed)
htop -t -p PID
```

## Integration with AgentSight

When monitoring AI agents with AgentSight, you can track memory usage alongside SSL/TLS traffic:

```bash
# Start AgentSight monitoring
sudo ./agentsight trace --ssl --process --comm node &

# In another terminal, monitor memory
while true; do
    NODE_PID=$(pgrep -f "node.*agent")
    if [ ! -z "$NODE_PID" ]; then
        echo "$(date): PID $NODE_PID - $(ps -o rss= -p $NODE_PID) KB"
    fi
    sleep 5
done
```

This helps correlate memory spikes with specific AI agent activities captured by AgentSight.