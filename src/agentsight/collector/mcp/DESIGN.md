# AgentSight MCP Server Design

## Overview

AgentSight MCP (Model Context Protocol) server exposes AgentSight's observability capabilities as MCP tools, enabling AI assistants to monitor, analyze, and debug AI agent behavior through SSL/TLS traffic interception and process monitoring.

## Motivation

Unlike schedcp which manages kernel schedulers, AgentSight MCP provides:

1. **Real-time Observability**: AI assistants can monitor running AI agents in real-time
2. **Debugging Assistance**: Help debug agent misbehavior by analyzing SSL traffic and system calls
3. **Performance Analysis**: Track agent performance metrics and identify bottlenecks
4. **Security Auditing**: Monitor agent network activity and detect anomalous behavior
5. **Integration Testing**: Observe agent interactions during development and testing

## Architecture

### Transport Layer

AgentSight MCP uses **HTTP Remote Server** architecture instead of stdio (unlike schedcp):

```
AI Assistant (Claude Desktop/API)
    ↓ (HTTP + Streamable HTTP / Legacy SSE)
AgentSight MCP HTTP Server (Port 3000)
    ├── /mcp (Streamable HTTP endpoint - Modern 2025-03-26)
    ├── GET /mcp (SSE endpoint - Legacy 2024-11-05)
    └── POST /messages (JSON-RPC - Legacy 2024-11-05)
    ↓ (Session Management)
AgentSight Framework
    ├── SSL Runner (sslsniff eBPF)
    ├── Process Runner (process eBPF)
    └── Analyzers (HTTP, SSE, Filters)
    ↓ (Events)
Storage & Analysis (DashMap)
```

**Why HTTP instead of stdio:**
- AgentSight needs persistent monitoring sessions (hours/days)
- Multiple clients can connect to same monitoring sessions
- Remote access from different machines
- Web dashboard integration via same endpoints
- Sessions survive client disconnects

**Transport Support:**
- **Streamable HTTP (2025-03-26)**: Single `/mcp` endpoint, modern protocol
- **HTTP+SSE (2024-11-05)**: Dual endpoints for backward compatibility
- Both supported for maximum client compatibility

### MCP Tools Design

Following schedcp's unified command pattern, AgentSight MCP exposes **3 simple tools**:

#### 1. monitor (Unified Monitoring Control)

Manage monitoring sessions with subcommands.

**Subcommands:**
- `start` - Start monitoring for a command or PID
  - `command`: command name (e.g., "python") OR
  - `pid`: process ID
  - `ssl`: enable SSL monitoring (default: true)
  - `process`: enable process monitoring (default: false)
  - Returns: `session_id`

- `stop` - Stop monitoring session
  - `session_id`: session to stop
  - Returns: Summary with event count

- `status` - Get session status
  - `session_id`: session to query
  - Returns: Active status, event count

- `list` - List all sessions
  - Returns: Session list with metadata

**Example:**
```json
{"command": "start", "command_name": "python", "ssl": true}
{"command": "stop", "session_id": "abc123"}
```

#### 2. events (Event Query & Search)

Query and search captured events with subcommands.

**Subcommands:**
- `query` - Query events with filters
  - `session_id`: monitoring session
  - `type`: "ssl" | "http" | "process" (optional, default: all)
  - `limit`: max events (default: 100)
  - Returns: Event list

- `search` - Search event content
  - `session_id`: monitoring session
  - `query`: search string
  - Returns: Matching events

- `timeline` - Get HTTP timeline
  - `session_id`: monitoring session
  - Returns: HTTP request/response timeline

**Example:**
```json
{"command": "query", "session_id": "abc123", "type": "http", "limit": 50}
{"command": "search", "session_id": "abc123", "query": "api.openai.com"}
```

#### 3. session (Session Management)

Manage session data and exports.

**Subcommands:**
- `export` - Export session data
  - `session_id`: session to export
  - `format`: "json" | "timeline" (default: "json")
  - Returns: Exported data

- `load` - Load saved session
  - `file_path`: path to session file
  - Returns: Session metadata

- `delete` - Delete session
  - `session_id`: session to delete
  - Returns: Confirmation

**Example:**
```json
{"command": "export", "session_id": "abc123", "format": "json"}
{"command": "load", "file_path": "/tmp/session.json"}
```

## Implementation Details

### Session Management

```rust
struct MonitoringSession {
    session_id: String,
    target: MonitorTarget,
    config: MonitorConfig,
    ssl_runner: Option<SslRunner>,
    process_runner: Option<ProcessRunner>,
    events: Arc<DashMap<String, Event>>,
    start_time: DateTime<Utc>,
    end_time: Option<DateTime<Utc>>,
    status: SessionStatus,
}

enum MonitorTarget {
    Command { name: String, binary_path: Option<String> },
    Pid(u32),
}

struct MonitorConfig {
    monitor_ssl: bool,
    monitor_process: bool,
    ssl_filters: Vec<String>,
    http_filters: Vec<String>,
    enable_http_parser: bool,
    remove_auth_headers: bool,
}
```

### Event Storage

- Use `DashMap` for concurrent event storage during monitoring
- Events keyed by UUID for fast lookup
- Support time-based indexing for range queries
- Optional persistence to disk for session replay

### Filter Integration

Leverage existing AgentSight analyzers:
- `SSLFilter` for SSL traffic filtering
- `HTTPFilter` for HTTP request/response filtering
- `AuthHeaderRemover` for security
- Custom analyzers for pattern detection

### Data Flow

```
1. MCP Tool Call (start_monitoring)
   ↓
2. Create MonitoringSession
   ↓
3. Start Runners with Config
   ↓
4. Events → Analyzer Chain → DashMap Storage
   ↓
5. MCP Tool Call (query_events)
   ↓
6. Filter & Return Events
   ↓
7. MCP Tool Call (stop_monitoring)
   ↓
8. Stop Runners, Generate Summary
```

## Use Cases

### 1. Debug Agent Stuck in Loop

```
AI: monitor(command="start", command_name="python", ssl=true)
    → session_id: abc123

AI: monitor(command="status", session_id="abc123")
    → Shows 1000+ events in 10 seconds

AI: events(command="query", session_id="abc123", type="http", limit=20)
    → Returns repeated calls to same endpoint with errors

AI: events(command="search", session_id="abc123", query="/api/chat")
    → Shows error loop pattern
```

### 2. Performance Analysis

```
AI: monitor(command="start", command_name="node", ssl=true)
    → session_id: def456

[Agent runs workload]

AI: events(command="timeline", session_id="def456")
    → Timeline shows sequential calls that could be parallel

AI: monitor(command="stop", session_id="def456")
    → Summary: 150 requests, avg latency 250ms
```

### 3. Session Export & Review

```
AI: monitor(command="list")
    → Shows previous session xyz789

AI: session(command="export", session_id="xyz789", format="json")
    → Returns full session data

AI: events(command="search", session_id="xyz789", query="error")
    → Finds all error events
```

## Comparison with schedcp

| Aspect | schedcp | agentsight-mcp |
|--------|---------|----------------|
| Domain | Kernel scheduler management | AI agent observability |
| Transport | stdio (local process) | HTTP/SSE/Streamable HTTP (remote server) |
| Data Source | Embedded scheduler binaries | eBPF programs (embedded) |
| Tool Count | 6 tools | 3 tools |
| Tool Pattern | list_schedulers, run_scheduler, stop_scheduler, get_execution_status, workload, system_monitor | monitor, events, session |
| State Management | Execution tracking (in-memory) | Session + event storage (DashMap, persistent) |
| Subcommands | workload: create/list/get_history/add_history, system_monitor: start/stop | monitor: start/stop/status/list, events: query/search/timeline, session: export/load/delete |
| Multi-client | No (stdio per client) | Yes (HTTP server, multiple clients) |
| Session Persistence | No | Yes (sessions survive client disconnects) |

## Technical Considerations

### 1. Performance
- Events stored in memory during active monitoring
- Configurable limits to prevent OOM
- Streaming export for large datasets
- Background cleanup of old sessions

### 2. Security
- Sensitive data filtering (auth headers)
- Sudo handling similar to schedcp
- Session isolation per user
- Encrypted storage option for sensitive sessions

### 3. Scalability
- Support concurrent monitoring sessions
- Handle high-throughput agents (1000s events/sec)
- Efficient filtering to reduce data volume
- Pagination for large query results

### 4. Reliability
- Graceful shutdown of runners
- Session recovery on crash
- Automatic cleanup of eBPF resources
- Error isolation per session

## File Structure

```
collector/mcp/
├── Cargo.toml
├── README.md
├── DESIGN.md (this file)
├── src/
│   ├── lib.rs                # Core MCP server logic and tool definitions
│   ├── main.rs               # HTTP server binary (hyper + streamable HTTP)
│   ├── cli.rs                # HTTP client CLI tool for testing
│   ├── transport/
│   │   ├── mod.rs
│   │   ├── streamable_http.rs  # Modern streamable HTTP handler
│   │   └── sse.rs              # Legacy SSE + POST /messages handler
│   ├── session_manager.rs    # Monitoring session management
│   ├── event_store.rs        # Event storage and querying (DashMap)
│   ├── tools/
│   │   ├── mod.rs
│   │   ├── monitor.rs        # monitor tool implementation
│   │   ├── events.rs         # events tool implementation
│   │   └── session.rs        # session tool implementation
│   └── auth.rs               # Optional: OAuth/token authentication
└── tests/
    ├── http_transport_test.rs
    ├── mcp_tools_test.rs
    └── session_test.rs
```

## Development Roadmap

### Phase 1: HTTP Transport Layer
- [ ] HTTP server with hyper (Streamable HTTP support)
- [ ] Legacy SSE + POST /messages endpoints
- [ ] JSON-RPC request/response handling
- [ ] Session management via HTTP headers
- [ ] Basic authentication (optional)

### Phase 2: Core Tools (3 Tools)
- [ ] `monitor` tool with start/stop/status/list subcommands
- [ ] `events` tool with query/search/timeline subcommands
- [ ] `session` tool with export/load/delete subcommands
- [ ] Session management with DashMap storage
- [ ] Integration with existing SslRunner/ProcessRunner

### Phase 3: Production Ready
- [ ] Resource limits and auto-cleanup
- [ ] Error handling and recovery
- [ ] HTTP client CLI tool for testing
- [ ] Documentation and deployment guide
- [ ] Docker containerization

## Example Usage

### Starting the Remote Server

```bash
# Start MCP HTTP server on port 3000
sudo AGENTSIGHT_SUDO_PASSWORD="your_password" ./agentsight-mcp --port 3000

# Or with environment variable
export AGENTSIGHT_SUDO_PASSWORD="your_password"
sudo ./agentsight-mcp --port 3000 --host 0.0.0.0

# Output:
# AgentSight MCP Server listening on http://0.0.0.0:3000
# Streamable HTTP endpoint: POST /mcp
# Legacy SSE endpoint: GET /mcp
# Legacy messages endpoint: POST /messages
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "agentsight": {
      "url": "http://localhost:3000/mcp",
      "transport": "streamable-http"
    }
  }
}
```

**For legacy SSE transport:**
```json
{
  "mcpServers": {
    "agentsight": {
      "url": "http://localhost:3000/mcp",
      "transport": "sse"
    }
  }
}
```

**For remote server:**
```json
{
  "mcpServers": {
    "agentsight": {
      "url": "https://agentsight.example.com/mcp",
      "transport": "streamable-http",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN"
      }
    }
  }
}
```

### CLI Testing (HTTP Client)

```bash
# Monitor commands (sends HTTP requests to server)
./agentsight-mcp-cli --url http://localhost:3000 monitor start --command python
./agentsight-mcp-cli --url http://localhost:3000 monitor status --session abc123
./agentsight-mcp-cli --url http://localhost:3000 monitor stop --session abc123
./agentsight-mcp-cli --url http://localhost:3000 monitor list

# Event commands
./agentsight-mcp-cli --url http://localhost:3000 events query --session abc123 --type http --limit 10
./agentsight-mcp-cli --url http://localhost:3000 events search --session abc123 --query "openai"
./agentsight-mcp-cli --url http://localhost:3000 events timeline --session abc123

# Session commands
./agentsight-mcp-cli --url http://localhost:3000 session export --session abc123 --format json
./agentsight-mcp-cli --url http://localhost:3000 session load --file session.json
./agentsight-mcp-cli --url http://localhost:3000 session delete --session abc123
```

### Direct HTTP Testing

```bash
# Test streamable HTTP endpoint
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "monitor",
      "arguments": {
        "command": "start",
        "command_name": "python",
        "ssl": true
      }
    }
  }'

# Test SSE endpoint (legacy)
curl -N http://localhost:3000/mcp

# Send message (legacy)
curl -X POST http://localhost:3000/messages \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list"
  }'
```
