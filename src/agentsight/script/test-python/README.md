# AgentSight Testing

This directory contains test scripts for validating AgentSight's SSL/TLS traffic monitoring capabilities.

## Setup

### 1. Create Virtual Environment

```bash
cd test
bash setup_venv.sh
```

This will create a Python virtual environment and install required dependencies (openai, python-dotenv).

### 2. Configure API Key

Create a `.env` file in the `test/` directory:

```bash
cd test
cat > .env << EOF
OPENAI_API_KEY=your-api-key-here
OPENAI_MODEL=gpt-4o-mini
EOF
```

Replace `your-api-key-here` with your actual OpenAI API key.

## Running Tests

### Test OpenAI API Traffic Monitoring

This test verifies that AgentSight can capture OpenAI API traffic at the SSL/TLS layer.

```bash
# From the agentsight root directory
timeout 30 sudo ./bpf/sslsniff -c python 2>&1 &
SNIFFER_PID=$!
sleep 2
./test/venv/bin/python ./test/test_openai.py
sleep 3
sudo kill -INT $SNIFFER_PID 2>/dev/null || true
```

**Expected Output:**

The sslsniff program should capture:
- HTTP POST request to `/v1/chat/completions`
- Authorization headers
- Request body with chat messages
- HTTP response with OpenAI headers
- Gzip-compressed response data

All events will be output as JSON with metadata including:
- `timestamp_ns`: Nanoseconds since boot
- `comm`: Process name (python)
- `pid`: Process ID
- `latency_ms`: Operation latency
- `data`: Captured SSL/TLS data

### Using the Rust Collector

For a more user-friendly experience with the web UI:

```bash
# From the collector directory
cd collector
cargo run record -- --comm python --server-port 7395 &
COLLECTOR_PID=$!

# Run the test
../test/venv/bin/python ../test/test_openai.py

# View results in browser at http://localhost:7395
# Press Ctrl+C to stop the collector
```

## Test Scripts

### `test_openai.py`

Sends a simple chat completion request to the OpenAI API. The script:
1. Loads API credentials from `.env`
2. Creates an OpenAI client
3. Sends a chat completion request
4. Prints the response

This generates SSL/TLS traffic that AgentSight captures at the system level.

## Troubleshooting

### Virtual Environment Issues

If packages aren't found, recreate the virtual environment:

```bash
cd test
rm -rf venv
bash setup_venv.sh
```

### SSL Sniffer Not Capturing Traffic

1. Ensure the sniffer is running **before** starting the Python script
2. Verify you're using `sudo` (eBPF requires root privileges)
3. Check that the process name filter matches (`-c python` or `-c python3`)
4. Ensure the bpf binaries are built: `cd bpf && make build`

### Permission Denied

eBPF programs require root privileges:
```bash
sudo ./bpf/sslsniff -c python
```

### OpenAI API Errors

- Verify your API key is valid in `.env`
- Check your OpenAI account has available credits
- Ensure the model name is correct (default: `gpt-5-nano`)

## Quick Start (Automated)

```bash
# Run complete test with automatic decoding
cd /home/yunwei37/workspace/agentsight
sudo ./script/test-python/run_test.sh
```

This automated script:
1. Starts sslsniff and captures to `/tmp/agentsight_capture_*.json`
2. Runs the OpenAI test
3. Decodes captured traffic including gzip decompression
4. Shows the AI assistant's response

## Test Results

### ✅ Bug Fix Verified

**Before fix** (line 288 in `bpf/sslsniff.bpf.c`):
- All events showed as `WRITE/SEND`

**After fix**:
- `WRITE/SEND` - Outgoing data (HTTP requests)
- `READ/RECV` - Incoming data (HTTP responses)

### Captured Events Example

```
Event #1: WRITE/SEND (676 bytes)
  Type: HTTP Request
  - POST /v1/chat/completions HTTP/1.1
  - Authorization: Bearer sk-proj-... [visible API key!]
  - All request headers

Event #2: WRITE/SEND (120 bytes)
  Type: Request Body (JSON)
  - {"messages":[...],"model":"gpt-5-nano",...}

Event #3: READ/RECV (1369 bytes)
  Type: HTTP Response Headers + Partial Gzip Data
  - HTTP/1.1 200 OK
  - Content-Encoding: gzip
  - Transfer-Encoding: chunked
  - Chunk size: 0x183 (387 bytes)
  - First ~21 bytes of gzipped response

Event #4: READ/RECV (373 bytes)
  Type: Continuation of Gzip Data
  - Remaining ~373 bytes of compressed response

Event #5: READ/RECV (5 bytes)
  Type: Chunked Transfer End Marker
  - "0\r\n\r\n"
```

### Why Response is Split Across Multiple Events

The gzip-compressed response is **split across Events #3 and #4** because:
1. Python's OpenSSL makes multiple `SSL_read()` calls
2. Each `SSL_read()` triggers a separate eBPF event
3. The first read gets headers + partial body
4. Subsequent reads get the rest of the data

**Total gzip data**: 387 bytes (`0x183` from chunk size)
- Event #3 body: ~21 bytes after headers
- Event #4 data: ~373 bytes
- Combined: Full compressed response

## Design Solution: Multi-Event Stream Reassembly

### Problem Statement

Current challenges:
1. **Data Fragmentation**: HTTP responses split across multiple `SSL_read()` events
2. **Chunked Encoding**: Need to parse chunk sizes and reassemble chunks
3. **Compression**: Gzip data cannot be decompressed until fully reassembled
4. **Stateless Events**: Each eBPF event is independent with no connection context

### Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ eBPF Layer (Kernel Space)                                       │
│  - Capture SSL_read/SSL_write events                            │
│  - Add connection tracking (socket FD + PID + TID)              │
│  - Add sequence numbers per connection                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ↓ JSON events with metadata
┌─────────────────────────────────────────────────────────────────┐
│ Stream Reassembly Layer (Userspace)                             │
│  - Group events by connection (FD, PID, direction)              │
│  - Maintain connection state machines                           │
│  - Buffer incomplete data chunks                                │
│  - Detect HTTP boundaries (headers, chunked encoding)           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ↓ Complete HTTP transactions
┌─────────────────────────────────────────────────────────────────┐
│ Protocol Analysis Layer                                         │
│  - HTTP/1.1 chunked transfer decoding                           │
│  - Content-Encoding decompression (gzip, deflate, br)           │
│  - JSON parsing and validation                                  │
│  - API-specific extraction (OpenAI, Anthropic, etc.)            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ↓ Structured API data
┌─────────────────────────────────────────────────────────────────┐
│ Output Layer                                                    │
│  - Decoded requests and responses                               │
│  - AI assistant messages extracted                              │
│  - Timeline visualization                                       │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation Plan

#### Phase 1: eBPF Connection Tracking

**Add to `sslsniff.bpf.c`**:
```c
struct connection_key {
    u32 pid;
    u32 tid;
    u64 fd;        // File descriptor for socket
    u32 direction; // 0=read, 1=write
};

struct connection_state {
    u64 seq_num;   // Sequence number for ordering
    u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct connection_key);
    __type(value, struct connection_state);
} conn_state SEC(".maps");
```

**Capture socket FD**:
- Use `SSL_get_fd()` or trace socket operations
- Add `fd` field to `probe_SSL_data_t`
- Add `seq_num` for ordering events

#### Phase 2: Userspace Stream Reassembly

**New Rust module: `collector/src/framework/analyzers/stream_reassembly.rs`**:

```rust
use std::collections::HashMap;

#[derive(Hash, Eq, PartialEq, Clone)]
struct ConnectionId {
    pid: u32,
    tid: u32,
    fd: u64,
    direction: Direction,
}

#[derive(Clone, Copy)]
enum Direction {
    Read,
    Write,
}

struct StreamBuffer {
    seq_num: u64,
    chunks: Vec<(u64, Vec<u8>)>, // (seq_num, data)
    expected_next_seq: u64,
    protocol_state: ProtocolState,
}

enum ProtocolState {
    ReadingHeaders,
    ReadingChunkedBody { remaining_chunk_size: usize },
    ReadingFixedBody { remaining_bytes: usize },
    Complete,
}

struct StreamReassembler {
    streams: HashMap<ConnectionId, StreamBuffer>,
}

impl StreamReassembler {
    fn on_event(&mut self, event: SSLEvent) -> Option<CompleteHTTPTransaction> {
        let conn_id = ConnectionId::from_event(&event);
        let stream = self.streams.entry(conn_id).or_insert_with(StreamBuffer::new);

        // Add data chunk with sequence number
        stream.chunks.push((event.seq_num, event.data));
        stream.chunks.sort_by_key(|(seq, _)| *seq);

        // Try to reassemble contiguous data
        let reassembled = self.try_reassemble(stream)?;

        // Parse HTTP protocol
        self.parse_http(reassembled)
    }

    fn try_reassemble(&self, stream: &StreamBuffer) -> Option<Vec<u8>> {
        let mut result = Vec::new();
        let mut next_seq = stream.expected_next_seq;

        for (seq, data) in &stream.chunks {
            if *seq == next_seq {
                result.extend_from_slice(data);
                next_seq += data.len() as u64;
            } else if *seq > next_seq {
                // Gap in sequence - wait for missing data
                return None;
            }
        }

        Some(result)
    }

    fn parse_http(&mut self, data: Vec<u8>) -> Option<CompleteHTTPTransaction> {
        // Parse HTTP headers
        let (headers, body_start) = parse_http_headers(&data)?;

        // Handle Transfer-Encoding: chunked
        if headers.get("transfer-encoding") == Some(&"chunked") {
            return self.parse_chunked_body(&data[body_start..], headers);
        }

        // Handle Content-Length
        if let Some(content_length) = headers.get("content-length") {
            let length: usize = content_length.parse().ok()?;
            if data[body_start..].len() >= length {
                return Some(CompleteHTTPTransaction {
                    headers,
                    body: data[body_start..body_start + length].to_vec(),
                });
            }
        }

        None
    }

    fn parse_chunked_body(
        &self,
        data: &[u8],
        headers: HashMap<String, String>,
    ) -> Option<CompleteHTTPTransaction> {
        let mut body = Vec::new();
        let mut pos = 0;

        loop {
            // Read chunk size line
            let line_end = find_crlf(&data[pos..])?;
            let chunk_size_str = std::str::from_utf8(&data[pos..pos + line_end]).ok()?;
            let chunk_size = usize::from_str_radix(chunk_size_str.trim(), 16).ok()?;
            pos += line_end + 2; // Skip CRLF

            if chunk_size == 0 {
                // End of chunks
                break;
            }

            // Read chunk data
            if data.len() < pos + chunk_size + 2 {
                return None; // Incomplete chunk
            }
            body.extend_from_slice(&data[pos..pos + chunk_size]);
            pos += chunk_size + 2; // Skip chunk data and trailing CRLF
        }

        Some(CompleteHTTPTransaction { headers, body })
    }
}

struct CompleteHTTPTransaction {
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl CompleteHTTPTransaction {
    fn decompress(&self) -> Result<Vec<u8>, Error> {
        match self.headers.get("content-encoding") {
            Some(encoding) if encoding == "gzip" => {
                Ok(decompress_gzip(&self.body)?)
            }
            Some(encoding) if encoding == "deflate" => {
                Ok(decompress_deflate(&self.body)?)
            }
            Some(encoding) if encoding == "br" => {
                Ok(decompress_brotli(&self.body)?)
            }
            _ => Ok(self.body.clone()),
        }
    }
}
```

#### Phase 3: HTTP Protocol Parser

**New module: `collector/src/framework/analyzers/http_protocol.rs`**:

```rust
struct HTTPParser;

impl HTTPParser {
    fn parse_headers(data: &[u8]) -> Option<(HashMap<String, String>, usize)> {
        let header_end = find_double_crlf(data)?;
        let headers_str = std::str::from_utf8(&data[..header_end]).ok()?;

        let mut headers = HashMap::new();
        for line in headers_str.lines().skip(1) { // Skip status/request line
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(
                    key.trim().to_lowercase(),
                    value.trim().to_string(),
                );
            }
        }

        Some((headers, header_end + 4)) // +4 for \r\n\r\n
    }
}
```

#### Phase 4: Content Decompression

**Dependencies in `Cargo.toml`**:
```toml
[dependencies]
flate2 = "1.0"      # gzip, deflate
brotli = "3.3"      # brotli compression
```

**Implementation**:
```rust
use flate2::read::GzDecoder;
use std::io::Read;

fn decompress_gzip(compressed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = GzDecoder::new(compressed);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}
```

#### Phase 5: Integration with Existing Framework

**Update `collector/src/framework/analyzers/mod.rs`**:
```rust
pub mod stream_reassembly;
pub mod http_protocol;

pub use stream_reassembly::StreamReassembler;
```

**Usage in pipeline**:
```rust
let reassembler = StreamReassembler::new();

SSLRunner::new()
    .add_analyzer(reassembler)
    .add_analyzer(HttpFilter::new())
    .add_analyzer(OutputAnalyzer::new())
    .run()
    .await?;
```

### Benefits

1. **Complete HTTP Transactions**: Reassemble fragmented responses
2. **Automatic Decompression**: Handle gzip, deflate, brotli
3. **Protocol Awareness**: Parse chunked encoding correctly
4. **Stateful Analysis**: Track connections and maintain context
5. **API Extraction**: Easily extract AI messages from complete responses

### Alternative: Simplified Approach

If full connection tracking is too complex, implement a **simpler heuristic-based reassembly**:

1. **Buffer recent events** (last 10 events per PID)
2. **Detect HTTP response start** (begins with `HTTP/1.1`)
3. **Parse Content-Length or Transfer-Encoding** from headers
4. **Accumulate subsequent events** until size matched
5. **Decompress and emit** complete transaction

This avoids socket FD tracking but works for most cases.

## Files

- **run_test.sh** - Automated test with capture and decode
- **test_openai.py** - OpenAI API test script
- **decode_capture.py** - JSON event analyzer with gzip decompression
- **requirements.txt** - Python dependencies
- **setup_venv.sh** - Virtual environment setup script
- `.env` - API credentials (create this file, not tracked in git)
- `.gitignore` - Excludes venv and .env from version control
