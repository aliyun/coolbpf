# OpenAI Reverse Proxy POC

Axum-based reverse proxy for OpenAI API with streaming support and traffic analysis.

## Features

- **Zero-modification client integration** - just change `base_url`
- **SSE streaming support** - handles `text/event-stream` responses without buffering
- **Request/response analysis** - tees traffic to analysis pipeline
- **Tenant isolation** - extracts tenant from Authorization header
- **Model & usage tracking** - parses JSON bodies and usage metadata

## Quick Start

```bash
# Build
cargo build --release

# Run (default: listen on 0.0.0.0:3000, forward to api.openai.com)
OPENAI_API_KEY=sk-xxx cargo run

# Custom configuration
LISTEN_ADDR=0.0.0.0:8080 UPSTREAM=https://api.openai.com cargo run
```

## Usage Example

```bash
# Point your OpenAI client to the proxy
curl -N http://localhost:3000/v1/chat/completions \
  -H "Authorization: Bearer sk-xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello"}],
    "stream": true
  }'
```

## Configuration

Environment variables:

- `LISTEN_ADDR` - Proxy listen address (default: `0.0.0.0:3000`)
- `UPSTREAM` - OpenAI API URL (default: `https://api.openai.com`)

## Architecture

```
Client → Proxy (Axum) → OpenAI API
           │
           └─→ Analysis Worker (async)
```

The proxy:
1. Accepts requests on any path
2. Extracts metadata (tenant, model, stream flag) from request body
3. Forwards request to upstream OpenAI API
4. For streaming responses: pipes bytes immediately while teeing to analysis
5. For non-streaming: buffers response, extracts usage, forwards to client
6. Analysis worker processes events asynchronously without blocking

## Integration with AgentSight

This POC demonstrates the reverse-proxy pattern that can be integrated into AgentSight's collector framework:

```rust
// Future integration point
let reverse_runner = ReverseProxyRunner::builder()
    .listen_addr("0.0.0.0:3000")
    .upstream("https://api.openai.com")
    .add_analyzer(HttpParser::new())
    .add_analyzer(ChunkMerger::new())
    .add_analyzer(FileLogger::new("openai-proxy.log"))
    .build();

reverse_runner.run().await?;
```

## Comparison with MITM Approach

**Advantages:**
- ✅ No certificate management
- ✅ No device configuration needed
- ✅ No cert pinning issues
- ✅ Simple client integration (just change `base_url`)
- ✅ Lower latency (no TLS re-encryption)

**Use this when:**
- You control the application code
- You can modify the OpenAI SDK initialization
- You want the safest and fastest approach
