# OpenAI Proxy POCs

Two separate Rust projects demonstrating different approaches to OpenAI API traffic interception and analysis.

## Projects

### 1. Reverse Proxy (`reverse-proxy/`)

**Recommended approach** for controlled environments where you can modify client code.

- **Port**: 3000 (default)
- **Method**: Axum HTTP reverse proxy
- **Client change**: Set `base_url = "http://localhost:3000/v1"`
- **Advantages**: No CA management, no cert pinning issues, low latency
- **Use when**: You control the application code

### 2. MITM Proxy (`mitm-proxy/`)

**Last resort** for unmodified clients where you control devices.

- **Port**: 8080 (default)
- **Method**: TLS interception with self-signed CA
- **Client change**: Set system proxy + install CA certificate
- **Advantages**: Works with unmodified apps
- **Disadvantages**: CA management, cert pinning breaks, legal/compliance concerns
- **Use when**: Cannot modify application, control devices, have explicit policy

## Unified Analysis Pipeline

Both projects share identical `AnalysisMsg` types:

```rust
enum AnalysisMsg {
    Request(RequestMeta, serde_json::Value),
    StreamChunk(Uuid, bytes::Bytes),
    ResponseDone { id: Uuid, status: u16, usage: Option<Value> },
}
```

This design allows **both ingress paths to feed the same analysis/policy/telemetry pipeline**, enabling:

- Shared metrics (token counts, costs, latency)
- Unified policy enforcement (rate limits, budgets)
- Common storage backend
- Consistent logging and observability

## Architecture Comparison

### Reverse Proxy Flow
```
Client (modified) → HTTP → Axum Proxy → HTTPS → OpenAI
                             ↓
                        Analysis Worker
```

### MITM Proxy Flow
```
Client (unmodified) → HTTPS+Proxy → MITM → Decrypt → Re-encrypt → OpenAI
                                      ↓
                                Analysis Worker
```

## Quick Start

### Reverse Proxy
```bash
cd reverse-proxy
cargo run --release

# In client code
client = OpenAI(base_url="http://localhost:3000/v1")
```

### MITM Proxy
```bash
cd mitm-proxy
cargo run --release

# Install agentsight-mitm-ca.crt on client device
export HTTPS_PROXY=http://localhost:8080

# No client code changes needed
client = OpenAI()  # uses system proxy
```

## Decision Matrix

| Factor | Reverse Proxy | MITM Proxy |
|--------|---------------|------------|
| Code changes | ✅ Yes (1 line) | ❌ No |
| Cert management | ✅ None | ❌ CA install |
| Cert pinning | ✅ No issues | ❌ Breaks apps |
| Latency | ✅ Low | ⚠️ Higher |
| Security | ✅ Simple | ⚠️ Complex |
| Legal compliance | ✅ Clear | ⚠️ Sensitive |
| HTTP/3 support | ✅ Yes | ❌ No |
| Integration | ✅ Easy | ⚠️ Complex |

## Production Deployment Pattern

The recommended production approach is to **ship both in one binary** with runtime mode selection:

```bash
# Mode 1: Reverse only (default, recommended)
./agentsight-proxy --mode reverse --port 3000

# Mode 2: MITM only (controlled devices)
./agentsight-proxy --mode mitm --port 8080 --allowlist api.openai.com

# Mode 3: Both (edge gateway)
./agentsight-proxy --mode both \
  --reverse-port 3000 \
  --mitm-port 8080 \
  --allowlist api.openai.com,files.openai.com
```

Both modes feed the **same analysis pipeline**, sharing:
- Policy engine (rate limits, budgets)
- Metrics (Prometheus)
- Telemetry (OpenTelemetry)
- Storage (request logs, usage)

## Integration with AgentSight

These POCs demonstrate patterns for integrating proxy capabilities into AgentSight's streaming framework:

```rust
// Potential integration
let proxy_runner = ProxyRunner::builder()
    .mode(ProxyMode::ReverseAndMitm)
    .reverse_addr("0.0.0.0:3000")
    .mitm_addr("0.0.0.0:8080")
    .mitm_allowlist(vec!["api.openai.com"])
    .add_analyzer(HttpParser::new())
    .add_analyzer(ChunkMerger::new())
    .add_analyzer(AuthHeaderRemover::new())
    .add_analyzer(FileLogger::new("proxy.log"))
    .add_analyzer(MetricsCollector::new())
    .build();

proxy_runner.run().await?;
```

## Testing

### Reverse Proxy Test
```bash
cd reverse-proxy
cargo test

# Manual test
cargo run &
curl -N http://localhost:3000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"test"}],"stream":true}'
```

### MITM Proxy Test
```bash
cd mitm-proxy
cargo test

# Manual test (after installing CA)
cargo run &
export HTTPS_PROXY=http://localhost:8080
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

## Security Best Practices

1. **Reverse Proxy**:
   - Sanitize Authorization headers in logs
   - Use virtual keys (map tenant → upstream key server-side)
   - Rate limit per tenant
   - Monitor for anomalous usage

2. **MITM Proxy**:
   - **Strict allowlist** - only intercept intended domains
   - **Minimize retention** - don't persist decrypted data longer than needed
   - **Audit logging** - track who/what was intercepted
   - **Access control** - restrict who can read intercepted data
   - **Policy compliance** - explicit consent, documented purpose

## Performance Characteristics

### Reverse Proxy
- **Latency**: +1-3ms (single HTTP hop)
- **Throughput**: ~10k req/s on 4-core
- **Memory**: ~50MB base + streaming buffers
- **Overhead**: <1% CPU during streaming

### MITM Proxy
- **Latency**: +10-30ms (double TLS handshake)
- **Throughput**: ~2k req/s on 4-core
- **Memory**: ~100MB base + TLS state
- **Overhead**: 5-10% CPU (TLS re-encryption)

## License

Both POCs are part of the AgentSight project and follow the same license.

## Recommendation

**Start with reverse-proxy**. It's simpler, faster, and safer. Only add MITM if you have a specific need to monitor unmodified applications and accept the operational complexity.

For AgentSight integration, the reverse-proxy pattern aligns better with the existing eBPF-based monitoring philosophy: observe at clean boundaries without requiring system-wide certificate trust modifications.
