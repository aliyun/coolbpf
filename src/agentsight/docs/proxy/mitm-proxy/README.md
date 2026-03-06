# OpenAI MITM Proxy POC

TLS-intercepting proxy for unmodified OpenAI clients with domain allowlisting.

## ⚠️ Important Security Warnings

- **USE ONLY WHERE YOU CONTROL DEVICES** - requires installing CA certificate on client devices
- **Allowlist strictly** - only intercept intended domains, tunnel everything else
- **Legal compliance** - decrypting traffic has legal/privacy implications
- **Certificate pinning** - some apps will fail (can't be fixed centrally)

## Features

- **Transparent interception** - works with unmodified clients
- **Domain allowlisting** - only intercepts `api.openai.com` by default, tunnels rest
- **CA management** - generates and exports CA certificate automatically
- **Shared analysis pipeline** - identical `AnalysisMsg` types as reverse-proxy
- **CONNECT tunnel support** - standard HTTP proxy protocol

## Quick Start

```bash
# Build
cargo build --release

# Run (generates agentsight-mitm-ca.crt)
cargo run

# Install CA certificate on client devices
# Linux: copy to /usr/local/share/ca-certificates/ and run update-ca-certificates
# macOS: add to Keychain with "Always Trust"
# Windows: certutil -addstore -f "ROOT" agentsight-mitm-ca.crt
```

## Usage Example

```bash
# Configure system/app to use HTTP proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Or in Python
import openai
import os
os.environ['HTTP_PROXY'] = 'http://localhost:8080'
os.environ['HTTPS_PROXY'] = 'http://localhost:8080'

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}]
)
```

## Configuration

Environment variables:

- `LISTEN_ADDR` - Proxy listen address (default: `0.0.0.0:8080`)
- `ALLOWLIST_HOSTS` - Comma-separated domains to intercept (default: `api.openai.com,files.openai.com`)

## Architecture

```
Client (unmodified)
  │ HTTPS with system proxy setting
  ↓
MITM Proxy
  ├─ Allowlisted (api.openai.com):
  │   ├─ Accept CONNECT
  │   ├─ Start TLS with fake cert (signed by our CA)
  │   ├─ Decrypt request/response
  │   ├─ Tee to analysis
  │   └─ Re-encrypt and forward
  │
  └─ Not allowlisted:
      └─ Transparent tunnel (no interception)
```

## How It Works

1. **CONNECT request**: Client sends `CONNECT api.openai.com:443`
2. **Domain check**: Proxy checks if `api.openai.com` is in allowlist
3. **If allowlisted**:
   - Generate fake certificate for `api.openai.com` signed by our CA
   - Accept TLS handshake with client using fake cert
   - Connect to real `api.openai.com` with real TLS
   - Decrypt client → proxy, encrypt proxy → server
   - Tee decrypted data to analysis pipeline
4. **If not allowlisted**:
   - Simple TCP tunnel (no decryption)

## Limitations

- **HTTP/3/QUIC**: Not supported, clients will fallback to HTTP/2 or HTTP/1.1
- **Certificate pinning**: Apps that pin certs will fail
- **Performance**: Extra TLS handshakes add latency
- **Compliance**: You are legally responsible for decrypted data

## CA Certificate Installation

### Linux (Ubuntu/Debian)
```bash
sudo cp agentsight-mitm-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### macOS
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain agentsight-mitm-ca.crt
```

### Windows (as Administrator)
```powershell
certutil -addstore -f "ROOT" agentsight-mitm-ca.crt
```

## Integration with AgentSight

This POC demonstrates the MITM pattern for integration:

```rust
// Future integration point
let mitm_runner = MitmProxyRunner::builder()
    .listen_addr("0.0.0.0:8080")
    .allowlist(vec!["api.openai.com", "files.openai.com"])
    .ca_cert_path("mitm-ca.crt")
    .add_analyzer(HttpParser::new())
    .add_analyzer(ChunkMerger::new())
    .add_analyzer(FileLogger::new("mitm-traffic.log"))
    .build();

mitm_runner.run().await?;
```

## Comparison with Reverse Proxy Approach

**Advantages:**
- ✅ Works with unmodified applications
- ✅ No code changes needed
- ✅ Can monitor third-party tools

**Disadvantages:**
- ❌ Requires CA installation on every device
- ❌ Certificate pinning breaks some apps
- ❌ Higher latency (double TLS)
- ❌ Legal/compliance concerns
- ❌ Can't handle HTTP/3/QUIC

**Use this when:**
- You cannot modify application code
- You control all client devices (can install CA)
- You need to monitor third-party tools
- You understand the security/legal implications

## Recommended Approach

**Default to reverse-proxy**. Only use MITM when:
1. You physically control the devices
2. You cannot modify the application
3. You have explicit consent/policy
4. You accept the operational complexity

The reverse-proxy approach (see `../reverse-proxy/`) is simpler, safer, and faster for the majority of use cases.
