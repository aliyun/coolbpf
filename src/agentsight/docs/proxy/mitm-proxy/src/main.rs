// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use bytes::Bytes;
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{Body, Request, Response},
    HttpContext, HttpHandler, ProxyBuilder, RequestOrResponse,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};
use uuid::Uuid;

// Analysis message types (matching reverse-proxy for unified pipeline)
#[derive(Clone, Debug)]
struct RequestMeta {
    id: Uuid,
    tenant: String,
    endpoint: String,
    model: Option<String>,
    stream: bool,
}

enum AnalysisMsg {
    Request(RequestMeta, serde_json::Value),
    StreamChunk(Uuid, Bytes),
    ResponseDone {
        id: Uuid,
        status: u16,
        usage: Option<serde_json::Value>,
    },
}

// Custom HTTP handler that analyzes traffic
#[derive(Clone)]
struct AnalysisHandler {
    allowlist: Arc<HashSet<String>>,
    sink: mpsc::UnboundedSender<AnalysisMsg>,
}

#[async_trait]
impl HttpHandler for AnalysisHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let host = req
            .uri()
            .host()
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|h| h.split(':').next())
            })
            .unwrap_or("unknown");

        // Check allowlist
        if !self.allowlist.contains(host) {
            info!("🚫 Tunneling (not allowlisted): {}", host);
            return RequestOrResponse::Request(req);
        }

        info!("🔍 Intercepting: {} {}", req.method(), req.uri());

        let id = Uuid::new_v4();
        let endpoint = req.uri().path().to_string();

        // For simplicity, just log the request metadata without reading body
        // In production, you would need to stream/buffer the body carefully
        let meta = RequestMeta {
            id,
            tenant: format!("mitm-{}", host),
            endpoint: endpoint.clone(),
            model: None,  // Would need body parsing
            stream: false,
        };

        let _ = self.sink.send(AnalysisMsg::Request(meta, serde_json::Value::Null));

        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        // For simplicity, we'll just forward the response
        // In production, you'd tee the response body to analysis
        res
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()?;

    // Initialize allowlist
    let allowlist_env = std::env::var("ALLOWLIST_HOSTS")
        .unwrap_or_else(|_| "api.openai.com,files.openai.com".to_string());
    let allowlist: HashSet<String> = allowlist_env
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    info!("📋 Allowlist: {:?}", allowlist);

    let (tx, mut rx) = mpsc::unbounded_channel();

    // Analysis worker (identical to reverse-proxy)
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                AnalysisMsg::Request(meta, _json) => {
                    info!(
                        "📥 Request {} - tenant:{} endpoint:{} model:{:?} stream:{}",
                        meta.id, meta.tenant, meta.endpoint, meta.model, meta.stream
                    );
                }
                AnalysisMsg::StreamChunk(id, chunk) => {
                    info!("📦 Stream chunk {} - {} bytes", id, chunk.len());
                }
                AnalysisMsg::ResponseDone { id, status, usage } => {
                    info!(
                        "✅ Response done {} - status:{} usage:{:?}",
                        id, status, usage
                    );
                }
            }
        }
    });

    // Generate CA certificate - RcgenAuthority::new takes private_key, ca_cert, cache_size
    // We need to generate them first using rcgen
    let mut ca_params = rcgen::CertificateParams::new(vec![])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "AgentSight MITM Root CA");
    ca_params.distinguished_name.push(rcgen::DnType::OrganizationName, "AgentSight");

    let ca_key_pair = rcgen::KeyPair::generate()?;
    let ca_cert_rcgen = ca_params.self_signed(&ca_key_pair)?;

    // Convert to rustls types
    let ca_key_der = ca_key_pair.serialized_der();
    let ca_cert_der = ca_cert_rcgen.der();

    let private_key = hudsucker::rustls::PrivateKey(ca_key_der.to_vec());
    let ca_cert_rustls = hudsucker::rustls::Certificate(ca_cert_der.to_vec());

    let ca = RcgenAuthority::new(private_key, ca_cert_rustls, 1024)?;

    // Export CA certificate
    tokio::fs::write("agentsight-mitm-ca.crt", ca_cert_rcgen.pem()).await?;
    info!("📜 CA certificate exported to agentsight-mitm-ca.crt");
    info!("   Install this certificate on client devices to enable MITM");

    // Create handler
    let handler = AnalysisHandler {
        allowlist: Arc::new(allowlist),
        sink: tx,
    };

    // Build and start proxy
    let proxy = ProxyBuilder::new()
        .with_addr(addr)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(handler)
        .build();

    info!("🚀 MITM proxy listening on {}", addr);
    info!("   Configure clients to use HTTP proxy: {}", addr);
    info!("   Press Ctrl+C to stop");

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("Proxy error: {}", e);
    }

    Ok(())
}
