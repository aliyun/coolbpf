// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use axum::{
    Router, body::Body, extract::{Request, State}, http::{StatusCode, header::{AUTHORIZATION, CONTENT_TYPE}}, response::Response,
};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, StreamBody};
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::info;
use uuid::Uuid;

// Analysis message types
#[derive(Clone, Debug)]
struct RequestMeta {
    id: Uuid,
    tenant: String,
    endpoint: String,
    model: Option<String>,
    stream: bool,
}

enum AnalysisMsg {
    Request(RequestMeta, Value),
    StreamChunk(Uuid, Bytes),
    ResponseDone { id: Uuid, status: u16, usage: Option<Value> },
}

// App state
#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    upstream: String,
    sink: mpsc::UnboundedSender<AnalysisMsg>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let upstream = std::env::var("UPSTREAM").unwrap_or_else(|_| "https://api.openai.com".to_string());
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    let (tx, mut rx) = mpsc::unbounded_channel();

    // Analysis worker
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                AnalysisMsg::Request(meta, _json) => {
                    info!("📥 Request {} - tenant:{} endpoint:{} model:{:?} stream:{}",
                          meta.id, meta.tenant, meta.endpoint, meta.model, meta.stream);
                }
                AnalysisMsg::StreamChunk(id, chunk) => {
                    info!("📦 Stream chunk {} - {} bytes", id, chunk.len());
                }
                AnalysisMsg::ResponseDone { id, status, usage } => {
                    info!("✅ Response done {} - status:{} usage:{:?}", id, status, usage);
                }
            }
        }
    });

    let state = AppState {
        client: reqwest::Client::new(),
        upstream,
        sink: tx,
    };

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!("🚀 Reverse proxy listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn proxy_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let id = Uuid::new_v4();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();

    // Extract tenant from Authorization header or use default
    let tenant = req.headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default".to_string());

    // Read body once
    let body_bytes = req.into_body()
        .collect()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        .to_bytes();

    // Parse metadata from JSON body
    let (model, stream, json_val) = if !body_bytes.is_empty() {
        match serde_json::from_slice::<Value>(&body_bytes) {
            Ok(json) => {
                let model = json.get("model").and_then(|v| v.as_str()).map(String::from);
                let stream = json.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
                (model, stream, json)
            }
            Err(_) => (None, false, Value::Null)
        }
    } else {
        (None, false, Value::Null)
    };

    let meta = RequestMeta {
        id,
        tenant: tenant.clone(),
        endpoint: path.clone(),
        model,
        stream,
    };

    let _ = state.sink.send(AnalysisMsg::Request(meta, json_val));

    // Forward to upstream
    let url = format!("{}{}{}", state.upstream, path, query);

    let upstream_resp = state.client
        .request(method, &url)
        .header(AUTHORIZATION, tenant)
        .header(CONTENT_TYPE, "application/json")
        .body(body_bytes.to_vec())
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let status = upstream_resp.status();
    let headers = upstream_resp.headers().clone();
    let is_stream = headers.get(CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.starts_with("text/event-stream"))
        .unwrap_or(false);

    if is_stream {
        // Stream response with tee to analysis
        let id_clone = id;
        let sink = state.sink.clone();

        let stream = upstream_resp.bytes_stream().map(move |chunk_result| {
            match chunk_result {
                Ok(chunk) => {
                    let _ = sink.send(AnalysisMsg::StreamChunk(id_clone, chunk.clone()));
                    Ok(hyper::body::Frame::data(chunk))
                }
                Err(e) => Err(e),
            }
        });

        let body = StreamBody::new(stream);
        let mut resp = Response::new(Body::new(body));
        *resp.status_mut() = status;

        // Copy essential headers
        for (k, v) in headers.iter() {
            if k == CONTENT_TYPE || k == "cache-control" {
                resp.headers_mut().insert(k, v.clone());
            }
        }

        Ok(resp)
    } else {
        // Buffer non-stream response
        let body_bytes = upstream_resp.bytes()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

        let usage = if let Ok(json) = serde_json::from_slice::<Value>(&body_bytes) {
            json.get("usage").cloned()
        } else {
            None
        };

        let _ = state.sink.send(AnalysisMsg::ResponseDone {
            id,
            status: status.as_u16(),
            usage,
        });

        let mut resp = Response::new(Body::from(body_bytes));
        *resp.status_mut() = status;

        for (k, v) in headers.iter() {
            resp.headers_mut().insert(k, v.clone());
        }

        Ok(resp)
    }
}
