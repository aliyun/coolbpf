//! Reuse-label endpoints (macOS local server).
//!
//! Mirrors `server::reuse` handler for handler. Both delegate to
//! [`crate::reuse::api`], which is where the behaviour actually lives — the
//! labels a macOS reader sees must be the labels a Linux reader sees.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, Responder, get, post, web};

use super::LocalState;
use crate::reuse::api::{self, ReuseApiError, SessionsQuery, TriageQuery};
use crate::reuse::triage::TriageConfig;

/// Renders a failure using the status and body the shared layer decided.
fn error_response(error: &ReuseApiError) -> HttpResponse {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    HttpResponse::build(status).json(error.body())
}

/// The label store, or the response explaining why labels are unavailable.
fn labels(data: &LocalState) -> std::result::Result<&crate::reuse::ReuseStore, HttpResponse> {
    data.reuse_store.as_deref().ok_or_else(|| {
        error_response(&ReuseApiError::ReuseUnavailable(
            "reuse.db could not be opened; see the server log".to_string(),
        ))
    })
}

/// POST /api/reuse/triage — see `server::reuse::run_triage`.
#[post("/reuse/triage")]
pub async fn run_triage(
    data: web::Data<LocalState>,
    query: web::Query<TriageQuery>,
) -> impl Responder {
    let store = match labels(&data) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match api::run_triage(
        data.trajectory_store().as_deref(),
        store,
        &query,
        &TriageConfig::default(),
    ) {
        Ok(report) => HttpResponse::Ok().json(report),
        Err(error) => {
            log::warn!("Reuse triage failed: {error}");
            error_response(&error)
        }
    }
}

/// GET /api/reuse/sessions — see `server::reuse::list_sessions`.
#[get("/reuse/sessions")]
pub async fn list_sessions(
    data: web::Data<LocalState>,
    query: web::Query<SessionsQuery>,
) -> impl Responder {
    let store = match labels(&data) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match api::list_sessions(store, &query) {
        Ok(sessions) => HttpResponse::Ok().json(serde_json::json!({
            "count": sessions.len(),
            "sessions": sessions,
        })),
        Err(error) => error_response(&error),
    }
}
