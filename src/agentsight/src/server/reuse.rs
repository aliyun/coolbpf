//! Reuse-label endpoints (Linux).
//!
//! Thin wrappers: every decision — which trajectories to examine, what a label
//! means, which status code a failure warrants — lives in [`crate::reuse::api`]
//! so this file and its macOS counterpart cannot drift apart.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, Responder, get, post, web};

use super::AppState;
use crate::reuse::api::{self, ReuseApiError, SessionsQuery, TriageQuery};
use crate::reuse::triage::TriageConfig;

/// Renders a failure using the status and body the shared layer decided.
fn error_response(error: &ReuseApiError) -> HttpResponse {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    HttpResponse::build(status).json(error.body())
}

/// The label store, or the response explaining why labels are unavailable.
fn labels(data: &AppState) -> std::result::Result<&crate::reuse::ReuseStore, HttpResponse> {
    data.reuse_store.as_deref().ok_or_else(|| {
        error_response(&ReuseApiError::ReuseUnavailable(
            "reuse.db could not be opened; see the server log".to_string(),
        ))
    })
}

/// POST /api/reuse/triage
///
/// Labels collected trajectories and records the automatic verdicts. Safe to
/// call repeatedly: unchanged content under unchanged rules is skipped.
///
/// Thresholds come from the defaults for now; wiring them to the
/// `causal_labeling` feature flag arrives with the confirmation endpoints.
#[post("/reuse/triage")]
pub async fn run_triage(
    data: web::Data<AppState>,
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

/// GET /api/reuse/sessions
///
/// Lists label rows with the effective label already resolved.
#[get("/reuse/sessions")]
pub async fn list_sessions(
    data: web::Data<AppState>,
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
