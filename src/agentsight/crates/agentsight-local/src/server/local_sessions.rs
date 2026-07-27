//! Local agent session discovery and ATIF conversion handlers
//!
//! These endpoints scan well-known directories on the local machine for agent
//! session files (Claude Code, Qoder, QoderWork, Codex, Cursor) and convert
//! them to ATIF format for trajectory display. They work without eBPF and
//! without a populated SQLite database — pure filesystem scanning.

use actix_web::{HttpResponse, Responder, get, web};
use serde::Deserialize;

use crate::collector::{LocalSessionsResponse, convert_jsonl_to_atif, discover_local_sessions};

/// List all discovered local agent session files.
#[get("/api/local-sessions")]
pub async fn list_local_sessions() -> impl Responder {
    let sessions = web::block(discover_local_sessions).await;

    match sessions {
        Ok(sessions) => {
            let total = sessions.len();
            let scanned_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let response = LocalSessionsResponse {
                sessions,
                total,
                scanned_at,
            };
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            log::error!("Failed to discover local sessions: {}", e);
            HttpResponse::InternalServerError().body(format!("Discovery failed: {}", e))
        }
    }
}

/// Query parameters for ATIF conversion
#[derive(Deserialize)]
pub struct AtifQuery {
    /// Absolute path to the JSONL session file
    pub path: String,
}

/// Convert a local JSONL session file to an ATIF document.
///
/// Query parameter: `path` — absolute path to the `.jsonl` file
#[get("/api/local-session/atif")]
pub async fn convert_local_to_atif(query: web::Query<AtifQuery>) -> impl Responder {
    let path = query.path.clone();

    if !is_safe_jsonl_path(&path) {
        return HttpResponse::BadRequest().body("Invalid file path: must be a .jsonl file");
    }

    let path_for_log = path.clone();
    let result = web::block(move || convert_jsonl_to_atif(std::path::Path::new(&path))).await;

    match result {
        Ok(Ok(doc)) => HttpResponse::Ok().json(doc),
        Ok(Err(e)) => {
            log::error!("Failed to convert {} to ATIF: {}", path_for_log, e);
            HttpResponse::InternalServerError().body(format!("Conversion failed: {}", e))
        }
        Err(e) => {
            log::error!("Thread pool error converting {}: {}", path_for_log, e);
            HttpResponse::InternalServerError().body(format!("Internal error: {}", e))
        }
    }
}

/// Query parameters for file reading
#[derive(Deserialize)]
pub struct FileQuery {
    /// Absolute path to the JSONL session file
    pub path: String,
}

/// Read the raw content of a local session file.
///
/// Query parameter: `path` — absolute path to the `.jsonl` file
#[get("/api/local-session/file")]
pub async fn read_local_session_file(query: web::Query<FileQuery>) -> impl Responder {
    let path = query.path.as_str();

    if !is_safe_jsonl_path(path) {
        return HttpResponse::BadRequest()
            .body("Invalid file path: must be a .jsonl or .json file");
    }

    match std::fs::read_to_string(path) {
        Ok(content) => HttpResponse::Ok()
            .content_type("application/jsonl; charset=utf-8")
            .body(content),
        Err(e) => {
            log::error!("Failed to read {}: {}", path, e);
            HttpResponse::NotFound().body(format!("File not found: {}", e))
        }
    }
}

/// Validate that the path points to a .jsonl or .json file.
fn is_safe_jsonl_path(path: &str) -> bool {
    let p = std::path::Path::new(path);
    p.extension()
        .is_some_and(|ext| ext == "jsonl" || ext == "json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_jsonl_path_valid() {
        assert!(is_safe_jsonl_path("/tmp/session.jsonl"));
        assert!(is_safe_jsonl_path("/home/user/data.json"));
        assert!(is_safe_jsonl_path("relative/path.jsonl"));
    }

    #[test]
    fn test_is_safe_jsonl_path_invalid() {
        assert!(!is_safe_jsonl_path("/tmp/session.txt"));
        assert!(!is_safe_jsonl_path("/tmp/session.csv"));
        assert!(!is_safe_jsonl_path("/tmp/noext"));
        assert!(!is_safe_jsonl_path("/tmp/session"));
        assert!(!is_safe_jsonl_path(""));
    }

    #[actix_web::test]
    async fn test_list_local_sessions_endpoint() {
        let app =
            actix_web::test::init_service(actix_web::App::new().service(list_local_sessions)).await;
        let req = actix_web::test::TestRequest::get()
            .uri("/api/local-sessions")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_convert_local_to_atif_bad_path() {
        let app =
            actix_web::test::init_service(actix_web::App::new().service(convert_local_to_atif))
                .await;
        let req = actix_web::test::TestRequest::get()
            .uri("/api/local-session/atif?path=/tmp/notjson.txt")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_convert_local_to_atif_valid_path() {
        let tmp = std::env::temp_dir().join("agentsight_atif_test.jsonl");
        std::fs::write(
            &tmp,
            r#"{"type":"user","message":{"content":[{"type":"text","text":"hello"}]}}"#,
        )
        .unwrap();
        let app =
            actix_web::test::init_service(actix_web::App::new().service(convert_local_to_atif))
                .await;
        let uri = format!("/api/local-session/atif?path={}", tmp.to_string_lossy());
        let req = actix_web::test::TestRequest::get().uri(&uri).to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let _ = std::fs::remove_file(&tmp);
    }

    #[actix_web::test]
    async fn test_read_local_session_file_not_found() {
        let app =
            actix_web::test::init_service(actix_web::App::new().service(read_local_session_file))
                .await;
        let req = actix_web::test::TestRequest::get()
            .uri("/api/local-session/file?path=/tmp/nonexistent_file.jsonl")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn test_read_local_session_file_valid() {
        let tmp = std::env::temp_dir().join("agentsight_read_test.jsonl");
        std::fs::write(&tmp, r#"{"type":"user","message":"hi"}"#).unwrap();
        let app =
            actix_web::test::init_service(actix_web::App::new().service(read_local_session_file))
                .await;
        let uri = format!("/api/local-session/file?path={}", tmp.to_string_lossy());
        let req = actix_web::test::TestRequest::get().uri(&uri).to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let _ = std::fs::remove_file(&tmp);
    }

    #[actix_web::test]
    async fn test_read_local_session_file_bad_ext() {
        let app =
            actix_web::test::init_service(actix_web::App::new().service(read_local_session_file))
                .await;
        let req = actix_web::test::TestRequest::get()
            .uri("/api/local-session/file?path=/tmp/file.exe")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }
}
