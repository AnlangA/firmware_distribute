pub mod audit;
pub mod download;
pub mod file;
pub mod key;
pub mod project;

use axum::{
    extract::{DefaultBodyLimit, Path},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use rust_embed::Embed;
use serde::Serialize;

use crate::AppState;

#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn serve_index() -> Response {
    serve_static_path("index.html")
}

async fn serve_asset(Path(path): Path<String>) -> Response {
    let trimmed = path.trim_start_matches('/');
    serve_static_path(trimmed)
}

fn serve_static_path(rel_path: &str) -> Response {
    match StaticAssets::get(rel_path) {
        Some(content) => {
            let mime = mime_guess::from_path(rel_path).first_or_octet_stream();
            let mut resp = (StatusCode::OK, content.data.into_owned()).into_response();
            if let Ok(val) = HeaderValue::from_str(mime.as_ref()) {
                resp.headers_mut().insert(header::CONTENT_TYPE, val);
            }
            resp
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub fn build_api_router(state: AppState) -> Router {
    let max_body = usize::try_from(state.max_upload_bytes).unwrap_or(usize::MAX);

    let upload_route = Router::new()
        .route("/api/v1/files", post(file::upload_files))
        .layer(DefaultBodyLimit::max(max_body));

    Router::new()
        .route("/", get(serve_index))
        .route("/assets/{*path}", get(serve_asset))
        .route("/healthz", get(healthz))
        .route("/api/v1/auth/me", get(key::auth_me))
        .route("/api/v1/projects", get(project::list_projects))
        .route("/api/v1/files", get(file::list_files))
        .route("/api/v1/files/latest", get(file::get_latest_file))
        .route(
            "/api/v1/files/{id}",
            get(file::get_file).delete(file::delete_file),
        )
        .route("/api/v1/files/{id}/download", get(download::download_file))
        .route("/api/v1/keys", get(key::list_keys).post(key::create_key))
        .route("/api/v1/keys/{id}", delete(key::revoke_key))
        .route("/api/v1/audit-logs", get(audit::list_audit_logs))
        .merge(upload_route)
        .with_state(state)
}
