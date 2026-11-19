pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod models;
pub mod storage;

use axum::{extract::FromRef, Router};
use sqlx::SqlitePool;
use std::path::PathBuf;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub data_dir: PathBuf,
    pub max_upload_bytes: u64,
}

impl FromRef<AppState> for SqlitePool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

pub fn build_router(state: AppState) -> Router {
    handlers::build_api_router(state).layer(TraceLayer::new_for_http())
}
