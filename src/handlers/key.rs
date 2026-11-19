use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use std::collections::HashSet;
use uuid::Uuid;

use crate::{
    auth::{
        generate_key_pair, parse_scopes_str, scopes_to_sorted_vec, AuthContext, Scope,
    },
    db::record_audit_log,
    error::AppError,
    models::{ApiKeyRow, AuthMeResponse, CreateKeyRequest, CreateKeyResponse, KeyListItem},
    AppState,
};

pub async fn auth_me(auth: AuthContext) -> Json<AuthMeResponse> {
    Json(AuthMeResponse {
        key_id: auth.key_id,
        access_key_id: auth.access_key_id,
        name: auth.name,
        scopes: scopes_to_sorted_vec(&auth.scopes),
    })
}

pub async fn list_keys(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<KeyListItem>>, AppError> {
    auth.require(Scope::Admin)?;

    let rows: Vec<ApiKeyRow> = sqlx::query_as(
        r#"
        SELECT id, access_key_id, secret_hash, name, scopes, is_active, created_at, last_used_at
        FROM api_keys
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let items = rows
        .into_iter()
        .map(|r| {
            let scopes = scopes_to_sorted_vec(&parse_scopes_str(&r.scopes));
            KeyListItem {
                id: r.id,
                access_key_id: r.access_key_id,
                name: r.name,
                scopes,
                is_active: r.is_active != 0,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
            }
        })
        .collect();

    Ok(Json(items))
}

pub async fn create_key(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), AppError> {
    auth.require(Scope::Admin)?;

    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("Key name cannot be empty".to_string()));
    }
    if req.scopes.is_empty() {
        return Err(AppError::BadRequest(
            "At least one scope (read, write, admin) is required".to_string(),
        ));
    }

    let mut parsed_scopes = HashSet::new();
    for raw_scope in &req.scopes {
        parsed_scopes.insert(Scope::parse(raw_scope)?);
    }
    let scope_list = scopes_to_sorted_vec(&parsed_scopes);
    let scopes_str = scope_list.join(",");

    let id = Uuid::new_v4().to_string();
    let (ak, sk, secret_hash) = generate_key_pair();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO api_keys (id, access_key_id, secret_hash, name, scopes, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
        "#,
    )
    .bind(&id)
    .bind(&ak)
    .bind(&secret_hash)
    .bind(name)
    .bind(&scopes_str)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    record_audit_log(
        &state.pool,
        Some(&auth.key_id),
        Some(&auth.name),
        "key.create",
        "api_key",
        Some(&id),
        Some(&format!("name={}, scopes={}", name, scopes_str)),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            id,
            access_key_id: ak,
            access_key_secret: sk,
            name: name.to_string(),
            scopes: scope_list,
            created_at: now,
        }),
    ))
}

pub async fn revoke_key(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require(Scope::Admin)?;

    if id == auth.key_id {
        return Err(AppError::BadRequest(
            "Cannot revoke the currently authenticated API key".to_string(),
        ));
    }

    let result = sqlx::query("UPDATE api_keys SET is_active = 0 WHERE id = ? AND is_active = 1")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        let exists: Option<(String,)> =
            sqlx::query_as("SELECT id FROM api_keys WHERE id = ?")
                .bind(&id)
                .fetch_optional(&state.pool)
                .await?;
        if exists.is_none() {
            return Err(AppError::NotFound(format!("API key '{}' not found", id)));
        }
    }

    record_audit_log(
        &state.pool,
        Some(&auth.key_id),
        Some(&auth.name),
        "key.revoke",
        "api_key",
        Some(&id),
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
