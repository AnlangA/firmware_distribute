use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use sqlx::QueryBuilder;

use crate::{
    auth::{AuthContext, Scope},
    error::AppError,
    models::{AuditLogItem, AuditLogListResponse},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct ListAuditLogsQuery {
    pub action: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_audit_logs(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(query): Query<ListAuditLogsQuery>,
) -> Result<Json<AuditLogListResponse>, AppError> {
    auth.require(Scope::Admin)?;

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);

    let mut count_qb = QueryBuilder::<sqlx::Sqlite>::new("SELECT COUNT(*) FROM audit_logs");
    let mut data_qb = QueryBuilder::<sqlx::Sqlite>::new(
        r#"
        SELECT id, actor_key_id, actor_name, action, target_type, target_id, detail, created_at
        FROM audit_logs
        "#,
    );

    if let Some(action) = query
        .action
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        count_qb.push(" WHERE action = ");
        count_qb.push_bind(action.to_string());
        data_qb.push(" WHERE action = ");
        data_qb.push_bind(action.to_string());
    }

    let (total,): (i64,) = count_qb.build_query_as().fetch_one(&state.pool).await?;

    data_qb.push(" ORDER BY id DESC LIMIT ");
    data_qb.push_bind(limit);
    data_qb.push(" OFFSET ");
    data_qb.push_bind(offset);

    let items: Vec<AuditLogItem> = data_qb.build_query_as().fetch_all(&state.pool).await?;

    Ok(Json(AuditLogListResponse {
        items,
        total,
        limit,
        offset,
    }))
}
