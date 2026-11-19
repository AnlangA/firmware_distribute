use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use sqlx::QueryBuilder;

use crate::{
    auth::{AuthContext, Scope},
    error::AppError,
    models::ProjectSummary,
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct ListProjectsQuery {
    pub q: Option<String>,
}

pub async fn list_projects(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(query): Query<ListProjectsQuery>,
) -> Result<Json<Vec<ProjectSummary>>, AppError> {
    auth.require(Scope::Read)?;

    let mut qb = QueryBuilder::<sqlx::Sqlite>::new(
        r#"
        SELECT
            p.id,
            p.name,
            p.slug,
            CASE WHEN p.is_public != 0 THEN 1 ELSE 0 END AS is_public,
            COUNT(f.id) AS file_count,
            COALESCE(SUM(f.file_size), 0) AS total_size,
            p.created_at,
            p.updated_at
        FROM projects p
        LEFT JOIN files f ON f.project_id = p.id
        "#,
    );

    if let Some(q) = query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let pattern = format!("%{}%", q);
        qb.push(" WHERE (p.name LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR p.slug LIKE ");
        qb.push_bind(pattern);
        qb.push(")");
    }

    qb.push(" GROUP BY p.id ORDER BY p.is_public DESC, p.updated_at DESC, p.name ASC");

    #[derive(sqlx::FromRow)]
    struct Row {
        id: String,
        name: String,
        slug: String,
        is_public: i64,
        file_count: i64,
        total_size: i64,
        created_at: String,
        updated_at: String,
    }

    let rows: Vec<Row> = qb.build_query_as().fetch_all(&state.pool).await?;
    let summaries = rows
        .into_iter()
        .map(|r| ProjectSummary {
            id: r.id,
            name: r.name,
            slug: r.slug,
            is_public: r.is_public != 0,
            file_count: r.file_count,
            total_size: r.total_size,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect();

    Ok(Json(summaries))
}
