use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use sqlx::{QueryBuilder, SqlitePool};
use uuid::Uuid;

use crate::{
    auth::{AuthContext, Scope},
    db::record_audit_log,
    error::AppError,
    models::{
        FileItem, FileListResponse, FileWithProjectRow, ProjectRow, UploadResponse,
    },
    storage::{
        compute_project_slug, extract_extension, finalize_temp_file, infer_file_type,
        remove_file_dir, sanitize_filename, stream_field_to_temp, validate_project_name,
        TempUploadFile,
    },
    AppState,
};

struct PendingUpload {
    file_name: String,
    temp: TempUploadFile,
}

async fn cleanup_pending(pending: &[PendingUpload]) {
    for item in pending {
        let _ = tokio::fs::remove_file(&item.temp.temp_path).await;
    }
}

pub async fn upload_files(
    auth: AuthContext,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), AppError> {
    auth.require(Scope::Write)?;

    let mut raw_project: Option<String> = None;
    let mut raw_file_type: Option<String> = None;
    let mut raw_version: Option<String> = None;
    let mut raw_summary: Option<String> = None;
    let mut raw_tags: Option<String> = None;
    let mut pending_files: Vec<PendingUpload> = Vec::new();

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(err) => {
                cleanup_pending(&pending_files).await;
                return Err(AppError::BadRequest(format!(
                    "Invalid multipart request: {}",
                    err
                )));
            }
        };

        let field_name = field.name().unwrap_or("").to_string();
        let maybe_filename = field.file_name().map(|s| s.to_string());

        if let Some(raw_fname) = maybe_filename {
            let safe_name = match sanitize_filename(&raw_fname) {
                Ok(n) => n,
                Err(err) => {
                    cleanup_pending(&pending_files).await;
                    return Err(err);
                }
            };

            match stream_field_to_temp(field, &state.data_dir, state.max_upload_bytes).await {
                Ok(temp) => {
                    pending_files.push(PendingUpload {
                        file_name: safe_name,
                        temp,
                    });
                }
                Err(err) => {
                    cleanup_pending(&pending_files).await;
                    return Err(err);
                }
            }
        } else {
            let text_val = match field.text().await {
                Ok(t) => t,
                Err(err) => {
                    cleanup_pending(&pending_files).await;
                    return Err(AppError::BadRequest(format!(
                        "Failed to read text field '{}': {}",
                        field_name, err
                    )));
                }
            };

            match field_name.as_str() {
                "project" => raw_project = Some(text_val),
                "file_type" => raw_file_type = Some(text_val),
                "version" => raw_version = Some(text_val),
                "summary" => raw_summary = Some(text_val),
                "tags" => raw_tags = Some(text_val),
                _ => {}
            }
        }
    }

    if pending_files.is_empty() {
        return Err(AppError::BadRequest(
            "At least one file field is required".to_string(),
        ));
    }

    let project_name = match validate_project_name(raw_project.as_deref().unwrap_or("")) {
        Ok(n) => n,
        Err(err) => {
            cleanup_pending(&pending_files).await;
            return Err(err);
        }
    };

    let explicit_file_type = raw_file_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());

    if let Some(ref ft) = explicit_file_type {
        if !matches!(ft.as_str(), "firmware" | "doc" | "config" | "other") {
            cleanup_pending(&pending_files).await;
            return Err(AppError::BadRequest(format!(
                "Invalid file_type '{}'; allowed: firmware, doc, config, other",
                ft
            )));
        }
    }

    let version = raw_version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let summary = raw_summary
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let tags = raw_tags
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|s| !s.is_empty());

    let project = match get_or_create_project(&state.pool, &project_name).await {
        Ok(p) => p,
        Err(err) => {
            cleanup_pending(&pending_files).await;
            return Err(err);
        }
    };

    let batch_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let mut created_items = Vec::with_capacity(pending_files.len());

    for item in pending_files {
        let file_id = Uuid::new_v4().to_string();
        let rel_path = finalize_temp_file(
            &item.temp.temp_path,
            &state.data_dir,
            &project.slug,
            &file_id,
            &item.file_name,
        )
        .await?;

        let ext = extract_extension(&item.file_name);
        let file_type = explicit_file_type
            .clone()
            .unwrap_or_else(|| infer_file_type(&ext).to_string());

        sqlx::query(
            r#"
            INSERT INTO files (
                id, project_id, file_name, file_type, extension, version, summary, tags,
                sha256, file_size, file_path, batch_id, uploaded_by_key_id, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&file_id)
        .bind(&project.id)
        .bind(&item.file_name)
        .bind(&file_type)
        .bind(&ext)
        .bind(&version)
        .bind(&summary)
        .bind(&tags)
        .bind(&item.temp.sha256)
        .bind(item.temp.size as i64)
        .bind(&rel_path)
        .bind(&batch_id)
        .bind(&auth.key_id)
        .bind(&now)
        .execute(&state.pool)
        .await?;

        let row = FileWithProjectRow {
            id: file_id,
            project_id: project.id.clone(),
            project_name: project.name.clone(),
            project_slug: project.slug.clone(),
            file_name: item.file_name,
            file_type,
            extension: ext,
            version: version.clone(),
            summary: summary.clone(),
            tags: tags.clone(),
            sha256: item.temp.sha256,
            file_size: item.temp.size as i64,
            file_path: rel_path,
            batch_id: batch_id.clone(),
            uploaded_by_key_id: Some(auth.key_id.clone()),
            created_at: now.clone(),
        };
        created_items.push(FileItem::from(row));
    }

    sqlx::query("UPDATE projects SET updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&project.id)
        .execute(&state.pool)
        .await?;

    let file_names: Vec<&str> = created_items.iter().map(|f| f.file_name.as_str()).collect();
    record_audit_log(
        &state.pool,
        Some(&auth.key_id),
        Some(&auth.name),
        "file.upload",
        "batch",
        Some(&batch_id),
        Some(&format!(
            "project={}, files=[{}]",
            project.name,
            file_names.join(", ")
        )),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(UploadResponse {
            batch_id,
            project,
            files: created_items,
        }),
    ))
}

async fn get_or_create_project(
    pool: &SqlitePool,
    project_name: &str,
) -> Result<ProjectRow, AppError> {
    if let Some(existing) = sqlx::query_as::<_, ProjectRow>(
        "SELECT id, name, slug, is_public, created_at, updated_at FROM projects WHERE name = ?",
    )
    .bind(project_name)
    .fetch_optional(pool)
    .await?
    {
        return Ok(existing);
    }

    let mut slug = compute_project_slug(project_name, false);
    let slug_conflict: Option<(String,)> =
        sqlx::query_as("SELECT id FROM projects WHERE slug = ?")
            .bind(&slug)
            .fetch_optional(pool)
            .await?;

    if slug_conflict.is_some() {
        slug = compute_project_slug(project_name, true);
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let is_public = if project_name == "public" { 1 } else { 0 };

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO projects (id, name, slug, is_public, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(project_name)
    .bind(&slug)
    .bind(is_public)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    let row = sqlx::query_as::<_, ProjectRow>(
        "SELECT id, name, slug, is_public, created_at, updated_at FROM projects WHERE name = ?",
    )
    .bind(project_name)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

#[derive(Debug, Deserialize)]
pub struct ListFilesQuery {
    pub project: Option<String>,
    pub file_type: Option<String>,
    pub ext: Option<String>,
    pub q: Option<String>,
    pub version: Option<String>,
    pub sort: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_files(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(query): Query<ListFilesQuery>,
) -> Result<Json<FileListResponse>, AppError> {
    auth.require(Scope::Read)?;

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);

    let mut count_qb = QueryBuilder::<sqlx::Sqlite>::new(
        r#"
        SELECT COUNT(*)
        FROM files f
        JOIN projects p ON f.project_id = p.id
        WHERE 1=1
        "#,
    );

    let mut data_qb = QueryBuilder::<sqlx::Sqlite>::new(
        r#"
        SELECT
            f.id, f.project_id, p.name AS project_name, p.slug AS project_slug,
            f.file_name, f.file_type, f.extension, f.version, f.summary, f.tags,
            f.sha256, f.file_size, f.file_path, f.batch_id, f.uploaded_by_key_id, f.created_at
        FROM files f
        JOIN projects p ON f.project_id = p.id
        WHERE 1=1
        "#,
    );

    if let Some(proj) = query.project.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        count_qb.push(" AND (p.slug = ");
        count_qb.push_bind(proj.to_string());
        count_qb.push(" OR p.name = ");
        count_qb.push_bind(proj.to_string());
        count_qb.push(")");

        data_qb.push(" AND (p.slug = ");
        data_qb.push_bind(proj.to_string());
        data_qb.push(" OR p.name = ");
        data_qb.push_bind(proj.to_string());
        data_qb.push(")");
    }

    if let Some(ft) = query.file_type.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let ft_lower = ft.to_ascii_lowercase();
        count_qb.push(" AND f.file_type = ");
        count_qb.push_bind(ft_lower.clone());
        data_qb.push(" AND f.file_type = ");
        data_qb.push_bind(ft_lower);
    }

    if let Some(ext) = query.ext.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let normalized_ext = if ext.starts_with('.') {
            ext.to_ascii_lowercase()
        } else {
            format!(".{}", ext.to_ascii_lowercase())
        };
        count_qb.push(" AND f.extension = ");
        count_qb.push_bind(normalized_ext.clone());
        data_qb.push(" AND f.extension = ");
        data_qb.push_bind(normalized_ext);
    }

    if let Some(ver) = query.version.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        count_qb.push(" AND f.version = ");
        count_qb.push_bind(ver.to_string());
        data_qb.push(" AND f.version = ");
        data_qb.push_bind(ver.to_string());
    }

    if let Some(q) = query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let pattern = format!("%{}%", q);
        for qb in [&mut count_qb, &mut data_qb] {
            qb.push(" AND (f.file_name LIKE ");
            qb.push_bind(pattern.clone());
            qb.push(" OR COALESCE(f.summary, '') LIKE ");
            qb.push_bind(pattern.clone());
            qb.push(" OR COALESCE(f.tags, '') LIKE ");
            qb.push_bind(pattern.clone());
            qb.push(" OR f.sha256 LIKE ");
            qb.push_bind(pattern.clone());
            qb.push(")");
        }
    }

    let (total,): (i64,) = count_qb.build_query_as().fetch_one(&state.pool).await?;

    let order_clause = match query.sort.as_deref().unwrap_or("created_at_desc") {
        "created_at_asc" => " ORDER BY f.created_at ASC, f.id ASC",
        "file_size_desc" => " ORDER BY f.file_size DESC, f.created_at DESC",
        "file_size_asc" => " ORDER BY f.file_size ASC, f.created_at DESC",
        "file_name_asc" => " ORDER BY f.file_name ASC, f.created_at DESC",
        _ => " ORDER BY f.created_at DESC, f.id DESC",
    };

    data_qb.push(order_clause);
    data_qb.push(" LIMIT ");
    data_qb.push_bind(limit);
    data_qb.push(" OFFSET ");
    data_qb.push_bind(offset);

    let rows: Vec<FileWithProjectRow> = data_qb.build_query_as().fetch_all(&state.pool).await?;
    let items = rows.into_iter().map(FileItem::from).collect();

    Ok(Json(FileListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

#[derive(Debug, Deserialize)]
pub struct LatestFileQuery {
    pub project: Option<String>,
    pub file_type: Option<String>,
    pub file_name: Option<String>,
}

pub async fn get_latest_file(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(query): Query<LatestFileQuery>,
) -> Result<Json<FileItem>, AppError> {
    auth.require(Scope::Read)?;

    let mut qb = QueryBuilder::<sqlx::Sqlite>::new(
        r#"
        SELECT
            f.id, f.project_id, p.name AS project_name, p.slug AS project_slug,
            f.file_name, f.file_type, f.extension, f.version, f.summary, f.tags,
            f.sha256, f.file_size, f.file_path, f.batch_id, f.uploaded_by_key_id, f.created_at
        FROM files f
        JOIN projects p ON f.project_id = p.id
        WHERE 1=1
        "#,
    );

    if let Some(proj) = query.project.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        qb.push(" AND (p.slug = ");
        qb.push_bind(proj.to_string());
        qb.push(" OR p.name = ");
        qb.push_bind(proj.to_string());
        qb.push(")");
    }

    if let Some(ft) = query.file_type.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        qb.push(" AND f.file_type = ");
        qb.push_bind(ft.to_ascii_lowercase());
    }

    if let Some(fname) = query.file_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        qb.push(" AND f.file_name = ");
        qb.push_bind(fname.to_string());
    }

    qb.push(" ORDER BY f.created_at DESC, f.id DESC LIMIT 1");

    let row: Option<FileWithProjectRow> = qb.build_query_as().fetch_optional(&state.pool).await?;
    let row = row.ok_or_else(|| AppError::NotFound("No matching file found".to_string()))?;

    Ok(Json(FileItem::from(row)))
}

pub async fn get_file(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<FileItem>, AppError> {
    auth.require(Scope::Read)?;

    let row: Option<FileWithProjectRow> = sqlx::query_as(
        r#"
        SELECT
            f.id, f.project_id, p.name AS project_name, p.slug AS project_slug,
            f.file_name, f.file_type, f.extension, f.version, f.summary, f.tags,
            f.sha256, f.file_size, f.file_path, f.batch_id, f.uploaded_by_key_id, f.created_at
        FROM files f
        JOIN projects p ON f.project_id = p.id
        WHERE f.id = ?
        "#,
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or_else(|| AppError::NotFound(format!("File '{}' not found", id)))?;
    Ok(Json(FileItem::from(row)))
}

pub async fn delete_file(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require_any(&[Scope::Write, Scope::Admin])?;

    #[derive(sqlx::FromRow)]
    struct DeleteTarget {
        file_name: String,
        file_path: String,
        project_id: String,
    }

    let target: Option<DeleteTarget> = sqlx::query_as(
        "SELECT file_name, file_path, project_id FROM files WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;

    let target = target.ok_or_else(|| AppError::NotFound(format!("File '{}' not found", id)))?;

    sqlx::query("DELETE FROM files WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    remove_file_dir(&state.data_dir, &target.file_path).await;

    record_audit_log(
        &state.pool,
        Some(&auth.key_id),
        Some(&auth.name),
        "file.delete",
        "file",
        Some(&id),
        Some(&format!(
            "file_name={}, project_id={}",
            target.file_name, target.project_id
        )),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
