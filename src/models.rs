use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ProjectRow {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub is_public: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ProjectSummary {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub is_public: bool,
    pub file_count: i64,
    pub total_size: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct ApiKeyRow {
    pub id: String,
    pub access_key_id: String,
    pub secret_hash: String,
    pub name: String,
    pub scopes: String,
    pub is_active: i64,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyListItem {
    pub id: String,
    pub access_key_id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateKeyResponse {
    pub id: String,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthMeResponse {
    pub key_id: String,
    pub access_key_id: String,
    pub name: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct FileWithProjectRow {
    pub id: String,
    pub project_id: String,
    pub project_name: String,
    pub project_slug: String,
    pub file_name: String,
    pub file_type: String,
    pub extension: String,
    pub version: Option<String>,
    pub summary: Option<String>,
    pub tags: Option<String>,
    pub sha256: String,
    pub file_size: i64,
    pub file_path: String,
    pub batch_id: String,
    pub uploaded_by_key_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileItem {
    pub id: String,
    pub project_id: String,
    pub project_name: String,
    pub project_slug: String,
    pub file_name: String,
    pub file_type: String,
    pub extension: String,
    pub version: Option<String>,
    pub summary: Option<String>,
    pub tags: Vec<String>,
    pub sha256: String,
    pub file_size: i64,
    pub batch_id: String,
    pub uploaded_by_key_id: Option<String>,
    pub created_at: String,
    pub download_url: String,
}

impl From<FileWithProjectRow> for FileItem {
    fn from(row: FileWithProjectRow) -> Self {
        let tags = row
            .tags
            .as_deref()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let download_url = format!("/api/v1/files/{}/download", row.id);
        Self {
            id: row.id,
            project_id: row.project_id,
            project_name: row.project_name,
            project_slug: row.project_slug,
            file_name: row.file_name,
            file_type: row.file_type,
            extension: row.extension,
            version: row.version,
            summary: row.summary,
            tags,
            sha256: row.sha256,
            file_size: row.file_size,
            batch_id: row.batch_id,
            uploaded_by_key_id: row.uploaded_by_key_id,
            created_at: row.created_at,
            download_url,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileListResponse {
    pub items: Vec<FileItem>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadResponse {
    pub batch_id: String,
    pub project: ProjectRow,
    pub files: Vec<FileItem>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AuditLogItem {
    pub id: i64,
    pub actor_key_id: Option<String>,
    pub actor_name: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditLogListResponse {
    pub items: Vec<AuditLogItem>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}
