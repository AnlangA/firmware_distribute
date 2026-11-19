use axum::extract::multipart::Field;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::error::AppError;

pub async fn ensure_storage_dirs(data_dir: &Path) -> Result<(), String> {
    tokio::fs::create_dir_all(data_dir.join("tmp"))
        .await
        .map_err(|e| format!("Failed to create tmp storage dir: {}", e))?;
    tokio::fs::create_dir_all(data_dir.join("projects").join("public"))
        .await
        .map_err(|e| format!("Failed to create public project dir: {}", e))?;
    Ok(())
}

pub fn validate_project_name(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok("public".to_string());
    }

    if trimmed == "."
        || trimmed == ".."
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.chars().any(|c| c == '\0' || c.is_control())
    {
        return Err(AppError::BadRequest(format!(
            "Invalid project name '{}': path traversal or control characters are not allowed",
            trimmed
        )));
    }

    Ok(trimmed.to_string())
}

pub fn compute_project_slug(name: &str, force_hash_suffix: bool) -> String {
    if name == "public" {
        return "public".to_string();
    }

    let is_safe_ascii = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

    if is_safe_ascii && !force_hash_suffix {
        return name.to_ascii_lowercase();
    }

    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let digest_hex = hex::encode(hasher.finalize());

    let ascii_prefix: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(24)
        .collect::<String>()
        .to_ascii_lowercase()
        .trim_matches(|c| c == '-' || c == '_')
        .to_string();

    if ascii_prefix.is_empty() {
        format!("proj-{}", &digest_hex[..12])
    } else {
        format!("{}-{}", ascii_prefix, &digest_hex[..8])
    }
}

pub fn sanitize_filename(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Filename cannot be empty".to_string()));
    }

    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('\0') {
        return Err(AppError::BadRequest(format!(
            "Invalid filename '{}': path separators are not allowed",
            trimmed
        )));
    }

    if trimmed == "." || trimmed == ".." || trimmed.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest(format!(
            "Invalid filename '{}'",
            trimmed
        )));
    }

    Ok(trimmed.to_string())
}

pub fn extract_extension(file_name: &str) -> String {
    Path::new(file_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_ascii_lowercase()))
        .unwrap_or_default()
}

pub fn infer_file_type(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        ".bin" | ".hex" | ".elf" | ".img" | ".dfu" | ".fw" | ".uf2" | ".ota" => "firmware",
        ".md" | ".txt" | ".pdf" => "doc",
        ".json" | ".yaml" | ".yml" | ".toml" | ".ini" | ".conf" => "config",
        _ => "other",
    }
}

pub struct TempUploadFile {
    pub temp_path: PathBuf,
    pub sha256: String,
    pub size: u64,
}

pub async fn stream_field_to_temp(
    mut field: Field<'_>,
    data_dir: &Path,
    max_upload_bytes: u64,
) -> Result<TempUploadFile, AppError> {
    let tmp_dir = data_dir.join("tmp");
    tokio::fs::create_dir_all(&tmp_dir).await?;

    let temp_path = tmp_dir.join(format!("{}.part", Uuid::new_v4()));
    let mut file = tokio::fs::File::create(&temp_path).await?;
    let mut hasher = Sha256::new();
    let mut total_size: u64 = 0;

    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => {
                total_size = total_size.saturating_add(chunk.len() as u64);
                if total_size > max_upload_bytes {
                    drop(file);
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return Err(AppError::PayloadTooLarge(format!(
                        "File exceeds maximum allowed size of {} bytes",
                        max_upload_bytes
                    )));
                }
                hasher.update(&chunk);
                if let Err(err) = file.write_all(&chunk).await {
                    drop(file);
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return Err(AppError::Internal(format!(
                        "Failed to write temporary upload file: {}",
                        err
                    )));
                }
            }
            Ok(None) => break,
            Err(err) => {
                drop(file);
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(AppError::BadRequest(format!(
                    "Failed to read multipart upload chunk: {}",
                    err
                )));
            }
        }
    }

    if let Err(err) = file.flush().await {
        drop(file);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AppError::Internal(format!(
            "Failed to flush temporary upload file: {}",
            err
        )));
    }

    let sha256 = hex::encode(hasher.finalize());
    Ok(TempUploadFile {
        temp_path,
        sha256,
        size: total_size,
    })
}

pub async fn finalize_temp_file(
    temp_path: &Path,
    data_dir: &Path,
    project_slug: &str,
    file_id: &str,
    safe_file_name: &str,
) -> Result<String, AppError> {
    let dest_dir = data_dir.join("projects").join(project_slug).join(file_id);
    tokio::fs::create_dir_all(&dest_dir).await?;
    let dest_path = dest_dir.join(safe_file_name);

    if let Err(err) = tokio::fs::rename(temp_path, &dest_path).await {
        // Fallback if temp and dest are on different filesystems
        tokio::fs::copy(temp_path, &dest_path).await.map_err(|copy_err| {
            AppError::Internal(format!(
                "Failed to move file to storage ({} / {})",
                err, copy_err
            ))
        })?;
        let _ = tokio::fs::remove_file(temp_path).await;
    }

    Ok(format!(
        "projects/{}/{}/{}",
        project_slug, file_id, safe_file_name
    ))
}

pub async fn remove_file_dir(data_dir: &Path, relative_file_path: &str) {
    let full_path = data_dir.join(relative_file_path);
    if let Some(parent_dir) = full_path.parent() {
        if let Err(err) = tokio::fs::remove_dir_all(parent_dir).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    "Failed to remove file directory {}: {}",
                    parent_dir.display(),
                    err
                );
            }
        }
    }
}
