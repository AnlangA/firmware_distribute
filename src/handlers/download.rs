use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::{
    auth::{AuthContext, Scope},
    error::AppError,
    AppState,
};

pub async fn download_file(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    auth.require(Scope::Read)?;

    #[derive(sqlx::FromRow)]
    struct DownloadRow {
        file_name: String,
        file_path: String,
        sha256: String,
        file_size: i64,
    }

    let row: Option<DownloadRow> = sqlx::query_as(
        r#"
        SELECT file_name, file_path, sha256, file_size
        FROM files
        WHERE id = ?
        "#,
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or_else(|| AppError::NotFound(format!("File '{}' not found", id)))?;
    let full_path = state.data_dir.join(&row.file_path);

    let mut file = tokio::fs::File::open(&full_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound(format!("Stored file for '{}' is missing on disk", id))
        } else {
            AppError::Internal(format!("Failed to open file: {}", e))
        }
    })?;

    let metadata = file.metadata().await?;
    let total_size = metadata.len();
    let etag_value = format!("\"{}\"", row.sha256);

    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm.trim() == etag_value || inm.trim() == "*" {
            let mut resp = StatusCode::NOT_MODIFIED.into_response();
            resp.headers_mut().insert(
                header::ETAG,
                HeaderValue::from_str(&etag_value).unwrap_or_else(|_| HeaderValue::from_static("")),
            );
            return Ok(resp);
        }
    }

    let mime_type = mime_guess::from_path(&row.file_name)
        .first_or_octet_stream()
        .to_string();

    let safe_disp_name = row.file_name.replace('"', "_");
    let content_disposition = format!("attachment; filename=\"{}\"", safe_disp_name);

    if let Some(range_header) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        let (start, end) = parse_single_byte_range(range_header, total_size)?;
        let length = end - start + 1;

        file.seek(std::io::SeekFrom::Start(start)).await?;
        let limited = file.take(length);
        let stream = ReaderStream::new(limited);
        let body = Body::from_stream(stream);

        let mut resp = Response::new(body);
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        let h = resp.headers_mut();
        h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(&mime_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        );
        h.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string()).unwrap(),
        );
        h.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, total_size)).unwrap(),
        );
        h.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&content_disposition).unwrap(),
        );
        h.insert(header::ETAG, HeaderValue::from_str(&etag_value).unwrap());
        h.insert(
            header::HeaderName::from_static("x-file-sha256"),
            HeaderValue::from_str(&row.sha256).unwrap(),
        );
        return Ok(resp);
    }

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&row.file_size.max(0).to_string()).unwrap(),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition).unwrap(),
    );
    h.insert(header::ETAG, HeaderValue::from_str(&etag_value).unwrap());
    h.insert(
        header::HeaderName::from_static("x-file-sha256"),
        HeaderValue::from_str(&row.sha256).unwrap(),
    );

    Ok(resp)
}

fn parse_single_byte_range(header_val: &str, total_size: u64) -> Result<(u64, u64), AppError> {
    if total_size == 0 {
        return Err(AppError::RangeNotSatisfiable(0));
    }
    let spec = header_val
        .trim()
        .strip_prefix("bytes=")
        .ok_or_else(|| AppError::RangeNotSatisfiable(total_size))?;

    if spec.contains(',') {
        return Err(AppError::RangeNotSatisfiable(total_size));
    }

    let (start_str, end_str) = spec
        .split_once('-')
        .ok_or_else(|| AppError::RangeNotSatisfiable(total_size))?;

    if start_str.is_empty() {
        // Suffix range: bytes=-N
        let suffix_len: u64 = end_str
            .trim()
            .parse()
            .map_err(|_| AppError::RangeNotSatisfiable(total_size))?;
        if suffix_len == 0 {
            return Err(AppError::RangeNotSatisfiable(total_size));
        }
        let start = total_size.saturating_sub(suffix_len);
        return Ok((start, total_size - 1));
    }

    let start: u64 = start_str
        .trim()
        .parse()
        .map_err(|_| AppError::RangeNotSatisfiable(total_size))?;

    if start >= total_size {
        return Err(AppError::RangeNotSatisfiable(total_size));
    }

    let end = if end_str.trim().is_empty() {
        total_size - 1
    } else {
        let parsed_end: u64 = end_str
            .trim()
            .parse()
            .map_err(|_| AppError::RangeNotSatisfiable(total_size))?;
        if parsed_end < start {
            return Err(AppError::RangeNotSatisfiable(total_size));
        }
        parsed_end.min(total_size - 1)
    };

    Ok((start, end))
}
