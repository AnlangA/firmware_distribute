use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    PayloadTooLarge(String),
    RangeNotSatisfiable(u64),
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::RangeNotSatisfiable(total_len) => {
                let mut res = (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    Json(ErrorBody {
                        error: ErrorDetail {
                            code: "range_not_satisfiable",
                            message: "Requested range is not satisfiable".to_string(),
                        },
                    }),
                )
                    .into_response();
                if let Ok(val) = header::HeaderValue::from_str(&format!("bytes */{}", total_len)) {
                    res.headers_mut().insert(header::CONTENT_RANGE, val);
                }
                res
            }
            other => {
                let (status, code, message, needs_www_auth) = match other {
                    AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg, false),
                    AppError::Unauthorized(msg) => {
                        (StatusCode::UNAUTHORIZED, "unauthorized", msg, true)
                    }
                    AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg, false),
                    AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg, false),
                    AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg, false),
                    AppError::PayloadTooLarge(msg) => {
                        (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", msg, false)
                    }
                    AppError::Internal(msg) => {
                        tracing::error!("Internal server error: {}", msg);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "Internal server error".to_string(),
                            false,
                        )
                    }
                    AppError::RangeNotSatisfiable(_) => unreachable!(),
                };

                let mut res = (
                    status,
                    Json(ErrorBody {
                        error: ErrorDetail { code, message },
                    }),
                )
                    .into_response();

                if needs_www_auth {
                    res.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        header::HeaderValue::from_static("Basic realm=\"firmware_distribute\""),
                    );
                }

                res
            }
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Internal(format!("Database error: {}", err))
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Internal(format!("I/O error: {}", err))
    }
}
