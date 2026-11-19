use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashSet;
use subtle::ConstantTimeEq;

use crate::{error::AppError, models::ApiKeyRow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Read,
    Write,
    Admin,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
            Scope::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "read" => Ok(Scope::Read),
            "write" => Ok(Scope::Write),
            "admin" => Ok(Scope::Admin),
            other => Err(AppError::BadRequest(format!(
                "Invalid scope '{}'; allowed scopes are: read, write, admin",
                other
            ))),
        }
    }
}

pub fn parse_scopes_str(raw: &str) -> HashSet<Scope> {
    raw.split(',')
        .filter_map(|s| Scope::parse(s).ok())
        .collect()
}

pub fn scopes_to_sorted_vec(scopes: &HashSet<Scope>) -> Vec<String> {
    let mut out = Vec::with_capacity(scopes.len());
    for scope in [Scope::Read, Scope::Write, Scope::Admin] {
        if scopes.contains(&scope) {
            out.push(scope.as_str().to_string());
        }
    }
    out
}

pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_secret(plain_secret: &str, expected_hex_hash: &str) -> bool {
    let actual_hex = hash_secret(plain_secret);
    let actual_bytes = actual_hex.as_bytes();
    let expected_bytes = expected_hex_hash.as_bytes();
    actual_bytes.len() == expected_bytes.len() && bool::from(actual_bytes.ct_eq(expected_bytes))
}

pub fn generate_key_pair() -> (String, String, String) {
    let mut rng = rand::thread_rng();
    let ak_rand: String = (0..16)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    let sk_rand: String = (0..32)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();

    let access_key_id = format!("ak_{}", ak_rand);
    let access_key_secret = format!("sk_{}", sk_rand);
    let secret_hash = hash_secret(&access_key_secret);
    (access_key_id, access_key_secret, secret_hash)
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub key_id: String,
    pub access_key_id: String,
    pub name: String,
    pub scopes: HashSet<Scope>,
}

impl AuthContext {
    pub fn has_scope(&self, required: Scope) -> bool {
        self.scopes.contains(&Scope::Admin) || self.scopes.contains(&required)
    }

    pub fn require(&self, required: Scope) -> Result<(), AppError> {
        if self.has_scope(required) {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "Missing required scope '{}'",
                required.as_str()
            )))
        }
    }

    pub fn require_any(&self, required: &[Scope]) -> Result<(), AppError> {
        if self.scopes.contains(&Scope::Admin)
            || required.iter().any(|s| self.scopes.contains(s))
        {
            Ok(())
        } else {
            let names: Vec<&str> = required.iter().map(|s| s.as_str()).collect();
            Err(AppError::Forbidden(format!(
                "Missing required scope (one of: {})",
                names.join(", ")
            )))
        }
    }
}

impl<S> FromRequestParts<S> for AuthContext
where
    SqlitePool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

        let encoded = auth_header
            .strip_prefix("Basic ")
            .or_else(|| auth_header.strip_prefix("basic "))
            .ok_or_else(|| {
                AppError::Unauthorized("Authorization header must use Basic scheme".to_string())
            })?;

        let decoded_bytes = BASE64
            .decode(encoded.trim())
            .map_err(|_| AppError::Unauthorized("Invalid Basic auth base64".to_string()))?;

        let decoded = String::from_utf8(decoded_bytes)
            .map_err(|_| AppError::Unauthorized("Invalid Basic auth UTF-8".to_string()))?;

        let (ak, sk) = decoded.split_once(':').ok_or_else(|| {
            AppError::Unauthorized("Basic auth credentials must be ak:sk".to_string())
        })?;

        if ak.is_empty() || sk.is_empty() {
            return Err(AppError::Unauthorized(
                "AccessKey ID and Secret must not be empty".to_string(),
            ));
        }

        let pool = SqlitePool::from_ref(state);
        let row: Option<ApiKeyRow> = sqlx::query_as(
            r#"
            SELECT id, access_key_id, secret_hash, name, scopes, is_active, created_at, last_used_at
            FROM api_keys
            WHERE access_key_id = ?
            "#,
        )
        .bind(ak)
        .fetch_optional(&pool)
        .await?;

        let row = row.ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;

        if row.is_active == 0 {
            return Err(AppError::Unauthorized("API key has been revoked".to_string()));
        }

        if !verify_secret(sk, &row.secret_hash) {
            return Err(AppError::Unauthorized("Invalid credentials".to_string()));
        }

        let scopes = parse_scopes_str(&row.scopes);
        let key_id = row.id.clone();

        // Best-effort async update of last_used_at
        let pool_clone = pool.clone();
        let key_id_clone = key_id.clone();
        tokio::spawn(async move {
            let now = Utc::now().to_rfc3339();
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
                .bind(&now)
                .bind(&key_id_clone)
                .execute(&pool_clone)
                .await;
        });

        Ok(AuthContext {
            key_id,
            access_key_id: row.access_key_id,
            name: row.name,
            scopes,
        })
    }
}
