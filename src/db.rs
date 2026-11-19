use chrono::Utc;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

pub async fn init_pool(database_url: &str) -> Result<SqlitePool, String> {
    if let Some(path_part) = database_url.strip_prefix("sqlite://") {
        let file_path = path_part.split('?').next().unwrap_or(path_part);
        if file_path != ":memory:" && !file_path.is_empty() {
            if let Some(parent) = Path::new(file_path).parent() {
                if !parent.as_os_str().is_empty() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|e| format!("Failed to create database directory: {}", e))?;
                }
            }
        }
    }

    let options = SqliteConnectOptions::from_str(database_url)
        .map_err(|e| format!("Invalid database URL '{}': {}", database_url, e))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await
        .map_err(|e| format!("Failed to connect to SQLite: {}", e))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;

    ensure_public_project(&pool).await?;

    Ok(pool)
}

async fn ensure_public_project(pool: &SqlitePool) -> Result<(), String> {
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO projects (id, name, slug, is_public, created_at, updated_at)
        VALUES (?, 'public', 'public', 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to seed public project: {}", e))?;

    Ok(())
}

pub async fn record_audit_log(
    pool: &SqlitePool,
    actor_key_id: Option<&str>,
    actor_name: Option<&str>,
    action: &str,
    target_type: &str,
    target_id: Option<&str>,
    detail: Option<&str>,
) {
    let now = Utc::now().to_rfc3339();
    if let Err(err) = sqlx::query(
        r#"
        INSERT INTO audit_logs (actor_key_id, actor_name, action, target_type, target_id, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(actor_key_id)
    .bind(actor_name)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(detail)
    .bind(&now)
    .execute(pool)
    .await
    {
        tracing::warn!("Failed to record audit log ({}): {}", action, err);
    }
}
