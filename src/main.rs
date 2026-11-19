use chrono::Utc;
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use firmware_distribute::{
    auth::{generate_key_pair, scopes_to_sorted_vec, Scope},
    build_router,
    config::AppConfig,
    db::init_pool,
    models::ApiKeyRow,
    storage::ensure_storage_dirs,
    AppState,
};

#[derive(Parser)]
#[command(name = "firmware_distribute", version, about = "LAN firmware & file distribution platform")]
struct Cli {
    /// Optional path to config TOML file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP server (default when no subcommand is given)
    Serve,
    /// Manage API keys
    Key {
        #[command(subcommand)]
        action: KeyCommands,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create a new API key pair
    Create {
        #[arg(long)]
        name: String,
        /// Comma-separated scopes: read, write, admin
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
    },
    /// List all API keys
    List,
    /// Revoke an API key by ID or AccessKey ID
    Revoke {
        #[arg(long)]
        id: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "firmware_distribute=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let cfg = match AppConfig::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = ensure_storage_dirs(&cfg.data_dir).await {
        eprintln!("Storage initialization error: {}", e);
        std::process::exit(1);
    }

    let pool = match init_pool(&cfg.database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Database initialization error: {}", e);
            std::process::exit(1);
        }
    };

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => {
            let state = AppState {
                pool,
                data_dir: cfg.data_dir.clone(),
                max_upload_bytes: cfg.max_upload_bytes,
            };
            let app = build_router(state);
            let listener = match tokio::net::TcpListener::bind(&cfg.listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Failed to bind {}: {}", cfg.listen_addr, e);
                    std::process::exit(1);
                }
            };
            tracing::info!(
                "firmware_distribute listening on http://{} (data_dir={})",
                cfg.listen_addr,
                cfg.data_dir.display()
            );
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("Server error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Key { action } => match action {
            KeyCommands::Create { name, scopes } => {
                let trimmed_name = name.trim();
                if trimmed_name.is_empty() || scopes.is_empty() {
                    eprintln!("Name and at least one scope are required");
                    std::process::exit(1);
                }
                let mut parsed = HashSet::new();
                for s in &scopes {
                    match Scope::parse(s) {
                        Ok(sc) => {
                            parsed.insert(sc);
                        }
                        Err(_) => {
                            eprintln!("Invalid scope '{}'; allowed: read, write, admin", s);
                            std::process::exit(1);
                        }
                    }
                }
                let scope_vec = scopes_to_sorted_vec(&parsed);
                let scopes_str = scope_vec.join(",");
                let id = Uuid::new_v4().to_string();
                let (ak, sk, secret_hash) = generate_key_pair();
                let now = Utc::now().to_rfc3339();

                if let Err(e) = sqlx::query(
                    "INSERT INTO api_keys (id, access_key_id, secret_hash, name, scopes, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                )
                .bind(&id)
                .bind(&ak)
                .bind(&secret_hash)
                .bind(trimmed_name)
                .bind(&scopes_str)
                .bind(&now)
                .execute(&pool)
                .await
                {
                    eprintln!("Failed to create API key: {}", e);
                    std::process::exit(1);
                }

                println!("Created API key:");
                println!("  ID:                {}", id);
                println!("  Name:              {}", trimmed_name);
                println!("  Scopes:            {}", scopes_str);
                println!("  AccessKey ID:      {}", ak);
                println!("  AccessKey Secret:  {}  (save now, shown only once)", sk);
            }
            KeyCommands::List => {
                let rows: Vec<ApiKeyRow> = sqlx::query_as(
                    "SELECT id, access_key_id, secret_hash, name, scopes, is_active, created_at, last_used_at FROM api_keys ORDER BY created_at DESC",
                )
                .fetch_all(&pool)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("Failed to list keys: {}", e);
                    std::process::exit(1);
                });

                if rows.is_empty() {
                    println!("No API keys found.");
                } else {
                    for r in rows {
                        println!(
                            "{} | {} | name={} | scopes={} | active={} | created={}",
                            r.id,
                            r.access_key_id,
                            r.name,
                            r.scopes,
                            r.is_active != 0,
                            r.created_at
                        );
                    }
                }
            }
            KeyCommands::Revoke { id } => {
                let res = sqlx::query(
                    "UPDATE api_keys SET is_active = 0 WHERE id = ? OR access_key_id = ?",
                )
                .bind(&id)
                .bind(&id)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("Failed to revoke key: {}", e);
                    std::process::exit(1);
                });

                if res.rows_affected() == 0 {
                    eprintln!("No API key found matching '{}'", id);
                    std::process::exit(1);
                }
                println!("Revoked API key '{}'", id);
            }
        },
    }
}
