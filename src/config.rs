use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub listen_addr: String,
    pub data_dir: PathBuf,
    pub database_url: String,
    pub max_upload_bytes: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".to_string(),
            data_dir: PathBuf::from("./storage"),
            database_url: "sqlite://./storage/firmware_distribute.db?mode=rwc".to_string(),
            max_upload_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
        }
    }
}

impl AppConfig {
    pub fn load(config_path: Option<&Path>) -> Result<Self, String> {
        let mut cfg = match config_path {
            Some(path) => {
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
                toml::from_str::<Self>(&raw)
                    .map_err(|e| format!("Failed to parse config file {}: {}", path.display(), e))?
            }
            None => {
                let default_path = Path::new("config.toml");
                if default_path.exists() {
                    let raw = std::fs::read_to_string(default_path)
                        .map_err(|e| format!("Failed to read config.toml: {}", e))?;
                    toml::from_str::<Self>(&raw)
                        .map_err(|e| format!("Failed to parse config.toml: {}", e))?
                } else {
                    Self::default()
                }
            }
        };

        if let Ok(val) = std::env::var("FD_LISTEN_ADDR") {
            if !val.trim().is_empty() {
                cfg.listen_addr = val;
            }
        }
        if let Ok(val) = std::env::var("FD_DATA_DIR") {
            if !val.trim().is_empty() {
                cfg.data_dir = PathBuf::from(val);
            }
        }
        if let Ok(val) = std::env::var("FD_DATABASE_URL") {
            if !val.trim().is_empty() {
                cfg.database_url = val;
            }
        }
        if let Ok(val) = std::env::var("FD_MAX_UPLOAD_BYTES") {
            if !val.trim().is_empty() {
                cfg.max_upload_bytes = val
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid FD_MAX_UPLOAD_BYTES '{}': {}", val, e))?;
            }
        }

        Ok(cfg)
    }
}
