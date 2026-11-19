CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT UNIQUE NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    is_public INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    access_key_id TEXT UNIQUE NOT NULL,
    secret_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    scopes TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id),
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    extension TEXT NOT NULL,
    version TEXT,
    summary TEXT,
    tags TEXT,
    sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    uploaded_by_key_id TEXT REFERENCES api_keys(id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_files_project_created ON files(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_file_type ON files(file_type);
CREATE INDEX IF NOT EXISTS idx_files_file_name ON files(file_name);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_key_id TEXT,
    actor_name TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    detail TEXT,
    created_at TEXT NOT NULL
);
