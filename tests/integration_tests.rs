use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

use firmware_distribute::{
    auth::{generate_key_pair, verify_secret},
    build_router,
    db::init_pool,
    storage::{
        compute_project_slug, infer_file_type, sanitize_filename, validate_project_name,
    },
    AppState,
};

fn basic_auth(ak: &str, sk: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{}:{}", ak, sk)))
}

async fn setup_test_app() -> (TempDir, axum::Router, String, String) {
    let tmp = TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("test.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let pool = init_pool(&db_url).await.expect("init_pool");

    let (ak, sk, secret_hash) = generate_key_pair();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO api_keys (id, access_key_id, secret_hash, name, scopes, is_active, created_at) VALUES (?, ?, ?, 'test-admin', 'admin', 1, ?)",
    )
    .bind(&id)
    .bind(&ak)
    .bind(&secret_hash)
    .bind(&now)
    .execute(&pool)
    .await
    .expect("seed admin key");

    let state = AppState {
        pool,
        data_dir: tmp.path().to_path_buf(),
        max_upload_bytes: 10 * 1024 * 1024,
    };
    let router = build_router(state);
    (tmp, router, ak, sk)
}

fn build_multipart_body(boundary: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, content) in parts {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        if let Some(fname) = filename {
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
                    name, fname
                )
                .as_bytes(),
            );
        } else {
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes(),
            );
        }
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

#[test]
fn unit_auth_and_storage_helpers() {
    let (ak, sk, hash) = generate_key_pair();
    assert!(ak.starts_with("ak_"));
    assert!(sk.starts_with("sk_"));
    assert!(verify_secret(&sk, &hash));
    assert!(!verify_secret("sk_wrong", &hash));

    assert_eq!(validate_project_name("   ").unwrap(), "public");
    assert_eq!(validate_project_name("Motor_X1").unwrap(), "Motor_X1");
    assert_eq!(validate_project_name("电机控制板").unwrap(), "电机控制板");
    assert!(validate_project_name("../escape").is_err());
    assert!(validate_project_name("a/b").is_err());
    assert!(validate_project_name("a\\b").is_err());

    assert_eq!(compute_project_slug("public", false), "public");
    assert_eq!(compute_project_slug("Motor_X1", false), "motor_x1");
    let cn_slug = compute_project_slug("电机控制板", false);
    assert!(cn_slug.starts_with("proj-"));
    assert_eq!(cn_slug, compute_project_slug("电机控制板", false));

    assert!(sanitize_filename("../evil.bin").is_err());
    assert!(sanitize_filename("").is_err());
    assert_eq!(sanitize_filename("app.bin").unwrap(), "app.bin");

    assert_eq!(infer_file_type(".bin"), "firmware");
    assert_eq!(infer_file_type(".md"), "doc");
    assert_eq!(infer_file_type(".toml"), "config");
    assert_eq!(infer_file_type(".zip"), "other");
}

#[tokio::test]
async fn e2e_permissions_upload_search_range_and_audit() {
    let (_tmp, app, admin_ak, admin_sk) = setup_test_app().await;
    let admin_auth = basic_auth(&admin_ak, &admin_sk);

    // 1. Static embedded UI & healthz
    let resp = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(html.contains("固件与文件分发平台"));

    let resp = app
        .clone()
        .oneshot(Request::get("/assets/app.js").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Create read-only and write-only keys
    let create_key = |name: &str, scopes: Vec<&str>| {
        let admin_auth = admin_auth.clone();
        let app = app.clone();
        let payload = serde_json::json!({ "name": name, "scopes": scopes });
        async move {
            let resp = app
                .oneshot(
                    Request::post("/api/v1/keys")
                        .header(header::AUTHORIZATION, admin_auth)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        }
    };

    let read_key = create_key("reader", vec!["read"]).await;
    let read_auth = basic_auth(
        read_key["access_key_id"].as_str().unwrap(),
        read_key["access_key_secret"].as_str().unwrap(),
    );

    let write_key = create_key("writer", vec!["write"]).await;
    let write_auth = basic_auth(
        write_key["access_key_id"].as_str().unwrap(),
        write_key["access_key_secret"].as_str().unwrap(),
    );

    // 3. Strict scope isolation
    let boundary = "----TestBoundary123";
    let payload_data: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
    let expected_sha = hex::encode(Sha256::digest(&payload_data));

    // File BEFORE project field to test field-order independence
    let mp_body = build_multipart_body(
        boundary,
        &[
            ("file", Some("motor_fw.bin"), &payload_data),
            ("project", None, b"Motor_X1"),
            ("version", None, b"v1.0.0"),
            ("summary", None, b"initial release"),
            ("tags", None, b"release,stm32"),
        ],
    );

    // Read key cannot upload
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/files")
                .header(header::AUTHORIZATION, &read_auth)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(mp_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Write key CAN upload
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/files")
                .header(header::AUTHORIZATION, &write_auth)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(mp_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let upload_json: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    let file_id_1 = upload_json["files"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(upload_json["files"][0]["sha256"], expected_sha);
    assert_eq!(upload_json["files"][0]["file_type"], "firmware");
    assert_eq!(upload_json["project"]["slug"], "motor_x1");

    // Write key CANNOT list files or manage keys
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/files")
                .header(header::AUTHORIZATION, &write_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/keys")
                .header(header::AUTHORIZATION, &write_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4. Upload second version of same filename + public default project
    let payload_v2 = b"v2-firmware-payload";
    let mp_v2 = build_multipart_body(
        boundary,
        &[
            ("project", None, b"Motor_X1"),
            ("version", None, b"v2.0.0"),
            ("file", Some("motor_fw.bin"), payload_v2),
        ],
    );
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/files")
                .header(header::AUTHORIZATION, &write_auth)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(mp_v2))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let upload_v2: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    let file_id_2 = upload_v2["files"][0]["id"].as_str().unwrap().to_string();
    assert_ne!(file_id_1, file_id_2);

    // Default public project when project omitted
    let mp_pub = build_multipart_body(
        boundary,
        &[("file", Some("readme.md"), b"# Public Doc")],
    );
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/files")
                .header(header::AUTHORIZATION, &write_auth)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(mp_pub))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let pub_json: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    assert_eq!(pub_json["project"]["slug"], "public");
    assert_eq!(pub_json["files"][0]["file_type"], "doc");

    // 5. Latest file query
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/files/latest?project=Motor_X1&file_name=motor_fw.bin")
                .header(header::AUTHORIZATION, &read_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let latest_json: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    assert_eq!(latest_json["id"], file_id_2);
    assert_eq!(latest_json["version"], "v2.0.0");

    // 6. Range download + ETag + X-File-Sha256
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/files/{}/download", file_id_1))
                .header(header::AUTHORIZATION, &read_auth)
                .header(header::RANGE, "bytes=0-1023")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers().get("x-file-sha256").unwrap().to_str().unwrap(),
        expected_sha
    );
    assert_eq!(
        resp.headers().get(header::CONTENT_RANGE).unwrap().to_str().unwrap(),
        "bytes 0-1023/2048"
    );
    let range_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(range_bytes.as_ref(), &payload_data[..1024]);

    // If-None-Match -> 304
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/files/{}/download", file_id_1))
                .header(header::AUTHORIZATION, &read_auth)
                .header(header::IF_NONE_MATCH, format!("\"{}\"", expected_sha))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

    // 7. Read cannot delete; Write can delete
    let resp = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/v1/files/{}", file_id_1))
                .header(header::AUTHORIZATION, &read_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/v1/files/{}", file_id_1))
                .header(header::AUTHORIZATION, &write_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 8. Revoke write key and verify 401
    let write_id = write_key["id"].as_str().unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/v1/keys/{}", write_id))
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/me")
                .header(header::AUTHORIZATION, &write_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 9. Audit logs recorded
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/audit-logs")
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let audit_json: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    assert!(audit_json["total"].as_i64().unwrap() >= 5);
}
