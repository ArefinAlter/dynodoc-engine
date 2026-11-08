//! Original files in an object store (decision 037, migration 0113) through the real routes, the
//! restricted runtime login and the filesystem driver: the row holds a key and a digest, not the
//! bytes; a download returns the same bytes; a changed object is never served; the database
//! refuses a key that names another document; erasing the document deletes its objects.
mod common;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use base64::Engine;
use engine_api::{
    app,
    auth::{store, token, AuthConfig},
    object_store::ObjectStore,
    AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const KEY: [u8; 32] = [9; 32];

async fn call(
    router: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = if body.is_null() {
        Body::empty()
    } else {
        request = request.header(header::CONTENT_TYPE, "application/json");
        Body::from(body.to_string())
    };
    let response = router
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn originals_live_in_the_store_are_checked_on_read_and_go_with_the_document(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let dir = std::env::temp_dir().join(format!("dynodoc-store-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let root = std::fs::canonicalize(&dir).unwrap();
    let mut state = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.admin_emails = "admin@example.test".into();
    state.objects = std::sync::Arc::new(ObjectStore::Filesystem { root: root.clone() });
    let router = app(state);
    let person = |email: &'static str| {
        let pool = runtime.pool.clone();
        async move {
            let id = store::upsert_identity(&pool, email, None)
                .await
                .unwrap()
                .id
                .0;
            token::mint(&KEY, id, 3600).unwrap()
        }
    };
    let author = person("author@example.test").await;
    let admin = person("admin@example.test").await;
    let (status, created) = call(
        &router,
        "POST",
        "/documents",
        &author,
        json!({"title": "Stored"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let doc: Uuid = serde_json::from_value(json_of(&created)["id"].clone()).unwrap();

    let original = b"PK\x03\x04 synthetic original file bytes".to_vec();
    let (status, uploaded) = call(
        &router,
        "POST",
        &format!("/documents/{doc}/uploads"),
        &author,
        json!({"filename": "report.docx", "content_type": "application/octet-stream",
               "content": base64::engine::general_purpose::STANDARD.encode(&original), "report": {}}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&uploaded)
    );
    let upload: Uuid = serde_json::from_value(json_of(&uploaded)["id"].clone()).unwrap();
    let (content, key, size): (Option<Vec<u8>>, Option<String>, Option<i64>) =
        sqlx::query_as("select content,storage_key,size from document_upload where id=$1")
            .bind(upload)
            .fetch_one(&runtime.pool)
            .await
            .unwrap();
    assert!(content.is_none(), "the bytes are not in the database");
    let key = key.unwrap();
    assert_eq!(key, format!("originals/{doc}/{}", upload.simple()));
    assert_eq!(size, Some(original.len() as i64));
    let file = root.join(&key);
    assert_eq!(std::fs::read(&file).unwrap(), original);
    // The listing shows neither the key nor the digest.
    let (_, listed) = call(
        &router,
        "GET",
        &format!("/documents/{doc}/uploads"),
        &author,
        Value::Null,
    )
    .await;
    let listed = json_of(&listed);
    assert!(listed["items"][0].get("storage_key").is_none());
    assert!(listed["items"][0].get("sha256").is_none());

    let download = format!("/documents/{doc}/uploads/{upload}");
    let (status, bytes) = call(&router, "GET", &download, &author, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, original);

    // A changed object is refused, never served.
    std::fs::write(&file, b"tampered bytes").unwrap();
    let (status, bytes) = call(&router, "GET", &download, &author, Value::Null).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!String::from_utf8_lossy(&bytes).contains("tampered"));
    assert!(!String::from_utf8_lossy(&bytes).contains(&key));
    std::fs::write(&file, &original).unwrap();

    // The database ties a key to its own row: no row can name another document's object.
    let other: Uuid = sqlx::query_scalar("select id from document where id<>$1 limit 1")
        .bind(doc)
        .fetch_optional(&runtime.pool)
        .await
        .unwrap()
        .unwrap_or(doc);
    let forged = sqlx::query("insert into document_upload(document_id,filename,content_type,storage_key,size,sha256,created_by) select $1,'x','x',$2,1,$3,created_by from document where id=$4")
        .bind(other)
        .bind(&key)
        .bind(vec![0u8; 32])
        .bind(doc)
        .execute(&runtime.pool)
        .await;
    assert!(forged.is_err(), "a key of another row is refused");
    let both = sqlx::query("update document_upload set content=$2 where id=$1")
        .bind(upload)
        .bind(b"x".to_vec())
        .execute(&runtime.pool)
        .await;
    assert!(both.is_err(), "bytes are kept in one place only");

    // Erasure: the rows go in the transaction, then the object.
    let (status, impact) = call(
        &router,
        "GET",
        &format!("/admin/impact?kind=documents&id={doc}"),
        &admin,
        Value::Null,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&impact)
    );
    let impact = json_of(&impact);
    let (status, erased) = call(
        &router,
        "POST",
        "/admin/erase",
        &admin,
        json!({"kind": "documents", "id": doc, "confirmation": impact["label"], "revision": impact["revision"],
               "reason": "other", "acknowledge_backups": true}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&erased)
    );
    assert!(!file.exists(), "the erased document's object is deleted");
    let _ = std::fs::remove_dir_all(&dir);
}
