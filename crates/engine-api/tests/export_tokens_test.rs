//! Integration tests for PR-101: Per-export node tokens.
//!
//! Tests cross-export and cross-document denial, explicit export revocation, retries with
//! idempotency keys, random-token uniqueness, legacy IDs, deleted node targets,
//! and audited whole-document erasure.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use engine_api::{
    app,
    auth::{store as auth_store, token, AuthConfig},
    export_tokens::{CARRIER_FORMAT, CARRIER_VERSION},
    AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashSet;
use tower::ServiceExt;
use uuid::Uuid;

mod common;
use common::RuntimeDatabase;

const KEY: [u8; 32] = [7u8; 32];

fn test_state(pool: PgPool) -> AppState {
    AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 86400,
            public_base_url: "http://localhost:5548".into(),
        },
    )
}

async fn seed_identity(pool: &PgPool, email: &str) -> Uuid {
    auth_store::upsert_identity(pool, email, Some("Tester"))
        .await
        .unwrap()
        .id
        .0
}

fn bearer(id: Uuid) -> String {
    token::mint(&KEY, id, 86400).unwrap()
}

fn auth_post(uri: &str, token: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn auth_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn create_doc_with_nodes(
    router: &Router,
    token: &str,
    title: &str,
) -> (Uuid, String, String) {
    let (status, body) = send(
        router,
        auth_post("/documents", token, &json!({ "title": title })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    let node1 = ulid::Ulid::generate().to_string();
    let node2 = ulid::Ulid::generate().to_string();

    let (status, result) = send(
        router,
        auth_post(
            &format!("/documents/{doc_id}/batch"),
            token,
            &json!({
                "base_seq": 0,
                "ops": [
                    {"type": "NodeCreated", "node_id": node1, "node_type": "form", "pos": "a0", "fields": {"label": "Root"}},
                    {"type": "NodeCreated", "node_id": node2, "node_type": "item", "parent_id": node1, "pos": "a0", "fields": {"label": "Item", "type": "text", "name": "field1"}}
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");

    (doc_id, node1, node2)
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_and_resolve_export_tokens_basic(pool: PgPool) {
    let router = app(test_state(pool.clone()));
    let user = seed_identity(&pool, "user1@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, node2) = create_doc_with_nodes(&router, &auth, "Export Test Doc").await;

    // Mint export tokens for all nodes
    let (status, export_resp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &auth,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{export_resp}");
    assert_eq!(export_resp["format"], CARRIER_FORMAT);
    assert_eq!(export_resp["version"], CARRIER_VERSION);
    assert_eq!(export_resp["document_id"], doc_id.to_string());
    assert_eq!(export_resp["revision"], 2);

    let export_id = Uuid::parse_str(export_resp["export_id"].as_str().unwrap()).unwrap();
    let mappings = export_resp["mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 2);

    let token1 = mappings.iter().find(|m| m["node_id"] == node1).unwrap()["token"]
        .as_str()
        .unwrap();
    let token2 = mappings.iter().find(|m| m["node_id"] == node2).unwrap()["token"]
        .as_str()
        .unwrap();

    // Verify token format: 32 random bytes url-safe unpadded base64 is 43 chars
    assert_eq!(token1.len(), 43);
    assert_eq!(token2.len(), 43);
    assert_ne!(token1, token2);

    // Resolve both tokens
    let (status, resolve_resp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens/resolve"),
            &auth,
            &json!({
                "format": CARRIER_FORMAT,
                "version": CARRIER_VERSION,
                "export_id": export_id,
                "tokens": [token1, token2]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolve_resp}");
    let items = resolve_resp["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);

    let item1 = items.iter().find(|i| i["token"] == token1).unwrap();
    assert_eq!(item1["node_id"], node1);
    assert_eq!(item1["deleted"], false);
    assert_eq!(item1["resolved"], true);

    let item2 = items.iter().find(|i| i["token"] == token2).unwrap();
    assert_eq!(item2["node_id"], node2);
    assert_eq!(item2["deleted"], false);
    assert_eq!(item2["resolved"], true);

    // Verify get export status
    let (status, details) = send(
        &router,
        auth_get(
            &format!("/documents/{doc_id}/export-tokens/{export_id}"),
            &auth,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{details}");
    assert_eq!(details["token_count"], 2);
    assert!(details["revoked_at"].is_null());
}

#[sqlx::test(migrations = "../../migrations")]
async fn cross_export_denial(pool: PgPool) {
    let router = app(test_state(pool.clone()));
    let user = seed_identity(&pool, "user2@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, _) = create_doc_with_nodes(&router, &auth, "Cross Export Doc").await;

    // Export 1
    let (_, exp1) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &auth,
            &json!({"node_ids": [node1]}),
        ),
    )
    .await;
    let _exp1_id = exp1["export_id"].as_str().unwrap();
    let token_exp1 = exp1["mappings"][0]["token"].as_str().unwrap();

    // Export 2
    let (_, exp2) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &auth,
            &json!({"node_ids": [node1]}),
        ),
    )
    .await;
    let exp2_id = exp2["export_id"].as_str().unwrap();
    let token_exp2 = exp2["mappings"][0]["token"].as_str().unwrap();

    assert_ne!(token_exp1, token_exp2);

    // Attempt to resolve token_exp1 under Export 2: must NOT resolve
    let (status, resolve_resp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens/resolve"),
            &auth,
            &json!({
                "export_id": exp2_id,
                "tokens": [token_exp1]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolve_resp}");
    let items = resolve_resp["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["resolved"], false);
    assert!(items[0]["node_id"].is_null());

    // Token from Export 2 does resolve under Export 2
    let (status, resolve_resp2) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens/resolve"),
            &auth,
            &json!({
                "export_id": exp2_id,
                "tokens": [token_exp2]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolve_resp2}");
    assert_eq!(resolve_resp2["items"][0]["resolved"], true);
    assert_eq!(resolve_resp2["items"][0]["node_id"], node1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn cross_document_denial(pool: PgPool) {
    let router = app(test_state(pool.clone()));
    let user = seed_identity(&pool, "user3@example.com").await;
    let auth = bearer(user);

    let (doc1, node1, _) = create_doc_with_nodes(&router, &auth, "Doc 1").await;
    let (doc2, _, _) = create_doc_with_nodes(&router, &auth, "Doc 2").await;

    // Export from Doc 1
    let (_, exp1) = send(
        &router,
        auth_post(
            &format!("/documents/{doc1}/export-tokens"),
            &auth,
            &json!({"node_ids": [node1]}),
        ),
    )
    .await;
    let exp1_id = exp1["export_id"].as_str().unwrap();
    let token1 = exp1["mappings"][0]["token"].as_str().unwrap();

    // Querying Doc 2 with exp1_id must fail with 404 Not Found (no cross-document leak)
    let (status, resolve_resp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc2}/export-tokens/resolve"),
            &auth,
            &json!({
                "export_id": exp1_id,
                "tokens": [token1]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{resolve_resp}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn explicit_revocation(pool: PgPool) {
    let router = app(test_state(pool.clone()));
    let user = seed_identity(&pool, "user4@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, _) = create_doc_with_nodes(&router, &auth, "Revoke Doc").await;

    let (_, exp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &auth,
            &json!({"node_ids": [node1]}),
        ),
    )
    .await;
    let exp_id = exp["export_id"].as_str().unwrap();
    let token = exp["mappings"][0]["token"].as_str().unwrap();

    // Resolves before revocation
    let (status, res) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens/resolve"),
            &auth,
            &json!({
                "export_id": exp_id,
                "tokens": [token]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{res}");
    assert_eq!(res["items"][0]["resolved"], true);

    // Explicit revoke
    let (status, revoke_res) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens/{exp_id}/revoke"),
            &auth,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoke_res}");
    assert_eq!(revoke_res["revoked"], true);

    // Resolution after revocation must be denied with 403 Forbidden
    let (status, denied) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens/resolve"),
            &auth,
            &json!({
                "export_id": exp_id,
                "tokens": [token]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");

    // Get details shows revoked_at
    let (status, details) = send(
        &router,
        auth_get(
            &format!("/documents/{doc_id}/export-tokens/{exp_id}"),
            &auth,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{details}");
    assert!(!details["revoked_at"].is_null());
}

#[sqlx::test(migrations = "../../migrations")]
async fn idempotency_retries_replay_identical_tokens(pool: PgPool) {
    let router = app(test_state(pool.clone()));
    let user = seed_identity(&pool, "user5@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, node2) = create_doc_with_nodes(&router, &auth, "Idempotency Doc").await;

    let req_body = json!({
        "idempotency_key": "export-idem-key-001",
        "node_ids": [node1, node2]
    });

    let (status1, resp1) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &auth,
            &req_body,
        ),
    )
    .await;
    assert_eq!(status1, StatusCode::OK, "{resp1}");

    // Retry with exact same idempotency key
    let (status2, resp2) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &auth,
            &req_body,
        ),
    )
    .await;
    assert_eq!(status2, StatusCode::OK, "{resp2}");

    // The replayed response must match exactly
    assert_eq!(resp1["export_id"], resp2["export_id"]);
    assert_eq!(resp1["mappings"], resp2["mappings"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn random_token_uniqueness(pool: PgPool) {
    let router = app(test_state(pool.clone()));
    let user = seed_identity(&pool, "user6@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, node2) = create_doc_with_nodes(&router, &auth, "Uniqueness Doc").await;

    let mut all_tokens = HashSet::new();

    // Generate 10 separate exports of 2 nodes each = 20 tokens
    for _ in 0..10 {
        let (status, resp) = send(
            &router,
            auth_post(
                &format!("/documents/{doc_id}/export-tokens"),
                &auth,
                &json!({"node_ids": [node1, node2]}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for m in resp["mappings"].as_array().unwrap() {
            let t = m["token"].as_str().unwrap().to_string();
            assert_eq!(t.len(), 43);
            assert!(all_tokens.insert(t), "Token was not unique!");
        }
    }
    assert_eq!(all_tokens.len(), 20);
}

#[sqlx::test(migrations = "../../migrations")]
async fn legacy_ids_resolution_preserves_spelling(pool: PgPool) {
    let router = app(test_state(pool.clone()));
    let user = seed_identity(&pool, "user7@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, node2) = create_doc_with_nodes(&router, &auth, "Legacy IDs Doc").await;

    let nonexistent = ulid::Ulid::generate().to_string();

    let (status, resp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens/resolve"),
            &auth,
            &json!({
                "legacy_ids": [node1, node2, nonexistent]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let items = resp["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);

    let n1 = items.iter().find(|i| i["legacy_id"] == node1).unwrap();
    assert_eq!(n1["node_id"], node1);
    assert_eq!(n1["deleted"], false);
    assert_eq!(n1["resolved"], true);

    let n2 = items.iter().find(|i| i["legacy_id"] == node2).unwrap();
    assert_eq!(n2["node_id"], node2);
    assert_eq!(n2["deleted"], false);
    assert_eq!(n2["resolved"], true);

    let ne = items
        .iter()
        .find(|i| i["legacy_id"] == nonexistent)
        .unwrap();
    assert!(ne["node_id"].is_null());
    assert_eq!(ne["resolved"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleted_nodes_reported_without_rebinding(pool: PgPool) {
    let router = app(test_state(pool.clone()));
    let user = seed_identity(&pool, "user8@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, node2) = create_doc_with_nodes(&router, &auth, "Deleted Node Doc").await;

    // Export both nodes
    let (_, exp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &auth,
            &json!({"node_ids": [node1, node2]}),
        ),
    )
    .await;
    let exp_id = exp["export_id"].as_str().unwrap();
    let token1 = exp["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["node_id"] == node1)
        .unwrap()["token"]
        .as_str()
        .unwrap();
    let token2 = exp["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["node_id"] == node2)
        .unwrap()["token"]
        .as_str()
        .unwrap();

    // Now delete node2 via NodeDeleted event
    let (status, del_res) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/batch"),
            &auth,
            &json!({
                "base_seq": 2,
                "ops": [
                    {"type": "NodeDeleted", "node_id": node2}
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{del_res}");

    // Resolve tokens again: token2 maps to node2 with deleted: true
    let (status, resp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens/resolve"),
            &auth,
            &json!({
                "export_id": exp_id,
                "tokens": [token1, token2]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let items = resp["items"].as_array().unwrap();

    let res1 = items.iter().find(|i| i["token"] == token1).unwrap();
    assert_eq!(res1["node_id"], node1);
    assert_eq!(res1["deleted"], false);
    assert_eq!(res1["resolved"], true);

    let res2 = items.iter().find(|i| i["token"] == token2).unwrap();
    assert_eq!(res2["node_id"], node2);
    assert_eq!(res2["deleted"], true);
    assert_eq!(res2["resolved"], true);
}

#[sqlx::test(migrations = "../../migrations")]
async fn audited_document_erasure_purges_export_tokens(pool: PgPool) {
    let runtime = RuntimeDatabase::new(pool).await;
    let mut state = test_state(runtime.pool.clone());
    state.admin_emails = "admin@example.com".into();
    let router = app(state);

    let admin = seed_identity(&runtime.owner, "admin@example.com").await;
    let admin_auth = bearer(admin);

    let (doc_id, node1, _) = create_doc_with_nodes(&router, &admin_auth, "Document To Erase").await;

    // Export tokens
    let (status, exp) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &admin_auth,
            &json!({"node_ids": [node1]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{exp}");

    let count_before: i64 =
        sqlx::query_scalar("select count(*) from export_node_token where document_id = $1")
            .bind(doc_id)
            .fetch_one(&runtime.owner)
            .await
            .unwrap();
    assert_eq!(count_before, 1);

    // Get deletion preview
    let (status, preview) = send(
        &router,
        auth_get(
            &format!("/admin/impact?kind=documents&id={doc_id}"),
            &admin_auth,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");

    // Erase the document
    let (status, erase_res) = send(
        &router,
        auth_post(
            "/admin/erase",
            &admin_auth,
            &json!({
                "kind": "documents",
                "id": doc_id,
                "confirmation": preview["label"],
                "revision": preview["revision"],
                "reason": "owner_request",
                "acknowledge_backups": true
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{erase_res}");

    // Verify document is deleted and tokens are cascaded
    let count_after: i64 =
        sqlx::query_scalar("select count(*) from export_node_token where document_id = $1")
            .bind(doc_id)
            .fetch_one(&runtime.owner)
            .await
            .unwrap();
    assert_eq!(count_after, 0);

    // Endpoint for erased document returns 404
    let (status, _) = send(
        &router,
        auth_post(
            &format!("/documents/{doc_id}/export-tokens"),
            &admin_auth,
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn runtime_database_grants_and_privileges_pass(pool: PgPool) {
    let runtime = RuntimeDatabase::new(pool).await;
    // RuntimeDatabase::new already calls grant_runtime and check_runtime.
    // Verify check_runtime passes cleanly.
    engine_core::database::check_runtime(&runtime.pool)
        .await
        .unwrap();
    runtime.close().await;
}
