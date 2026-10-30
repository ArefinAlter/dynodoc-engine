use super::*;
use axum::{http::StatusCode, Router};
use engine_api::{
    app,
    auth::{store as auth_store, token, AuthConfig},
    AppState,
};
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashSet;

const KEY: [u8; 32] = [7u8; 32];

fn test_state(pool: PgPool) -> AppState {
    AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 86400,
            public_base_url: "http://test.local".into(),
        },
    )
}

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, server)
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

async fn create_doc_with_nodes(url: &str, auth_token: &str, title: &str) -> (Uuid, String, String) {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{url}documents"))
        .bearer_auth(auth_token)
        .json(&json!({ "title": title }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let doc_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    let node1 = ulid::Ulid::generate().to_string();
    let node2 = ulid::Ulid::generate().to_string();

    let batch_res = client
        .post(format!("{url}documents/{doc_id}/batch"))
        .bearer_auth(auth_token)
        .json(&json!({
            "base_seq": 0,
            "ops": [
                {"type": "NodeCreated", "node_id": node1, "node_type": "form", "pos": "a0", "fields": {"label": "Root"}},
                {"type": "NodeCreated", "node_id": node2, "node_type": "item", "parent_id": node1, "pos": "a0", "fields": {"label": "Item", "type": "text", "name": "field1"}}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(batch_res.status(), StatusCode::OK);

    (doc_id, node1, node2)
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dynodoc-export-tests-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn account_and_device_confusion_rejected() {
    let tmp = scratch_dir();
    let dummy_doc = Uuid::new_v4();

    // 1. Device key file argument is rejected explicitly
    let key_file = tmp.join("device.key");
    std::fs::write(&key_file, b"secret").unwrap();

    let opts_device_key = Options {
        url: Some("http://127.0.0.1:5548/".into()),
        remote: None,
        token_file: None,
        token: Some("account-token".into()),
        device_key: Some(key_file),
        allow_loopback_http: true,
        action: Action::Status {
            document: dummy_doc,
            export_id: Uuid::new_v4(),
            json: true,
        },
    };
    let err = run(opts_device_key).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("device-only credentials are not accepted"),
        "got: {err}"
    );

    // 2. Project-device token string passed in --token is rejected
    let project_device_token = token::mint_project_device(
        &KEY,
        &token::DeviceClaims {
            identity: Uuid::new_v4(),
            key: Uuid::new_v4(),
            project: Uuid::new_v4(),
            session: Uuid::new_v4(),
            scopes: vec!["history:read".into()],
            generation: 1,
        },
        3600,
    )
    .unwrap();

    let opts_device_token = Options {
        url: Some("http://127.0.0.1:5548/".into()),
        remote: None,
        token_file: None,
        token: Some(project_device_token),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Status {
            document: dummy_doc,
            export_id: Uuid::new_v4(),
            json: true,
        },
    };
    let err2 = run(opts_device_token).await.unwrap_err();
    assert!(
        err2.to_string()
            .contains("project-device tokens are rejected"),
        "got: {err2}"
    );

    // 3. No token provided
    let opts_no_token = Options {
        url: Some("http://127.0.0.1:5548/".into()),
        remote: None,
        token_file: None,
        token: None,
        device_key: None,
        allow_loopback_http: true,
        action: Action::Status {
            document: dummy_doc,
            export_id: Uuid::new_v4(),
            json: true,
        },
    };
    let err3 = run(opts_no_token).await.unwrap_err();
    assert!(
        err3.to_string().contains("provide account credential"),
        "got: {err3}"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

#[tokio::test]
async fn existing_output_refusal_before_network() {
    let tmp = scratch_dir();
    let carrier_file = tmp.join("carrier.json");
    std::fs::write(&carrier_file, b"pre-existing content").unwrap();

    let opts = Options {
        url: Some("http://127.0.0.1:5548/".into()),
        remote: None,
        token_file: None,
        token: Some(bearer(Uuid::new_v4())),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Mint {
            document: Uuid::new_v4(),
            out: carrier_file.clone(),
            revision: Some(1),
            nodes: vec!["node1".into()],
            idempotency_key: None,
        },
    };

    let err = run(opts).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("output file already exists; will not overwrite"),
        "got: {err}"
    );
    // Verify file content was never touched
    assert_eq!(
        std::fs::read(&carrier_file).unwrap(),
        b"pre-existing content"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

#[sqlx::test(migrations = "../../migrations")]
async fn private_output_permissions_and_mint_contract(pool: PgPool) {
    let (url, server) = serve(app(test_state(pool.clone()))).await;
    let user = seed_identity(&pool, "owner@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, node2) = create_doc_with_nodes(&url, &auth, "Mint Doc").await;
    let tmp = scratch_dir();
    let carrier_out = tmp.join("private_carrier.json");

    let opts = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Mint {
            document: doc_id,
            out: carrier_out.clone(),
            revision: Some(1),
            nodes: vec![node1.clone(), node2.clone()],
            idempotency_key: None,
        },
    };

    run(opts).await.unwrap();
    assert!(carrier_out.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&carrier_out).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "carrier file must be owner-only mode 0600"
        );
    }

    let bytes = std::fs::read(&carrier_out).unwrap();
    let carrier: ExportTokensResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(carrier.format, CARRIER_FORMAT);
    assert_eq!(carrier.version, CARRIER_VERSION);
    assert_eq!(carrier.document_id, doc_id);
    assert_eq!(carrier.revision, 1);
    assert_eq!(carrier.mappings.len(), 2);
    let mapped_nodes: HashSet<String> =
        carrier.mappings.iter().map(|m| m.node_id.clone()).collect();
    assert!(mapped_nodes.contains(&node1));
    assert!(mapped_nodes.contains(&node2));

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(tmp);
}

#[sqlx::test(migrations = "../../migrations")]
async fn lost_response_and_idempotency_key_replay(pool: PgPool) {
    let (url, server) = serve(app(test_state(pool.clone()))).await;
    let user = seed_identity(&pool, "idempotent@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, _node2) = create_doc_with_nodes(&url, &auth, "Idem Doc").await;
    let tmp = scratch_dir();
    let carrier1 = tmp.join("carrier1.json");
    let carrier2 = tmp.join("carrier2.json");

    let idem_key = format!("test-idem-{}", Uuid::new_v4());

    // 1. First mint call with explicit idempotency key
    let opts1 = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Mint {
            document: doc_id,
            out: carrier1.clone(),
            revision: Some(1),
            nodes: vec![node1.clone()],
            idempotency_key: Some(idem_key.clone()),
        },
    };
    run(opts1).await.unwrap();
    let bytes1 = std::fs::read(&carrier1).unwrap();
    let parsed1: ExportTokensResponse = serde_json::from_slice(&bytes1).unwrap();

    // 2. Retry with same idempotency key (writing to carrier2) replays identical response from cache
    let opts2 = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Mint {
            document: doc_id,
            out: carrier2.clone(),
            revision: Some(1),
            nodes: vec![node1.clone()],
            idempotency_key: Some(idem_key.clone()),
        },
    };
    run(opts2).await.unwrap();
    let bytes2 = std::fs::read(&carrier2).unwrap();
    let parsed2: ExportTokensResponse = serde_json::from_slice(&bytes2).unwrap();

    assert_eq!(parsed1.export_id, parsed2.export_id);
    assert_eq!(parsed1.mappings[0].node_id, parsed2.mappings[0].node_id);
    assert_eq!(parsed1.mappings[0].token, parsed2.mappings[0].token);

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(tmp);
}

#[sqlx::test(migrations = "../../migrations")]
async fn status_and_revoked_export_blocks_resolution(pool: PgPool) {
    let (url, server) = serve(app(test_state(pool.clone()))).await;
    let user = seed_identity(&pool, "revoke@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, node2) = create_doc_with_nodes(&url, &auth, "Revoke Doc").await;
    let tmp = scratch_dir();
    let carrier_path = tmp.join("carrier.json");

    // Mint carrier
    let opts_mint = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Mint {
            document: doc_id,
            out: carrier_path.clone(),
            revision: Some(1),
            nodes: vec![node1.clone(), node2.clone()],
            idempotency_key: None,
        },
    };
    run(opts_mint).await.unwrap();
    let carrier_bytes = std::fs::read(&carrier_path).unwrap();
    let carrier: ExportTokensResponse = serde_json::from_slice(&carrier_bytes).unwrap();
    let export_id = carrier.export_id;

    // Check active status
    let opts_status1 = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Status {
            document: doc_id,
            export_id,
            json: true,
        },
    };
    run(opts_status1).await.unwrap();

    // Resolve successfully before revocation
    let opts_resolve1 = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Resolve {
            document: doc_id,
            carrier: Some(carrier_path.clone()),
            export_id: None,
            tokens: vec![],
            legacy_ids: vec![],
            json: true,
        },
    };
    run(opts_resolve1).await.unwrap();

    // Revoke export
    let opts_revoke = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Revoke {
            document: doc_id,
            export_id,
            json: true,
        },
    };
    run(opts_revoke).await.unwrap();

    // Check status after revocation
    let client = Client::new(&url, &auth, true).unwrap();
    let path = format!("documents/{doc_id}/export-tokens/{export_id}");
    let details: ExportDetailsResponse = client
        .send_json(Method::GET, &path, None, None)
        .await
        .unwrap();
    assert!(details.revoked_at.is_some());

    // Resolution after revocation fails with 403 Forbidden
    let opts_resolve2 = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Resolve {
            document: doc_id,
            carrier: Some(carrier_path.clone()),
            export_id: None,
            tokens: vec![],
            legacy_ids: vec![],
            json: true,
        },
    };
    let err_revoked = run(opts_resolve2).await.unwrap_err();
    assert!(
        err_revoked.to_string().contains("403"),
        "expected 403 forbidden on revoked export resolution, got: {err_revoked}"
    );

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(tmp);
}

#[sqlx::test(migrations = "../../migrations")]
async fn wrong_document_access_denied_or_not_found(pool: PgPool) {
    let (url, server) = serve(app(test_state(pool.clone()))).await;
    let user = seed_identity(&pool, "wrongdoc@example.com").await;
    let auth = bearer(user);

    let (doc1, node1, _node2) = create_doc_with_nodes(&url, &auth, "Doc 1").await;
    let (doc2, _node3, _node4) = create_doc_with_nodes(&url, &auth, "Doc 2").await;

    let tmp = scratch_dir();
    let carrier_path = tmp.join("carrier_doc1.json");

    let opts_mint = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Mint {
            document: doc1,
            out: carrier_path.clone(),
            revision: Some(1),
            nodes: vec![node1.clone()],
            idempotency_key: None,
        },
    };
    run(opts_mint).await.unwrap();
    let bytes = std::fs::read(&carrier_path).unwrap();
    let carrier: ExportTokensResponse = serde_json::from_slice(&bytes).unwrap();

    // 1. Passing doc1's carrier to doc2 resolve is rejected locally on document mismatch
    let opts_resolve_mismatch = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Resolve {
            document: doc2,
            carrier: Some(carrier_path.clone()),
            export_id: None,
            tokens: vec![],
            legacy_ids: vec![],
            json: true,
        },
    };
    let err_mismatch = run(opts_resolve_mismatch).await.unwrap_err();
    assert!(
        err_mismatch
            .to_string()
            .contains("carrier document ID mismatch"),
        "got: {err_mismatch}"
    );

    // 2. Querying status of doc1's export under doc2 returns 404
    let opts_status_wrong = Options {
        url: Some(url.clone()),
        remote: None,
        token_file: None,
        token: Some(auth.clone()),
        device_key: None,
        allow_loopback_http: true,
        action: Action::Status {
            document: doc2,
            export_id: carrier.export_id,
            json: true,
        },
    };
    let err_404 = run(opts_status_wrong).await.unwrap_err();
    assert!(
        err_404.to_string().contains("404"),
        "expected 404 not found, got: {err_404}"
    );

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(tmp);
}

#[sqlx::test(migrations = "../../migrations")]
async fn legacy_ids_preserved_and_deleted_targets_reported(pool: PgPool) {
    let (url, server) = serve(app(test_state(pool.clone()))).await;
    let user = seed_identity(&pool, "legacy@example.com").await;
    let auth = bearer(user);

    let (doc_id, node1, node2) = create_doc_with_nodes(&url, &auth, "Legacy Doc").await;

    // Delete node2 via batch op
    let client_http = reqwest::Client::new();
    let del_res = client_http
        .post(format!("{url}documents/{doc_id}/batch"))
        .bearer_auth(&auth)
        .json(&json!({
            "base_seq": 2,
            "ops": [
                {"type": "NodeDeleted", "node_id": node2}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(del_res.status(), StatusCode::OK);

    let unknown_legacy = "unknown_legacy_ID_12345";
    let client = Client::new(&url, &auth, true).unwrap();
    let req = ResolveExportTokensRequest {
        format: Some(CARRIER_FORMAT.to_string()),
        version: Some(CARRIER_VERSION),
        export_id: None,
        tokens: vec![],
        legacy_ids: vec![node1.clone(), node2.clone(), unknown_legacy.to_string()],
    };
    let path = format!("documents/{doc_id}/export-tokens/resolve");
    let resp: ResolveExportTokensResponse = client
        .send_json(
            Method::POST,
            &path,
            Some(&serde_json::to_value(&req).unwrap()),
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.items.len(), 3);

    // node1: live
    let target1 = &resp.items[0];
    assert_eq!(target1.legacy_id.as_deref(), Some(node1.as_str()));
    assert_eq!(target1.node_id.as_deref(), Some(node1.as_str()));
    assert!(!target1.deleted);
    assert!(target1.resolved);

    // node2: deleted
    let target2 = &resp.items[1];
    assert_eq!(target2.legacy_id.as_deref(), Some(node2.as_str()));
    assert_eq!(target2.node_id.as_deref(), Some(node2.as_str()));
    assert!(target2.deleted);
    assert!(target2.resolved);

    // unknown: unresolved, preserving exact spelling
    let target3 = &resp.items[2];
    assert_eq!(target3.legacy_id.as_deref(), Some(unknown_legacy));
    assert_eq!(target3.node_id, None);
    assert!(!target3.resolved);

    server.abort();
    let _ = server.await;
}
