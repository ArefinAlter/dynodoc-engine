//! Named multi-file releases through the real router and database.
//! See PR-115 in ENGINE-PR-PLAN.md.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine};
use engine_api::auth::{store as auth_store, token, AuthConfig};
use engine_api::{app, AppState};
use engine_core::{
    materializer::DocumentState,
    repository::{
        device::{Challenge, Proof},
        server_authority, Commit, FileEntry, SignedCommit,
    },
    shared_checkpoint::{typed, Address, Limits, MemoryStore, ObjectStore},
};
use engine_shared::{DocumentId, NodeId};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;
use tower::ServiceExt;
use uuid::Uuid;

mod common;

const KEY: [u8; 32] = [9u8; 32];

fn signer(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn public(seed: u8) -> String {
    hex::encode(signer(seed).public_key().as_ref())
}

fn router(pool: PgPool, seed: Option<u8>) -> Router {
    let mut state = AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.ref_signer = seed.map(|s| std::sync::Arc::new(signer(s)));
    app(state)
}

async fn person(pool: &PgPool, email: &str) -> (String, Uuid) {
    let id = auth_store::upsert_identity(pool, email, None)
        .await
        .unwrap()
        .id
        .0;
    (
        format!("Bearer {}", token::mint(&KEY, id, 3600).unwrap()),
        id,
    )
}

async fn call(
    router: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if !token.is_empty() {
        req = req.header(header::AUTHORIZATION, token);
    }
    let req = match body {
        Some(body) => req
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn ok(router: &Router, method: &str, uri: &str, token: &str, body: Option<Value>) -> Value {
    let (status, result) = call(router, method, uri, token, body).await;
    assert_eq!(status, StatusCode::OK, "{uri}: {result}");
    result
}

#[derive(Default)]
struct Collect {
    inner: MemoryStore,
    objects: BTreeMap<Address, Vec<u8>>,
}

impl ObjectStore for Collect {
    async fn put(
        &mut self,
        doc: DocumentId,
        address: &Address,
        bytes: &[u8],
    ) -> Result<bool, engine_core::shared_checkpoint::Error> {
        self.objects.insert(address.clone(), bytes.to_vec());
        self.inner.put(doc, address, bytes).await
    }
    async fn get(
        &mut self,
        doc: DocumentId,
        address: &Address,
    ) -> Result<Vec<u8>, engine_core::shared_checkpoint::Error> {
        self.inner.get(doc, address).await
    }
}

fn doc_state(text: &str) -> DocumentState {
    let node = engine_core::materializer::MaterializedNode {
        id: NodeId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        parent_id: None,
        node_type: "paragraph".into(),
        pos: "a0".into(),
        var_name: None,
        deleted: false,
        current_fields: json!({"label": text, "runs":[{"text": text}]}),
    };
    DocumentState {
        nodes: BTreeMap::from([(node.id.clone(), node)]),
        ..Default::default()
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_file_release_recovery_after_later_main_and_file_edits(pool: PgPool) {
    let app = router(pool.clone(), Some(1));
    let (owner_token, owner_id) = person(&pool, "owner@example.test").await;

    // Install ref authority
    server_authority::install(&pool, &public(1)).await.unwrap();

    // Create project and two documents
    let project: Uuid = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/projects",
            &owner_token,
            Some(json!({"name":"Release Project"})),
        )
        .await["id"]
            .clone(),
    )
    .unwrap();

    let doc1: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('File 1',$1,$2) returning id",
    )
    .bind(owner_id)
    .bind(project)
    .fetch_one(&pool)
    .await
    .unwrap();

    let doc2: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('File 2',$1,$2) returning id",
    )
    .bind(owner_id)
    .bind(project)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Enroll device
    let key = signer(7);
    let challenge: Challenge = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/devices/challenge",
            &owner_token,
            Some(json!({"public_key": public(7)})),
        )
        .await,
    )
    .unwrap();
    let proof = Proof::sign(challenge.clone(), challenge.authority, owner_id, &key).unwrap();
    ok(&app, "POST", "/devices", &owner_token, Some(json!(proof))).await;

    // Write initial state objects for both files
    let mut store = Collect::default();
    let (root1, _) = typed::write_state(
        &mut store,
        DocumentId(doc1),
        &doc_state("Doc 1 V1"),
        Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();
    let (root2, _) = typed::write_state(
        &mut store,
        DocumentId(doc2),
        &doc_state("Doc 2 V1"),
        Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();

    let objects1: Vec<Value> = store
        .objects
        .iter()
        .map(|(address, bytes)| json!({"address": address, "bytes": STANDARD.encode(bytes)}))
        .collect();

    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/objects"),
        &owner_token,
        Some(json!({"document": doc1, "objects": objects1})),
    )
    .await;

    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/objects"),
        &owner_token,
        Some(json!({"document": doc2, "objects": objects1})),
    )
    .await;

    // Commit 1 on main (contains both files)
    let commit1 = SignedCommit::sign(
        Commit {
            version: 1,
            project,
            parents: Vec::new(),
            files: BTreeMap::from([
                (
                    "file1.docx".into(),
                    FileEntry {
                        document: DocumentId(doc1),
                        state: root1.clone(),
                    },
                ),
                (
                    "file2.docx".into(),
                    FileEntry {
                        document: DocumentId(doc2),
                        state: root2.clone(),
                    },
                ),
            ]),
            author_key: String::new(),
            authored_at_ms: 100,
            message: "Initial release commit".into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        &key,
    )
    .unwrap();

    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &owner_token,
        Some(json!(commit1)),
    )
    .await;
    let commit1_addr = commit1.verify().unwrap();

    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &owner_token,
        Some(json!({"address": commit1_addr})),
    )
    .await;

    // Advance main to commit 1
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/refs"),
        &owner_token,
        Some(json!({
            "branch": "main",
            "candidate": commit1_addr,
            "expected": null
        })),
    )
    .await;

    // 1. Create named release v1.0.0
    let rel_res = ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/releases"),
        &owner_token,
        Some(json!({
            "name": "v1.0.0",
            "commit": commit1_addr
        })),
    )
    .await;
    assert_eq!(rel_res["name"], "v1.0.0");
    assert_eq!(rel_res["commit"], commit1_addr.as_str());

    // 2. Modify doc1 and publish Commit 2 on main
    let mut store2 = Collect::default();
    let (root1_v2, _) = typed::write_state(
        &mut store2,
        DocumentId(doc1),
        &doc_state("Doc 1 V2 Updated"),
        Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();
    let objects2: Vec<Value> = store2
        .objects
        .iter()
        .map(|(address, bytes)| json!({"address": address, "bytes": STANDARD.encode(bytes)}))
        .collect();

    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/objects"),
        &owner_token,
        Some(json!({"document": doc1, "objects": objects2})),
    )
    .await;

    let commit2 = SignedCommit::sign(
        Commit {
            version: 1,
            project,
            parents: vec![commit1_addr.clone()],
            files: BTreeMap::from([
                (
                    "file1.docx".into(),
                    FileEntry {
                        document: DocumentId(doc1),
                        state: root1_v2.clone(),
                    },
                ),
                (
                    "file2.docx".into(),
                    FileEntry {
                        document: DocumentId(doc2),
                        state: root2.clone(),
                    },
                ),
            ]),
            author_key: String::new(),
            authored_at_ms: 200,
            message: "Second commit on main".into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        &key,
    )
    .unwrap();

    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &owner_token,
        Some(json!(commit2)),
    )
    .await;
    let commit2_addr = commit2.verify().unwrap();

    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &owner_token,
        Some(json!({"address": commit2_addr})),
    )
    .await;

    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/refs"),
        &owner_token,
        Some(json!({
            "branch": "main",
            "candidate": commit2_addr,
            "expected": {"commit": commit1_addr, "generation": 1}
        })),
    )
    .await;

    // 3. Verify release v1.0.0 still points to commit 1 and recovers both files
    let list_res = ok(
        &app,
        "GET",
        &format!("/projects/{project}/history/releases"),
        &owner_token,
        None,
    )
    .await;
    assert_eq!(list_res["items"].as_array().unwrap().len(), 1);
    assert_eq!(list_res["items"][0]["name"], "v1.0.0");
    assert_eq!(list_res["items"][0]["commit"], commit1_addr.as_str());

    let get_res = ok(
        &app,
        "GET",
        &format!("/projects/{project}/history/releases/v1.0.0"),
        &owner_token,
        None,
    )
    .await;
    assert_eq!(get_res["name"], "v1.0.0");
    assert_eq!(get_res["commit"], commit1_addr.as_str());
    let scope: Vec<Uuid> = serde_json::from_value(get_res["scope"].clone()).unwrap();
    assert!(scope.contains(&doc1));
    assert!(scope.contains(&doc2));

    // Client reads the commit manifest at commit1
    let c1_envelope = ok(
        &app,
        "GET",
        &format!(
            "/projects/{project}/history/commits/{}",
            commit1_addr.as_str()
        ),
        &owner_token,
        None,
    )
    .await;
    let loaded_commit: SignedCommit = serde_json::from_value(c1_envelope).unwrap();
    assert_eq!(loaded_commit.commit.files["file1.docx"].state, root1);
    assert_eq!(loaded_commit.commit.files["file2.docx"].state, root2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn duplicate_and_concurrent_naming_rules(pool: PgPool) {
    let app = router(pool.clone(), Some(1));
    let (owner_token, owner_id) = person(&pool, "owner@example.test").await;
    server_authority::install(&pool, &public(1)).await.unwrap();

    let project: Uuid = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/projects",
            &owner_token,
            Some(json!({"name":"Release Project 2"})),
        )
        .await["id"]
            .clone(),
    )
    .unwrap();

    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('File',$1,$2) returning id",
    )
    .bind(owner_id)
    .bind(project)
    .fetch_one(&pool)
    .await
    .unwrap();

    let key = signer(7);
    let challenge: Challenge = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/devices/challenge",
            &owner_token,
            Some(json!({"public_key": public(7)})),
        )
        .await,
    )
    .unwrap();
    let proof = Proof::sign(challenge.clone(), challenge.authority, owner_id, &key).unwrap();
    ok(&app, "POST", "/devices", &owner_token, Some(json!(proof))).await;

    let mut store = Collect::default();
    let (root, _) = typed::write_state(
        &mut store,
        DocumentId(doc),
        &doc_state("Doc"),
        Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();
    let objects: Vec<Value> = store
        .objects
        .iter()
        .map(|(address, bytes)| json!({"address": address, "bytes": STANDARD.encode(bytes)}))
        .collect();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/objects"),
        &owner_token,
        Some(json!({"document": doc, "objects": objects})),
    )
    .await;

    let commit1 = SignedCommit::sign(
        Commit {
            version: 1,
            project,
            parents: Vec::new(),
            files: BTreeMap::from([(
                "file.docx".into(),
                FileEntry {
                    document: DocumentId(doc),
                    state: root.clone(),
                },
            )]),
            author_key: String::new(),
            authored_at_ms: 100,
            message: "Commit 1".into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        &key,
    )
    .unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &owner_token,
        Some(json!(commit1)),
    )
    .await;
    let commit1_addr = commit1.verify().unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &owner_token,
        Some(json!({"address": commit1_addr})),
    )
    .await;
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/refs"),
        &owner_token,
        Some(json!({
            "branch": "main",
            "candidate": commit1_addr,
            "expected": null
        })),
    )
    .await;

    // Invalid release names
    for bad_name in [
        "",
        "has space",
        "/bad",
        ".leadingdot",
        "-hyphenfirst",
        "name@bad!",
    ] {
        let (status, _) = call(
            &app,
            "POST",
            &format!("/projects/{project}/history/releases"),
            &owner_token,
            Some(json!({"name": bad_name})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "expected 400 for bad name {bad_name}"
        );
    }

    // Create v1.0
    let (status, _) = call(
        &app,
        "POST",
        &format!("/projects/{project}/history/releases"),
        &owner_token,
        Some(json!({"name": "v1.0"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Idempotent retry with same name and same commit -> 200 OK
    let (status, res) = call(
        &app,
        "POST",
        &format!("/projects/{project}/history/releases"),
        &owner_token,
        Some(json!({"name": "v1.0", "commit": commit1_addr})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["name"], "v1.0");

    // Advance main to Commit 2
    let commit2 = SignedCommit::sign(
        Commit {
            version: 1,
            project,
            parents: vec![commit1_addr.clone()],
            files: BTreeMap::from([(
                "file.docx".into(),
                FileEntry {
                    document: DocumentId(doc),
                    state: root.clone(),
                },
            )]),
            author_key: String::new(),
            authored_at_ms: 200,
            message: "Commit 2".into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        &key,
    )
    .unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &owner_token,
        Some(json!(commit2)),
    )
    .await;
    let commit2_addr = commit2.verify().unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &owner_token,
        Some(json!({"address": commit2_addr})),
    )
    .await;
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/refs"),
        &owner_token,
        Some(json!({
            "branch": "main",
            "candidate": commit2_addr,
            "expected": {"commit": commit1_addr, "generation": 1}
        })),
    )
    .await;

    // Retry existing name v1.0 pointing to different commit -> 409 Conflict
    let (status, res) = call(
        &app,
        "POST",
        &format!("/projects/{project}/history/releases"),
        &owner_token,
        Some(json!({"name": "v1.0", "commit": commit2_addr})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{res}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn review_bypass_and_merge_authority_enforced(pool: PgPool) {
    let app = router(pool.clone(), Some(1));
    let (owner_token, owner_id) = person(&pool, "owner@example.test").await;
    let (contributor_token, contributor_id) = person(&pool, "contrib@example.test").await;
    server_authority::install(&pool, &public(1)).await.unwrap();

    let project: Uuid = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/projects",
            &owner_token,
            Some(json!({"name":"Protected Project"})),
        )
        .await["id"]
            .clone(),
    )
    .unwrap();

    // Add contributor as Viewer on project (no merge authority)
    sqlx::query("insert into space_member(space_id, identity_id, role) values($1, $2, 'viewer')")
        .bind(project)
        .bind(contributor_id)
        .execute(&pool)
        .await
        .unwrap();

    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('File',$1,$2) returning id",
    )
    .bind(owner_id)
    .bind(project)
    .fetch_one(&pool)
    .await
    .unwrap();

    let key = signer(7);
    let challenge: Challenge = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/devices/challenge",
            &owner_token,
            Some(json!({"public_key": public(7)})),
        )
        .await,
    )
    .unwrap();
    let proof = Proof::sign(challenge.clone(), challenge.authority, owner_id, &key).unwrap();
    ok(&app, "POST", "/devices", &owner_token, Some(json!(proof))).await;

    let mut store = Collect::default();
    let (root, _) = typed::write_state(
        &mut store,
        DocumentId(doc),
        &doc_state("Protected Doc"),
        Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();
    let objects: Vec<Value> = store
        .objects
        .iter()
        .map(|(address, bytes)| json!({"address": address, "bytes": STANDARD.encode(bytes)}))
        .collect();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/objects"),
        &owner_token,
        Some(json!({"document": doc, "objects": objects})),
    )
    .await;

    let main_commit = SignedCommit::sign(
        Commit {
            version: 1,
            project,
            parents: Vec::new(),
            files: BTreeMap::from([(
                "file.docx".into(),
                FileEntry {
                    document: DocumentId(doc),
                    state: root.clone(),
                },
            )]),
            author_key: String::new(),
            authored_at_ms: 100,
            message: "Main commit".into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        &key,
    )
    .unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &owner_token,
        Some(json!(main_commit)),
    )
    .await;
    let main_commit_addr = main_commit.verify().unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &owner_token,
        Some(json!({"address": main_commit_addr})),
    )
    .await;
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/refs"),
        &owner_token,
        Some(json!({
            "branch": "main",
            "candidate": main_commit_addr,
            "expected": null
        })),
    )
    .await;

    // Feature commit (not on main)
    let feature_commit = SignedCommit::sign(
        Commit {
            version: 1,
            project,
            parents: vec![main_commit_addr.clone()],
            files: BTreeMap::from([(
                "file.docx".into(),
                FileEntry {
                    document: DocumentId(doc),
                    state: root.clone(),
                },
            )]),
            author_key: String::new(),
            authored_at_ms: 150,
            message: "Unreviewed feature candidate".into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        &key,
    )
    .unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &owner_token,
        Some(json!(feature_commit)),
    )
    .await;
    let feature_commit_addr = feature_commit.verify().unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &owner_token,
        Some(json!({"address": feature_commit_addr})),
    )
    .await;

    // Attempting to release unreviewed feature candidate (bypassing main) -> 400 Bad Request
    let (status, res) = call(
        &app,
        "POST",
        &format!("/projects/{project}/history/releases"),
        &owner_token,
        Some(json!({"name": "v1.0-bypass", "commit": feature_commit_addr})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "bypassing main should be refused: {res}"
    );

    // Contributor (viewer) trying to create a release -> 403 Forbidden
    let (status, res) = call(
        &app,
        "POST",
        &format!("/projects/{project}/history/releases"),
        &contributor_token,
        Some(json!({"name": "v1.0-unauthorized"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer lacking merge authority should be forbidden: {res}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn quota_rollback_on_budget_exceeded(pool: PgPool) {
    let app = router(pool.clone(), Some(1));
    let (owner_token, owner_id) = person(&pool, "owner@example.test").await;
    server_authority::install(&pool, &public(1)).await.unwrap();

    let project: Uuid = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/projects",
            &owner_token,
            Some(json!({"name":"Quota Project"})),
        )
        .await["id"]
            .clone(),
    )
    .unwrap();

    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('File',$1,$2) returning id",
    )
    .bind(owner_id)
    .bind(project)
    .fetch_one(&pool)
    .await
    .unwrap();

    let key = signer(7);
    let challenge: Challenge = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/devices/challenge",
            &owner_token,
            Some(json!({"public_key": public(7)})),
        )
        .await,
    )
    .unwrap();
    let proof = Proof::sign(challenge.clone(), challenge.authority, owner_id, &key).unwrap();
    ok(&app, "POST", "/devices", &owner_token, Some(json!(proof))).await;

    let mut store = Collect::default();
    let (root, _) = typed::write_state(
        &mut store,
        DocumentId(doc),
        &doc_state("Doc"),
        Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();
    let objects: Vec<Value> = store
        .objects
        .iter()
        .map(|(address, bytes)| json!({"address": address, "bytes": STANDARD.encode(bytes)}))
        .collect();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/objects"),
        &owner_token,
        Some(json!({"document": doc, "objects": objects})),
    )
    .await;

    let commit = SignedCommit::sign(
        Commit {
            version: 1,
            project,
            parents: Vec::new(),
            files: BTreeMap::from([(
                "file.docx".into(),
                FileEntry {
                    document: DocumentId(doc),
                    state: root.clone(),
                },
            )]),
            author_key: String::new(),
            authored_at_ms: 100,
            message: "Commit".into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        &key,
    )
    .unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &owner_token,
        Some(json!(commit)),
    )
    .await;
    let commit_addr = commit.verify().unwrap();
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &owner_token,
        Some(json!({"address": commit_addr})),
    )
    .await;
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/history/refs"),
        &owner_token,
        Some(json!({
            "branch": "main",
            "candidate": commit_addr,
            "expected": null
        })),
    )
    .await;

    // Artificially saturate rows_used in project_history_storage
    sqlx::query("update project_history_storage set rows_used = row_limit where project_id = $1")
        .bind(project)
        .execute(&pool)
        .await
        .unwrap();

    // Attempt to create release -> 507 Insufficient Storage
    let (status, res) = call(
        &app,
        "POST",
        &format!("/projects/{project}/history/releases"),
        &owner_token,
        Some(json!({"name": "v1.0-overflow"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INSUFFICIENT_STORAGE,
        "quota exceeded should return 507: {res}"
    );

    // Verify release table has 0 rows and transaction rolled back
    let count: i64 =
        sqlx::query_scalar("select count(*) from project_release where project_id = $1")
            .bind(project)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0, "quota rollback must leave no partial release row");
}

#[sqlx::test(migrations = "../../migrations")]
async fn project_release_runtime_privileges_are_verified(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    engine_core::database::check_runtime(&runtime.pool)
        .await
        .unwrap();
    runtime.close().await;
}
