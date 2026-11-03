//! Integration tests for GET /projects/{id}/history/compare (NEXT-04).

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use engine_api::{
    app,
    auth::{store, token, AuthConfig},
    AppState,
};
use engine_core::{
    materializer::{CommentState, DocumentState},
    repository::{
        device::{Challenge, Proof},
        Commit, FileEntry, SignedCommit,
    },
    shared_checkpoint::{typed, Address, Limits, MemoryStore, ObjectStore},
};
use engine_shared::DocumentId;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;
use tower::ServiceExt;
use uuid::Uuid;

mod common;

const KEY: [u8; 32] = [9; 32];

fn router(pool: PgPool) -> Router {
    let mut state = AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.ref_signer = Some(std::sync::Arc::new(
        Ed25519KeyPair::from_seed_unchecked(&[99; 32]).unwrap(),
    ));
    app(state)
}

async fn new_actor(pool: &PgPool, name: &str) -> (Uuid, String) {
    let id = store::upsert_identity(pool, &format!("{name}@example.test"), None)
        .await
        .unwrap()
        .id
        .0;
    (id, token::mint(&KEY, id, 3600).unwrap())
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn ok(app: &Router, method: &str, path: &str, token: &str, body: Value) -> Value {
    let (status, result) = request(app, method, path, token, body).await;
    assert_eq!(status, StatusCode::OK, "{path}: {result}");
    result
}

async fn setup(pool: &PgPool) -> (Router, Uuid, String, Uuid, Uuid, Ed25519KeyPair) {
    let app = router(pool.clone());
    let (actor, login) = new_actor(pool, "owner").await;
    let project: Uuid = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/projects",
            &login,
            json!({"name":"Compare Test Project"}),
        )
        .await["id"]
            .clone(),
    )
    .unwrap();
    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Doc 1',$1,$2) returning id",
    )
    .bind(actor)
    .bind(project)
    .fetch_one(pool)
    .await
    .unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let challenge: Challenge = serde_json::from_value(
        ok(
            &app,
            "POST",
            "/devices/challenge",
            &login,
            json!({"public_key":hex::encode(key.public_key().as_ref())}),
        )
        .await,
    )
    .unwrap();
    let proof = Proof::sign(challenge.clone(), challenge.authority, actor, &key).unwrap();
    ok(&app, "POST", "/devices", &login, json!(proof)).await;
    (app, actor, login, project, doc, key)
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

async fn graph(doc: Uuid) -> (Address, Vec<Value>) {
    graph_with_state(doc, DocumentState::default()).await
}

async fn graph_with_state(doc: Uuid, state: DocumentState) -> (Address, Vec<Value>) {
    let mut store = Collect::default();
    let (root, _) = typed::write_state(
        &mut store,
        DocumentId(doc),
        &state,
        Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();
    let objects = store
        .objects
        .iter()
        .map(|(address, bytes)| json!({"address":address,"bytes":STANDARD.encode(bytes)}))
        .collect();
    (root, objects)
}

async fn upload(app: &Router, login: &str, project: Uuid, doc: Uuid, objects: &[Value]) {
    ok(
        app,
        "POST",
        &format!("/projects/{project}/staging/objects"),
        login,
        json!({"document":doc,"objects":objects}),
    )
    .await;
}

async fn publish_commit(
    app: &Router,
    login: &str,
    project: Uuid,
    signed: &SignedCommit,
) -> Address {
    ok(
        app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        login,
        json!(signed),
    )
    .await;
    let address = signed.verify().unwrap();
    ok(
        app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        login,
        json!({"address":address}),
    )
    .await;
    address
}

fn signed_commit(
    project: Uuid,
    key: &Ed25519KeyPair,
    files: BTreeMap<String, FileEntry>,
    message: &str,
) -> SignedCommit {
    SignedCommit::sign(
        Commit {
            version: 1,
            project,
            parents: vec![],
            files,
            author_key: String::new(),
            authored_at_ms: 1_700_000_000_000,
            message: message.into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        key,
    )
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn project_compare_api_happy_path_and_pagination(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (app, actor, login, project, doc1, key) = setup(&runtime.pool).await;

    // Create doc2 and doc3 in the same project
    let doc2: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Doc 2',$1,$2) returning id",
    )
    .bind(actor)
    .bind(project)
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    let doc3: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Doc 3',$1,$2) returning id",
    )
    .bind(actor)
    .bind(project)
    .fetch_one(&runtime.pool)
    .await
    .unwrap();

    let (root1_a, objects1_a) = graph(doc1).await;
    let (root2_a, objects2_a) = graph(doc2).await;
    upload(&app, &login, project, doc1, &objects1_a).await;
    upload(&app, &login, project, doc2, &objects2_a).await;

    // Commit A has doc1 and doc2
    let commit_a = signed_commit(
        project,
        &key,
        BTreeMap::from([
            (
                "doc1.txt".into(),
                FileEntry {
                    document: DocumentId(doc1),
                    state: root1_a.clone(),
                },
            ),
            (
                "doc2.txt".into(),
                FileEntry {
                    document: DocumentId(doc2),
                    state: root2_a.clone(),
                },
            ),
        ]),
        "Commit A",
    );
    let addr_a = publish_commit(&app, &login, project, &commit_a).await;

    // Generate root for doc3 and an edited root for doc1
    let (root3_b, objects3_b) = graph(doc3).await;
    let mut state1_b = DocumentState::default();
    state1_b.comments.push(CommentState {
        node_id: None,
        body: "updated comment".into(),
    });
    let (root1_b, objects1_b) = graph_with_state(doc1, state1_b).await;
    upload(&app, &login, project, doc3, &objects3_b).await;
    upload(&app, &login, project, doc1, &objects1_b).await;

    // Commit B has doc1 (modified), doc3 (added); doc2 is removed
    let commit_b = signed_commit(
        project,
        &key,
        BTreeMap::from([
            (
                "doc1.txt".into(),
                FileEntry {
                    document: DocumentId(doc1),
                    state: root1_b.clone(),
                },
            ),
            (
                "doc3.txt".into(),
                FileEntry {
                    document: DocumentId(doc3),
                    state: root3_b.clone(),
                },
            ),
        ]),
        "Commit B",
    );
    let addr_b = publish_commit(&app, &login, project, &commit_b).await;

    // 1. Full comparison
    let compare_url = format!(
        "/projects/{project}/history/compare?from={}&to={}",
        addr_a.as_str(),
        addr_b.as_str()
    );
    let report = ok(&app, "GET", &compare_url, &login, Value::Null).await;

    assert_eq!(report["project"], project.to_string());
    assert_eq!(report["from"], addr_a.as_str());
    assert_eq!(report["to"], addr_b.as_str());
    assert_eq!(report["totals"]["added"], 1);
    assert_eq!(report["totals"]["removed"], 1);
    assert_eq!(report["totals"]["modified"], 1);
    assert_eq!(report["totals"]["total_changes"], 3);
    assert_eq!(report["changes"].as_array().unwrap().len(), 3);
    assert_eq!(report["more"], false);
    assert!(report["next_cursor"].is_null());

    // 2. Pagination with limit=1
    let p1_url = format!("{compare_url}&limit=1");
    let p1 = ok(&app, "GET", &p1_url, &login, Value::Null).await;
    assert_eq!(p1["changes"].as_array().unwrap().len(), 1);
    assert_eq!(p1["more"], true);
    let c1 = p1["next_cursor"].as_str().expect("cursor 1");

    let p2_url = format!("{compare_url}&limit=1&cursor={c1}");
    let p2 = ok(&app, "GET", &p2_url, &login, Value::Null).await;
    assert_eq!(p2["changes"].as_array().unwrap().len(), 1);
    assert_eq!(p2["more"], true);
    let c2 = p2["next_cursor"].as_str().expect("cursor 2");

    let p3_url = format!("{compare_url}&limit=1&cursor={c2}");
    let p3 = ok(&app, "GET", &p3_url, &login, Value::Null).await;
    assert_eq!(p3["changes"].as_array().unwrap().len(), 1);
    assert_eq!(p3["more"], false);
    assert!(p3["next_cursor"].is_null());

    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn project_compare_api_authorization_and_denial(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (app, _actor, login, project, doc, key) = setup(&runtime.pool).await;

    let (root, objects) = graph(doc).await;
    upload(&app, &login, project, doc, &objects).await;

    let commit_a = signed_commit(
        project,
        &key,
        BTreeMap::from([(
            "doc.txt".into(),
            FileEntry {
                document: DocumentId(doc),
                state: root.clone(),
            },
        )]),
        "Commit A",
    );
    let addr_a = publish_commit(&app, &login, project, &commit_a).await;

    let (_outsider_id, outsider_login) = new_actor(&runtime.pool, "outsider").await;
    let random_addr = "11".repeat(32);

    // 1. Non-member denial on valid published commits -> 403 Forbidden
    let compare_url = format!(
        "/projects/{project}/history/compare?from={}&to={}",
        addr_a.as_str(),
        addr_a.as_str()
    );
    let (status, _) = request(&app, "GET", &compare_url, &outsider_login, Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 2. Non-member denial on non-existent commit address -> STILL 403 Forbidden (no existence oracle!)
    let missing_url = format!(
        "/projects/{project}/history/compare?from={}&to={}",
        random_addr, random_addr
    );
    let (status, _) = request(&app, "GET", &missing_url, &outsider_login, Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 3. Member requesting unpublished/non-existent commit -> 404 Not Found
    let (status, _) = request(&app, "GET", &missing_url, &login, Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 4. Staged commit that was never published to /history/commits -> 404 Not Found
    let unpublished_commit = signed_commit(project, &key, BTreeMap::new(), "Unpublished");
    ok(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &login,
        json!(unpublished_commit),
    )
    .await;
    let unpub_addr = unpublished_commit.verify().unwrap();
    let unpub_url = format!(
        "/projects/{project}/history/compare?from={}&to={}",
        addr_a.as_str(),
        unpub_addr.as_str()
    );
    let (status, _) = request(&app, "GET", &unpub_url, &login, Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 5. Malformed cursor -> 400 Bad Request
    let bad_cursor_url = format!("{compare_url}&cursor=invalid_hex_cursor");
    let (status, _) = request(&app, "GET", &bad_cursor_url, &login, Value::Null).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    runtime.close().await;
}
