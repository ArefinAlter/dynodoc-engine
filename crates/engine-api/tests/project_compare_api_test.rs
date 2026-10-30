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
    materializer::{CommentState, DocumentState, MaterializedNode},
    repository::{
        device::{Challenge, Proof},
        device_session::{SessionChallenge, SessionProof},
        Commit, FileEntry, SignedCommit,
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
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if !token.is_empty() {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
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

async fn device_session(
    app: &Router,
    project: Uuid,
    key: &Ed25519KeyPair,
    scopes: &[&str],
) -> (StatusCode, Value) {
    let (status, body) = request(
        app,
        "POST",
        &format!("/projects/{project}/device-sessions/challenge"),
        "",
        json!({"public_key": hex::encode(key.public_key().as_ref()), "scopes": scopes}),
    )
    .await;
    if status != StatusCode::OK {
        return (status, body);
    }
    let challenge: SessionChallenge = serde_json::from_value(body["challenge"].clone()).unwrap();
    let scopes_vec: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let proof = SessionProof::sign(
        challenge.clone(),
        body["mac"].as_str().unwrap().to_owned(),
        challenge.authority,
        project,
        &scopes_vec,
        key,
    )
    .unwrap();
    request(
        app,
        "POST",
        &format!("/projects/{project}/device-sessions"),
        "",
        json!(proof),
    )
    .await
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
    for chunk in objects.chunks(64) {
        ok(
            app,
            "POST",
            &format!("/projects/{project}/staging/objects"),
            login,
            json!({"document":doc,"objects":chunk}),
        )
        .await;
    }
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

#[sqlx::test(migrations = "../../migrations")]
async fn project_compare_file_api_classification(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (app, actor, login, project, doc1, key) = setup(&runtime.pool).await;

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

    let doc4: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Doc 4',$1,$2) returning id",
    )
    .bind(actor)
    .bind(project)
    .fetch_one(&runtime.pool)
    .await
    .unwrap();

    let (root1, obj1) = graph(doc1).await;
    let (root2, obj2) = graph(doc2).await;
    let (root3, obj3) = graph(doc3).await;
    let (root4, obj4) = graph(doc4).await;

    upload(&app, &login, project, doc1, &obj1).await;
    upload(&app, &login, project, doc2, &obj2).await;
    upload(&app, &login, project, doc3, &obj3).await;
    upload(&app, &login, project, doc4, &obj4).await;

    // Commit A has doc1.txt (doc1) and doc2.txt (doc2)
    let commit_a = signed_commit(
        project,
        &key,
        BTreeMap::from([
            (
                "doc1.txt".into(),
                FileEntry {
                    document: DocumentId(doc1),
                    state: root1.clone(),
                },
            ),
            (
                "doc2.txt".into(),
                FileEntry {
                    document: DocumentId(doc2),
                    state: root2.clone(),
                },
            ),
        ]),
        "Commit A",
    );
    let addr_a = publish_commit(&app, &login, project, &commit_a).await;

    // Commit B has doc2.txt (doc2), doc3.txt (doc3, added), and doc1.txt pointing to doc4 (replaced!)
    let commit_b = signed_commit(
        project,
        &key,
        BTreeMap::from([
            (
                "doc1.txt".into(),
                FileEntry {
                    document: DocumentId(doc4), // replaced document!
                    state: root4.clone(),
                },
            ),
            (
                "doc2.txt".into(),
                FileEntry {
                    document: DocumentId(doc2),
                    state: root2.clone(),
                },
            ),
            (
                "doc3.txt".into(),
                FileEntry {
                    document: DocumentId(doc3),
                    state: root3.clone(),
                },
            ),
        ]),
        "Commit B",
    );
    let addr_b = publish_commit(&app, &login, project, &commit_b).await;

    // 1. Added file: doc3.txt
    let url_added = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=doc3.txt",
        addr_a.as_str(),
        addr_b.as_str()
    );
    let rep_added = ok(&app, "GET", &url_added, &login, Value::Null).await;
    assert_eq!(rep_added["kind"], "added");
    assert!(rep_added["from_file"].is_null());
    assert_eq!(rep_added["to_file"]["document"], doc3.to_string());
    assert!(!rep_added
        .get("document_replaced")
        .and_then(Value::as_bool)
        .unwrap_or(false));
    assert!(rep_added["node_diff"].is_null());

    // 2. Removed file: compare from B to A for doc3.txt
    let url_removed = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=doc3.txt",
        addr_b.as_str(),
        addr_a.as_str()
    );
    let rep_removed = ok(&app, "GET", &url_removed, &login, Value::Null).await;
    assert_eq!(rep_removed["kind"], "removed");
    assert_eq!(rep_removed["from_file"]["document"], doc3.to_string());
    assert!(rep_removed["to_file"].is_null());
    assert!(!rep_removed
        .get("document_replaced")
        .and_then(Value::as_bool)
        .unwrap_or(false));
    assert!(rep_removed["node_diff"].is_null());

    // 3. Replaced document: doc1.txt (from doc1 to doc4)
    let url_replaced = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=doc1.txt",
        addr_a.as_str(),
        addr_b.as_str()
    );
    let rep_replaced = ok(&app, "GET", &url_replaced, &login, Value::Null).await;
    assert_eq!(rep_replaced["kind"], "modified");
    assert_eq!(rep_replaced["from_file"]["document"], doc1.to_string());
    assert_eq!(rep_replaced["to_file"]["document"], doc4.to_string());
    assert_eq!(rep_replaced["document_replaced"], true);
    assert!(rep_replaced["node_diff"].is_null());

    // 4. Same document unchanged: doc2.txt
    let url_unchanged = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=doc2.txt",
        addr_a.as_str(),
        addr_b.as_str()
    );
    let rep_unchanged = ok(&app, "GET", &url_unchanged, &login, Value::Null).await;
    assert_eq!(rep_unchanged["kind"], "unchanged");
    assert!(!rep_unchanged
        .get("document_replaced")
        .and_then(Value::as_bool)
        .unwrap_or(false));
    assert!(rep_unchanged["node_diff"].is_object());
    assert_eq!(rep_unchanged["node_diff"]["whole_state_identical"], true);

    // 5. Nonexistent file in both: nonexistent.txt -> 404
    let url_missing = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=nonexistent.txt",
        addr_a.as_str(),
        addr_b.as_str()
    );
    let (status, _) = request(&app, "GET", &url_missing, &login, Value::Null).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 6. Invalid file path: ../escape -> 400
    let url_invalid = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=../escape",
        addr_a.as_str(),
        addr_b.as_str()
    );
    let (status, _) = request(&app, "GET", &url_invalid, &login, Value::Null).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn project_compare_file_api_nodes_and_pagination(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (app, _actor, login, project, doc, key) = setup(&runtime.pool).await;

    let mut from_state = DocumentState::default();
    let mut to_state = DocumentState::default();

    // Create 15 nodes
    for i in 0..15 {
        let nid = NodeId(format!("node_{i:02}"));
        from_state.nodes.insert(
            nid.clone(),
            MaterializedNode {
                id: nid.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: format!("p{i:02}"),
                current_fields: json!({"text": format!("original {i}")}),
                var_name: None,
                deleted: false,
            },
        );

        // In to_state:
        // i < 10: modified text
        // 10 <= i < 13: deleted
        // 13 <= i < 15: unchanged
        if i < 10 {
            to_state.nodes.insert(
                nid.clone(),
                MaterializedNode {
                    id: nid.clone(),
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: format!("p{i:02}"),
                    current_fields: json!({"text": format!("modified {i}")}),
                    var_name: None,
                    deleted: false,
                },
            );
        } else if i < 13 {
            to_state.nodes.insert(
                nid.clone(),
                MaterializedNode {
                    id: nid.clone(),
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: format!("p{i:02}"),
                    current_fields: json!({"text": format!("original {i}")}),
                    var_name: None,
                    deleted: true,
                },
            );
        } else {
            to_state.nodes.insert(
                nid.clone(),
                MaterializedNode {
                    id: nid.clone(),
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: format!("p{i:02}"),
                    current_fields: json!({"text": format!("original {i}")}),
                    var_name: None,
                    deleted: false,
                },
            );
        }
    }

    // Add 2 new nodes in to_state
    for i in 15..17 {
        let nid = NodeId(format!("node_{i:02}"));
        to_state.nodes.insert(
            nid.clone(),
            MaterializedNode {
                id: nid.clone(),
                parent_id: None,
                node_type: "paragraph".into(),
                pos: format!("p{i:02}"),
                current_fields: json!({"text": format!("new {i}")}),
                var_name: None,
                deleted: false,
            },
        );
    }

    // Also add a comment in to_state
    to_state.comments.push(CommentState {
        node_id: None,
        body: "new comment".into(),
    });

    let (root_from, obj_from) = graph_with_state(doc, from_state).await;
    let (root_to, obj_to) = graph_with_state(doc, to_state).await;

    upload(&app, &login, project, doc, &obj_from).await;
    upload(&app, &login, project, doc, &obj_to).await;

    let commit_a = signed_commit(
        project,
        &key,
        BTreeMap::from([(
            "doc.txt".into(),
            FileEntry {
                document: DocumentId(doc),
                state: root_from.clone(),
            },
        )]),
        "Commit A",
    );
    let addr_a = publish_commit(&app, &login, project, &commit_a).await;

    let commit_b = signed_commit(
        project,
        &key,
        BTreeMap::from([(
            "doc.txt".into(),
            FileEntry {
                document: DocumentId(doc),
                state: root_to.clone(),
            },
        )]),
        "Commit B",
    );
    let addr_b = publish_commit(&app, &login, project, &commit_b).await;

    // Total changed nodes: 10 modified + 3 deleted + 2 added = 15 changes.
    // Plus 2 unchanged nodes.

    // Page 1: limit 5
    let url_p1 = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=doc.txt&limit=5",
        addr_a.as_str(),
        addr_b.as_str()
    );
    let p1 = ok(&app, "GET", &url_p1, &login, Value::Null).await;
    assert_eq!(p1["kind"], "modified");
    assert!(!p1
        .get("document_replaced")
        .and_then(Value::as_bool)
        .unwrap_or(false));
    assert_eq!(p1["node_diff"]["whole_state_identical"], false);
    assert_eq!(p1["node_diff"]["components"]["comments_changed"], true);
    assert_eq!(p1["node_diff"]["components"]["comments_to_count"], 1);
    assert_eq!(p1["node_diff"]["components"]["comments_from_count"], 0);
    assert_eq!(p1["node_diff"]["changes"].as_array().unwrap().len(), 5);
    assert_eq!(p1["more"], true);
    let c1 = p1["next_cursor"].as_str().unwrap();

    // Page 2: limit 5 with cursor
    let url_p2 = format!("{url_p1}&cursor={c1}");
    let p2 = ok(&app, "GET", &url_p2, &login, Value::Null).await;
    assert_eq!(p2["node_diff"]["changes"].as_array().unwrap().len(), 5);
    assert_eq!(p2["more"], true);
    let c2 = p2["next_cursor"].as_str().unwrap();

    // Page 3: limit 5 with cursor
    let url_p3 = format!("{url_p1}&cursor={c2}");
    let p3 = ok(&app, "GET", &url_p3, &login, Value::Null).await;
    assert_eq!(p3["node_diff"]["changes"].as_array().unwrap().len(), 5);
    assert_eq!(p3["more"], false);
    assert!(p3["next_cursor"].is_null());

    // Verify all 15 changes are unique
    let mut seen = std::collections::BTreeSet::new();
    for page in [&p1, &p2, &p3] {
        for change in page["node_diff"]["changes"].as_array().unwrap() {
            assert!(seen.insert(change["node_id"].as_str().unwrap().to_string()));
        }
    }
    assert_eq!(seen.len(), 15);

    // Test include_unchanged=true: totals includes the 2 unchanged nodes (17 changes in total)
    let url_unchanged = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=doc.txt&limit=100&include_unchanged=true",
        addr_a.as_str(),
        addr_b.as_str()
    );
    let rep_all = ok(&app, "GET", &url_unchanged, &login, Value::Null).await;
    assert_eq!(
        rep_all["node_diff"]["changes"].as_array().unwrap().len(),
        17
    );
    assert_eq!(rep_all["node_diff"]["totals"]["unchanged"], 2);

    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn project_compare_file_api_authorization_and_denial(pool: PgPool) {
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
    let url_valid = format!(
        "/projects/{project}/history/compare/file?from={}&to={}&path=doc.txt",
        addr_a.as_str(),
        addr_a.as_str()
    );

    // 1. Non-member denial -> 403
    let (status, _) = request(&app, "GET", &url_valid, &outsider_login, Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let key_id: Uuid = sqlx::query_scalar("select id from device_signing_key where public_key=$1")
        .bind(hex::encode(key.public_key().as_ref()))
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    sqlx::query("update device_key_access set project_access='all' where key_id=$1")
        .bind(key_id)
        .execute(&runtime.pool)
        .await
        .unwrap();

    // 2. Scoped device token with history:read -> 200
    let (status_dev, dev_body) = device_session(&app, project, &key, &["history:read"]).await;
    assert_eq!(status_dev, StatusCode::OK);
    let dev_token = dev_body["access_token"].as_str().unwrap();
    let (status, rep) = request(&app, "GET", &url_valid, dev_token, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rep["kind"], "unchanged");

    // 3. Scoped device token WITHOUT history:read (e.g. project:read only) -> 403
    let (status_dev_bad, dev_body_bad) =
        device_session(&app, project, &key, &["project:read"]).await;
    assert_eq!(status_dev_bad, StatusCode::OK);
    let bad_dev_token = dev_body_bad["access_token"].as_str().unwrap();
    let (status, _) = request(&app, "GET", &url_valid, bad_dev_token, Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 4. Revoked device key -> 401
    let (status_revoke, _) = request(
        &app,
        "POST",
        &format!("/devices/{key_id}/revoke"),
        &login,
        json!({}),
    )
    .await;
    assert_eq!(status_revoke, StatusCode::OK);

    let (status, _) = request(&app, "GET", &url_valid, dev_token, Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 5. Cursor tampering -> 400
    let bad_cursor_url = format!("{url_valid}&cursor=invalid_hex_cursor");
    let (status, _) = request(&app, "GET", &bad_cursor_url, &login, Value::Null).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 6. Corrupt object in checkpoint_object -> 400
    // Mutate the bytes of the published state root object under replica role to bypass immutability trigger
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("set session_replication_role = 'replica'")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("update checkpoint_object set bytes = $1 where document_id=$2 and address=$3")
        .bind(b"corrupted bytes".to_vec())
        .bind(doc)
        .bind(root.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("set session_replication_role = 'origin'")
        .execute(&mut *conn)
        .await
        .unwrap();

    let (status, _) = request(&app, "GET", &url_valid, &login, Value::Null).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    runtime.close().await;
}
