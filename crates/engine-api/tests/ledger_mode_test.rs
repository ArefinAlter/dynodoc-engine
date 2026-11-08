//! Ledger mode (decisions 025 and 028) through the real router: the storage choice (owner or
//! manager, audited, fixed at the first commit), hash-only first commits, block hashes on
//! every changed block, the manifest root, direct writes refused, images by hash only, the
//! member relay (connector auth, membership, size caps, deletion after delivery, expiry) and
//! the storage report after 200 commits beside the file size.
//! Requires a reachable Postgres (DATABASE_URL), like the other API integration tests.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine};
use engine_api::auth::{store as auth_store, token, AuthConfig};
use engine_api::{app, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod common;

const KEY: [u8; 32] = [7u8; 32];
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDRsynthetic-image-bytes";

fn test_state(pool: PgPool) -> AppState {
    AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    )
}
async fn identity(pool: &PgPool, email: &str) -> String {
    let id = auth_store::upsert_identity(pool, email, Some("Tester"))
        .await
        .unwrap()
        .id
        .0;
    format!("Bearer {}", token::mint(&KEY, id, 3600).unwrap())
}
async fn call(
    router: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, token);
    if body.is_some() {
        req = req.header("content-type", "application/json");
    }
    let req = req
        .body(body.map_or(Body::empty(), |b| {
            Body::from(serde_json::to_vec(&b).unwrap())
        }))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn post(router: &Router, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
    call(router, "POST", uri, token, Some(body)).await
}
async fn get(router: &Router, uri: &str, token: &str) -> (StatusCode, Value) {
    call(router, "GET", uri, token, None).await
}
fn hash(seed: &str) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, seed.as_bytes()))
}
fn native(xml: &str) -> Value {
    json!({"host":"word","v":1,"xml":xml,"media":[],"content_hash":"0".repeat(64)})
}
fn para(text: &str) -> Value {
    json!({"type":"paragraph","content":[{"type":"text","text":text}]})
}
fn ulid() -> String {
    ulid::Ulid::generate().to_string()
}

struct Seat {
    web: String,
    pane: String,
}
/// A document with its root only, a colleague as editor and both panes connected;
/// `ledger` chooses the storage mode first.
async fn setup(
    router: &Router,
    pool: &PgPool,
    tag: &str,
    ledger: bool,
) -> (Uuid, String, Seat, Seat) {
    let owner = identity(pool, &format!("{tag}-owner@example.test")).await;
    let colleague = identity(pool, &format!("{tag}-colleague@example.test")).await;
    let (status, body) = post(
        router,
        "/documents",
        &owner,
        json!({"title":"Ledger report"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    let (status, body) = post(
        router,
        &format!("/documents/{doc}/metadata"),
        &owner,
        json!({"settings":{"kind":"document"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let root = ulid();
    let (status, body) = post(
        router,
        &format!("/documents/{doc}/batch"),
        &owner,
        json!({"base_seq":0,"ops":[{"type":"NodeCreated","node_id":root,"node_type":"form","pos":"000000","fields":{"label":"Report"}}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post(
        router,
        &format!("/documents/{doc}/members"),
        &owner,
        json!({"email":format!("{tag}-colleague@example.test"),"role":"editor"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    if ledger {
        let (status, body) = post(
            router,
            &format!("/documents/{doc}/storage"),
            &owner,
            json!({"mode":"ledger"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let mut seats = Vec::new();
    for web in [owner, colleague] {
        let (status, grant) = post(
            router,
            &format!("/documents/{doc}/connectors"),
            &web,
            json!({"host":"word"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{grant}");
        let pane = format!("Bearer {}", grant["token"].as_str().unwrap());
        seats.push(Seat { web, pane });
    }
    let colleague = seats.pop().unwrap();
    let owner = seats.pop().unwrap();
    (doc, root, owner, colleague)
}
fn bundle(doc: Uuid, base: &Value, message: &str, ops: Vec<Value>) -> Value {
    json!({"name":message,"note":"","submit":true,"bundle":{
        "format":"dynodoc.change-bundle","version":1,"bundle_id":Uuid::new_v4(),"client_id":Uuid::new_v4(),"document_id":doc,
        "base_seq":base["through_seq"],"base_chain_hash":base["chain_hash"],
        "capture":{"host":"word","mode":"observed_snapshot","document_name":"report.docx"},
        "changes":ops.into_iter().map(|op| json!({"id":Uuid::new_v4(),"observed_at":"2026-11-05T08:00:00Z","operation":op})).collect::<Vec<_>>()
    }})
}
/// Push and merge one commit from `pane` on the current head; returns the merge status.
async fn commit(
    router: &Router,
    doc: Uuid,
    pane: &str,
    message: &str,
    ops: Vec<Value>,
) -> (StatusCode, Value) {
    let base = get(
        router,
        &format!("/connector/documents/{doc}/checkpoint"),
        pane,
    )
    .await
    .1;
    commit_on(router, doc, pane, &base, message, ops).await
}
/// A commit on a known base (a pane that just pulled), without reading a checkpoint: the
/// 200-commit run would otherwise meet the per-person read budget.
async fn commit_on(
    router: &Router,
    doc: Uuid,
    pane: &str,
    base: &Value,
    message: &str,
    ops: Vec<Value>,
) -> (StatusCode, Value) {
    let (status, receipt) = post(
        router,
        &format!("/connector/documents/{doc}/bundles"),
        pane,
        bundle(doc, base, message, ops),
    )
    .await;
    if status != StatusCode::OK {
        return (status, receipt);
    }
    let draft = receipt["id"].as_str().unwrap();
    post(
        router,
        &format!("/connector/documents/{doc}/requests/{draft}/merge"),
        pane,
        json!({}),
    )
    .await
}
fn edit(node: &str, text: &str) -> Vec<Value> {
    vec![
        json!({"type":"FieldEdited","node_id":node,"field":"content","value":para(text)}),
        json!({"type":"FieldEdited","node_id":node,"field":"native","value":native(&format!("<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"))}),
        json!({"type":"FieldEdited","node_id":node,"field":"label","value":text}),
        json!({"type":"FieldEdited","node_id":node,"field":"block_hash","value":hash(text)}),
    ]
}

#[sqlx::test(migrations = "../../migrations")]
async fn ledger_documents_keep_hashes_and_changed_blocks_only(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let (doc, root, owner, colleague) = setup(&router, &pool, "store", false).await;

    // The choice: owners and managers only, audited.
    let storage = format!("/documents/{doc}/storage");
    assert_eq!(
        post(&router, &storage, &colleague.web, json!({"mode":"ledger"}))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(
            &router,
            &storage,
            &owner.web,
            json!({"mode":"repository","media":"hash_only"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST,
        "images by hash only exist in ledger mode"
    );
    let (status, body) = post(&router, &storage, &owner.web, json!({"mode":"ledger"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let audited: i64 = sqlx::query_scalar("select count(*) from operation_audit where resource_id=$1 and action='document.storage_mode_set'")
        .bind(doc).fetch_one(&pool).await.unwrap();
    assert_eq!(audited, 1);
    let (_, view) = get(&router, &storage, &colleague.web).await;
    assert_eq!(view["storage"]["mode"], "ledger");
    assert_eq!(view["fixed"], false, "no commit yet: {view}");

    let (status, checkpoint) = get(
        &router,
        &format!("/connector/documents/{doc}/checkpoint"),
        &owner.pane,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{checkpoint}");
    assert_eq!(checkpoint["storage"]["mode"], "ledger");
    assert_eq!(checkpoint["manifest_root"], hash(""), "no blocks yet");

    // The first commit records hashes only: content is refused.
    let (a, b) = (ulid(), ulid());
    let (status, body) = commit(&router, doc, &owner.pane, "Bind the file", vec![
        json!({"type":"NodeCreated","node_id":a,"node_type":"item","parent_id":root,"pos":"B","fields":{"content":para("Secret baseline"),"block_hash":hash("a0")}}),
    ]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = commit(&router, doc, &owner.pane, "Bind the file", vec![
        json!({"type":"NodeCreated","node_id":a,"node_type":"item","parent_id":root,"pos":"B","fields":{"block_hash":hash("a0")}}),
        json!({"type":"NodeCreated","node_id":b,"node_type":"item","parent_id":root,"pos":"D","fields":{"block_hash":hash("b0")}}),
    ]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let held: i64 = sqlx::query_scalar("select count(*) from event where document_id=$1 and payload::text like '%Secret baseline%'")
        .bind(doc).fetch_one(&pool).await.unwrap();
    assert_eq!(held, 0, "the server never held the baseline");

    // Fixed from the first commit on, in both directions.
    let (status, body) = post(&router, &storage, &owner.web, json!({"mode":"repository"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("members"), "{body}");

    // The manifest and its root, the same in changes and in the manifest route.
    let (status, delta) = get(
        &router,
        &format!(
            "/connector/documents/{doc}/changes?since_seq=0&since_chain_hash={}",
            "0".repeat(64)
        ),
        &colleague.pane,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{delta}");
    assert_eq!(
        delta["nodes"][&a]["current_fields"],
        json!({"block_hash":hash("a0")})
    );
    let (status, manifest) = get(
        &router,
        &format!("/connector/documents/{doc}/manifest"),
        &colleague.pane,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{manifest}");
    assert_eq!(manifest["root"], delta["manifest_root"]);
    assert_eq!(manifest["blocks"].as_array().unwrap().len(), 2);
    let first_root = manifest["root"].clone();

    // Later commits: a changed block carries its new hash; then content is kept for it only.
    let mut ops = edit(&a, "First, edited");
    ops.pop();
    let (status, body) = commit(&router, doc, &colleague.pane, "Edit without a hash", ops).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = commit(
        &router,
        doc,
        &colleague.pane,
        "Edit the opening",
        edit(&a, "First, edited"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, manifest) = get(
        &router,
        &format!("/connector/documents/{doc}/manifest"),
        &owner.pane,
    )
    .await;
    assert_ne!(manifest["root"], first_root);
    assert!(manifest["blocks"]
        .to_string()
        .contains(&hash("First, edited")));
    let (_, now) = get(
        &router,
        &format!("/connector/documents/{doc}/checkpoint"),
        &owner.pane,
    )
    .await;
    assert_eq!(
        now["state"]["nodes"][&b]["current_fields"],
        json!({"block_hash":hash("b0")})
    );
    assert_eq!(
        now["state"]["nodes"][&a]["current_fields"]["label"],
        "First, edited"
    );
    // A block added later carries its content and hash.
    let c = ulid();
    let (status, body) = commit(&router, doc, &owner.pane, "Add a closing", vec![
        json!({"type":"NodeCreated","node_id":c,"node_type":"item","parent_id":root,"pos":"F","fields":{"block_hash":hash("c0")}}),
    ]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "hash-only blocks belong to the first commit: {body}"
    );

    // Every other writer is refused: the web editor, drafts and comments.
    let (status, body) = post(
        &router,
        &format!("/documents/{doc}/batch"),
        &owner.web,
        json!({"ops":[
            {"type":"FieldEdited","node_id":b,"field":"label","value":"Typed on the web"}
        ]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = post(&router, &format!("/documents/{doc}/change-requests"), &owner.web, json!({
        "name":"From the web","base_seq":0,"ops":[{"type":"FieldEdited","node_id":b,"field":"label","value":"x"}]
    })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // A merged request keeps no copy of its content: its edits are gone, its bundle keeps only
    // its digest and receipt, and its base names a revision of the log.
    let draft: Uuid =
        sqlx::query_scalar("select id from workspace_draft where document_id=$1 and name=$2")
            .bind(doc)
            .bind("Edit the opening")
            .fetch_one(&pool)
            .await
            .unwrap();
    let (edits, compacted, body, base): (i64, i32, Value, Value) = sqlx::query_as("select (select count(*) from draft_edit where draft_id=$1),(select edits from ledger_compaction where draft_id=$1),(select body from provenance_bundle where draft_id=$1),(select base_state from workspace_draft where id=$1)")
        .bind(draft).fetch_one(&pool).await.unwrap();
    assert_eq!(edits, 0);
    assert_eq!(compacted, 4, "the receipt counts the edits it dropped");
    assert_eq!(body, json!({"compacted":true}));
    assert!(base.get("$dynodoc_log").is_some(), "{base}");
    let (_, listed) = get(
        &router,
        &format!("/documents/{doc}/change-requests"),
        &owner.web,
    )
    .await;
    let row = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(draft))
        .unwrap();
    assert_eq!(row["edits"], 4);
    assert_eq!(row["status"], "merged");
    // A retried upload of a compacted request is still answered with its receipt.
    let base_now = get(
        &router,
        &format!("/connector/documents/{doc}/checkpoint"),
        &colleague.pane,
    )
    .await
    .1;
    let retried = bundle(doc, &base_now, "Retitle", edit(&b, "Second, retitled"));
    let (status, first) = post(
        &router,
        &format!("/connector/documents/{doc}/bundles"),
        &colleague.pane,
        retried.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let id = first["id"].as_str().unwrap().to_string();
    let (status, body) = post(
        &router,
        &format!("/connector/documents/{doc}/requests/{id}/merge"),
        &colleague.pane,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, again) = post(
        &router,
        &format!("/connector/documents/{doc}/bundles"),
        &colleague.pane,
        retried.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["id"], first["id"]);
    let bundle_id = retried["bundle"]["bundle_id"].as_str().unwrap();
    let (_, kept) = get(
        &router,
        &format!("/documents/{doc}/provenance/bundles/{bundle_id}"),
        &colleague.web,
    )
    .await;
    assert_eq!(kept["upload"], json!({"compacted":true}));
    assert_eq!(kept["receipt"]["id"], first["id"]);
    // A personal draft, a draft sync and a version restore are refused too.
    let (status, body) = post(
        &router,
        &format!("/documents/{doc}/drafts/{draft}"),
        &owner.web,
        json!({"ops":[{"type":"FieldEdited","node_id":b,"field":"label","value":"x"}],"revision":1}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "draft edit: {body}");
    assert!(body.to_string().contains("ledger mode"), "{body}");
    let (status, body) = post(
        &router,
        &format!("/documents/{doc}/drafts/{draft}/sync"),
        &owner.web,
        json!({"action":"share"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "draft sync: {body}");
    assert!(body.to_string().contains("ledger mode"), "{body}");
    let (status, version) = post(
        &router,
        &format!("/documents/{doc}/versions"),
        &owner.web,
        json!({"name":"Before the retitle"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{version}");
    let (status, body) = post(
        &router,
        &format!(
            "/documents/{doc}/versions/{}/restore",
            version["id"].as_str().unwrap()
        ),
        &owner.web,
        json!({"base_seq":version["through_seq"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "version restore: {body}");
    assert!(body.to_string().contains("ledger mode"), "{body}");

    // Images by hash only: nothing is uploaded and nothing is missing.
    let (status, body) = post(
        &router,
        &storage,
        &owner.web,
        json!({"mode":"ledger","media":"hash_only"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, missing) = post(
        &router,
        &format!("/connector/documents/{doc}/media/missing"),
        &owner.pane,
        json!({"hashes":[hash("png")]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(missing["missing"], json!([]));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/connector/documents/{doc}/media"))
        .header(header::AUTHORIZATION, &owner.pane)
        .header("content-type", "application/octet-stream")
        .header("x-dynodoc-media-type", "image/png")
        .body(Body::from(PNG.to_vec()))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    // Repository documents are unchanged: no manifest root, content accepted.
    let (rdoc, rroot, rowner, _) = setup(&router, &pool, "repo", false).await;
    let (_, rcheck) = get(
        &router,
        &format!("/connector/documents/{rdoc}/checkpoint"),
        &rowner.pane,
    )
    .await;
    assert_eq!(rcheck["storage"]["mode"], "repository");
    assert!(rcheck.get("manifest_root").is_none());
    let (status, body) = commit(&router, rdoc, &rowner.pane, "Initial", vec![
        json!({"type":"NodeCreated","node_id":ulid(),"node_type":"item","parent_id":rroot,"pos":"B","fields":{"label":"Plain","content":para("Plain"),"native":native("<w:p>Plain</w:p>")}}),
    ]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let kept: i64 = sqlx::query_scalar("select count(*) from draft_edit e join workspace_draft d on d.id=e.draft_id where d.document_id=$1")
        .bind(rdoc).fetch_one(&pool).await.unwrap();
    assert!(kept >= 1, "repository requests keep their edits");
    // A merged repository request cannot be compacted, even by a direct insert.
    let rdraft: Uuid = sqlx::query_scalar("select id from workspace_draft where document_id=$1")
        .bind(rdoc)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        sqlx::query("insert into ledger_compaction(draft_id,document_id) values($1,$2)")
            .bind(rdraft)
            .bind(rdoc)
            .execute(&pool)
            .await
            .is_err()
    );
    runtime.close().await;
}

/// The project default: owners and managers choose it, audited; a file that joins the project
/// before its first commit takes it, unless it has its own setting; a committed file keeps its
/// mode.
#[sqlx::test(migrations = "../../migrations")]
async fn files_joining_a_project_take_its_default_storage_mode(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let owner = identity(&pool, "default-owner@example.test").await;
    let editor = identity(&pool, "default-editor@example.test").await;
    let (status, project) = post(&router, "/projects", &owner, json!({"name":"Field study"})).await;
    assert_eq!(status, StatusCode::OK, "{project}");
    let project = project["id"].as_str().unwrap().to_string();
    let editor_id: Uuid =
        sqlx::query_scalar("select id from identity where email='default-editor@example.test'")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("insert into space_member(space_id,identity_id,role) values($1,$2,'editor')")
        .bind(Uuid::parse_str(&project).unwrap())
        .bind(editor_id)
        .execute(&runtime.owner)
        .await
        .unwrap();
    let route = format!("/projects/{project}/storage");
    let (_, view) = get(&router, &route, &editor).await;
    assert_eq!(view["storage"]["mode"], "repository");
    assert_eq!(view["can_manage"], false);
    assert_eq!(
        post(&router, &route, &editor, json!({"mode":"ledger"}))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(
            &router,
            &route,
            &owner,
            json!({"mode":"repository","media":"hash_only"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (status, body) = post(
        &router,
        &route,
        &owner,
        json!({"mode":"ledger","media":"hash_only"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let audited: i64 = sqlx::query_scalar(
        "select count(*) from operation_audit where action='project.storage_default_set'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);

    let file = |title: &'static str| {
        let (router, owner) = (router.clone(), owner.clone());
        async move {
            let (_, body) = post(&router, "/documents", &owner, json!({"title":title})).await;
            let doc = body["id"].as_str().unwrap().to_string();
            let (status, body) = post(
                &router,
                &format!("/documents/{doc}/metadata"),
                &owner,
                json!({"settings":{"kind":"document"}}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            doc
        }
    };
    let join = |doc: String| {
        let (router, owner, project) = (router.clone(), owner.clone(), project.clone());
        async move {
            let (status, body) = post(
                &router,
                &format!("/documents/{doc}/location"),
                &owner,
                json!({"space_id":project}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            get(&router, &format!("/documents/{doc}/storage"), &owner)
                .await
                .1["storage"]
                .clone()
        }
    };
    // A new file takes the default.
    let fresh = file("Notes").await;
    assert_eq!(
        join(fresh.clone()).await,
        json!({"mode":"ledger","media":"hash_only"})
    );
    let source: Value = sqlx::query_scalar("select detail->'source' from operation_audit where action='document.storage_mode_set' and resource_id=$1")
        .bind(Uuid::parse_str(&fresh).unwrap()).fetch_one(&pool).await.unwrap();
    assert_eq!(source, "project_default");
    // A file's own setting wins.
    let own = file("Own choice").await;
    let (status, body) = post(
        &router,
        &format!("/documents/{own}/storage"),
        &owner,
        json!({"mode":"repository"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(join(own).await["mode"], "repository");
    // A committed file keeps the mode it was committed in.
    let used = file("Used").await;
    let (status, body) = post(&router, &format!("/documents/{used}/batch"), &owner, json!({"base_seq":0,"ops":[
        {"type":"NodeCreated","node_id":ulid(),"node_type":"form","pos":"000000","fields":{"label":"Used"}}
    ]})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let root: String = sqlx::query_scalar("select id from node where document_id=$1")
        .bind(Uuid::parse_str(&used).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    let (status, body) = post(&router, &format!("/documents/{used}/batch"), &owner, json!({"ops":[
        {"type":"NodeCreated","node_id":ulid(),"node_type":"item","parent_id":root,"pos":"B","fields":{"label":"Text","content":para("Text")}}
    ]})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(join(used).await["mode"], "repository");
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_relay_is_for_members_capped_and_deleted_after_delivery(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let (doc, _root, owner, colleague) = setup(&router, &pool, "relay", true).await;
    let relay = format!("/connector/documents/{doc}/relay");
    let wanted_hash = hash("block-1");

    // Connector keys only; a document's key opens only its own relay.
    assert_eq!(
        post(
            &router,
            &relay,
            &colleague.web,
            json!({"kind":"block","hashes":[wanted_hash]})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &router,
            &relay,
            &format!("Bearer {}", "f".repeat(64)),
            json!({"kind":"block","hashes":[wanted_hash]})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (rdoc, _, rowner, _) = setup(&router, &pool, "relay-repo", false).await;
    assert_eq!(
        post(
            &router,
            &format!("/connector/documents/{doc}/relay"),
            &rowner.pane,
            json!({"kind":"block","hashes":[wanted_hash]})
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "another document's key"
    );
    assert_eq!(
        post(
            &router,
            &format!("/connector/documents/{rdoc}/relay"),
            &rowner.pane,
            json!({"kind":"block","hashes":[wanted_hash]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST,
        "repository documents have no relay"
    );
    // Well-formed requests only.
    for bad in [
        json!({"kind":"file","hashes":[wanted_hash]}),
        json!({"kind":"block","hashes":["ABC"]}),
        json!({"kind":"block","hashes":[]}),
        json!({"kind":"block","hashes":vec![wanted_hash.clone(); 201]}),
        json!({"kind":"block","hashes":[wanted_hash],"recipient_key":"short"}),
    ] {
        assert_eq!(
            post(&router, &relay, &colleague.pane, bad).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    let (status, asked) = post(
        &router,
        &relay,
        &colleague.pane,
        json!({"kind":"block","hashes":[wanted_hash]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{asked}");
    let id = asked["requests"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(asked["requests"][0]["served"], false);
    // Asking again is the same request.
    let (_, again) = post(
        &router,
        &relay,
        &colleague.pane,
        json!({"kind":"block","hashes":[wanted_hash]}),
    )
    .await;
    assert_eq!(again["requests"][0]["id"], id.as_str());

    // Other members see it, without the requester's name; the requester does not.
    let (_, theirs) = get(&router, &format!("{relay}/wanted"), &owner.pane).await;
    assert_eq!(theirs["wanted"][0]["id"], id.as_str());
    assert_eq!(theirs["wanted"][0]["hash"], wanted_hash.as_str());
    assert!(!theirs.to_string().contains("colleague"));
    let (_, own) = get(&router, &format!("{relay}/wanted"), &colleague.pane).await;
    assert_eq!(own["wanted"], json!([]));

    let answer = |bytes: &[u8]| json!({"encoding":"plain","data":STANDARD.encode(bytes)});
    let one = format!("{relay}/{id}");
    assert_eq!(
        post(&router, &one, &colleague.pane, answer(b"{}")).await.0,
        StatusCode::FORBIDDEN,
        "not your own request"
    );
    assert_eq!(
        post(
            &router,
            &one,
            &owner.pane,
            answer(&vec![b'x'; 2 * 1024 * 1024 + 1])
        )
        .await
        .0,
        StatusCode::BAD_REQUEST,
        "a block answer is capped at 2 MiB"
    );
    assert_eq!(
        post(
            &router,
            &one,
            &owner.pane,
            json!({"encoding":"rot13","data":"e30="})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // Waiting until answered.
    let (status, waiting) = get(&router, &one, &colleague.pane).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(waiting["waiting"], true);
    let block = br#"{"content":{"type":"paragraph"},"label":"Opening"}"#;
    let (status, body) = post(&router, &one, &owner.pane, answer(block)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        post(&router, &one, &owner.pane, answer(block)).await.0,
        StatusCode::NOT_FOUND,
        "answered once"
    );
    // Only the requester downloads it, once; the download deletes it from the server.
    assert_eq!(
        get(&router, &one, &owner.pane).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, got) = get(&router, &one, &colleague.pane).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        STANDARD.decode(got["data"].as_str().unwrap()).unwrap(),
        block.to_vec()
    );
    assert_eq!(got["hash"], wanted_hash.as_str());
    let rows: i64 = sqlx::query_scalar("select count(*) from ledger_relay where document_id=$1")
        .bind(doc)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "deleted after delivery");
    assert_eq!(
        get(&router, &one, &colleague.pane).await.0,
        StatusCode::NOT_FOUND
    );

    // Images: up to 15 MiB; unanswered requests expire after their hour and are purged.
    let (_, asked) = post(
        &router,
        &relay,
        &colleague.pane,
        json!({"kind":"media","hashes":[hash("png")]}),
    )
    .await;
    let media = asked["requests"][0]["id"].as_str().unwrap().to_string();
    let (status, body) = post(
        &router,
        &format!("{relay}/{media}"),
        &owner.pane,
        answer(&vec![1u8; 3 * 1024 * 1024]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an image may be larger than a block: {body}"
    );
    sqlx::query(
        "update ledger_relay set expires_at=now()-interval '1 second' where document_id=$1",
    )
    .bind(doc)
    .execute(&runtime.owner)
    .await
    .unwrap();
    assert_eq!(
        get(&router, &format!("{relay}/{media}"), &colleague.pane)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let rows: i64 = sqlx::query_scalar("select count(*) from ledger_relay where document_id=$1")
        .bind(doc)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "expired rows are purged");

    // A revoked key stops working at once.
    let (_, grants) = get(
        &router,
        &format!("/documents/{doc}/connectors"),
        &colleague.web,
    )
    .await;
    let grant = grants["items"][0]["id"].as_str().unwrap();
    assert_eq!(
        post(
            &router,
            &format!("/documents/{doc}/connectors/{grant}/revoke"),
            &colleague.web,
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        post(
            &router,
            &relay,
            &colleague.pane,
            json!({"kind":"block","hashes":[wanted_hash]})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    runtime.close().await;
}

/// Decision 025 acceptance 5: what the server keeps after 200 commits of typical edits (one
/// paragraph rewritten per commit, a new paragraph every tenth) for a 100-paragraph file, in
/// ledger and in repository mode, beside the size of the file's content.
/// Synthetic prose: words picked by a fixed linear congruential sequence, so paragraphs differ
/// (and compress) the way written text does, not like one repeated sentence.
fn prose(seed: usize, words: usize) -> String {
    const WORDS: [&str; 48] = [
        "committee",
        "reviewed",
        "quarterly",
        "figures",
        "agreed",
        "next",
        "steps",
        "field",
        "programme",
        "district",
        "survey",
        "results",
        "budget",
        "approved",
        "delayed",
        "report",
        "regional",
        "teams",
        "collected",
        "samples",
        "analysis",
        "showed",
        "higher",
        "lower",
        "rates",
        "than",
        "expected",
        "partners",
        "requested",
        "further",
        "detail",
        "on",
        "the",
        "and",
        "of",
        "for",
        "with",
        "during",
        "after",
        "before",
        "each",
        "site",
        "visit",
        "water",
        "supply",
        "training",
        "schools",
        "clinics",
    ];
    let mut x = seed as u64 * 2_654_435_761 + 1;
    (0..words)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            WORDS[(x >> 33) as usize % WORDS.len()]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "slow (400 commits): run with --ignored --nocapture for the decision 025 storage report"]
async fn storage_after_two_hundred_commits_is_reported_beside_the_file_size(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let mut kept = Vec::new();
    for ledger in [true, false] {
        let (doc, root, owner, _) = setup(
            &router,
            &pool,
            if ledger {
                "report-ledger"
            } else {
                "report-repo"
            },
            ledger,
        )
        .await;
        let mut blocks: Vec<(String, String)> = (0..100).map(|i| (ulid(), prose(i, 40))).collect();
        let created: Vec<Value> = blocks.iter().enumerate().map(|(i, (id, text))| {
            let fields = if ledger {
                json!({"block_hash":hash(text)})
            } else {
                json!({"label":text,"content":para(text),"native":native(&format!("<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"))})
            };
            json!({"type":"NodeCreated","node_id":id,"node_type":"item","parent_id":root,"pos":format!("B{i:04}"),"fields":fields})
        }).collect();
        let (status, body) = commit(&router, doc, &owner.pane, "Initial version", created).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        for n in 1..200usize {
            let ops = if n % 10 == 0 {
                let (id, text) = (ulid(), prose(1000 + n, 40));
                let mut fields = json!({"label":text,"content":para(&text),"native":native(&format!("<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"))});
                if ledger {
                    fields["block_hash"] = json!(hash(&text));
                }
                let op = json!({"type":"NodeCreated","node_id":id,"node_type":"item","parent_id":root,"pos":format!("C{n:04}"),"fields":fields});
                blocks.push((id, text));
                vec![op]
            } else {
                let at = (n * 37) % blocks.len();
                // A typical edit: a few words of the paragraph change.
                let mut words: Vec<String> = blocks[at].1.split(' ').map(String::from).collect();
                let w = words.len();
                for k in 0..4 {
                    words[(n * 7 + k * 11) % w] = prose(n * 4 + k, 1);
                }
                let text = words.join(" ");
                blocks[at].1 = text.clone();
                let mut ops = edit(&blocks[at].0, &text);
                if !ledger {
                    ops.pop();
                }
                ops
            };
            let base: (i64, String) = sqlx::query_as("select seq,encode(chain_hash,'hex') from event where document_id=$1 order by seq desc limit 1")
                .bind(doc).fetch_one(&pool).await.unwrap();
            let base = json!({"through_seq":base.0,"chain_hash":base.1});
            let (status, body) =
                commit_on(&router, doc, &owner.pane, &base, &format!("Edit {n}"), ops).await;
            assert_eq!(status, StatusCode::OK, "commit {n}: {body}");
        }
        let (_, view) = get(&router, &format!("/documents/{doc}/storage"), &owner.web).await;
        // The file's content: each paragraph's Word XML and text, as a .docx holds them before zip.
        let file: usize = blocks
            .iter()
            .map(|(_, t)| format!("<w:p><w:r><w:t>{t}</w:t></w:r></w:p>").len())
            .sum();
        println!(
            "decision-025-acceptance-5 mode={} commits=200 blocks={} file_content_bytes={} server_bytes={} detail={}",
            if ledger { "ledger" } else { "repository" },
            blocks.len(),
            file,
            view["report"]["total_bytes"],
            view["report"]["bytes"]
        );
        assert_eq!(view["fixed"], true);
        kept.push(view["report"]["total_bytes"].as_i64().unwrap());
    }
    assert!(
        kept[0] < kept[1],
        "ledger mode keeps less than repository mode: {kept:?}"
    );
    runtime.close().await;
}

/// Decision 040, owner decision: the block states members' panes sent for agents stay on the
/// server only until the agent's change request is merged, declined or withdrawn. While another
/// agent request of the file is open they stay; a person's request closing deletes nothing;
/// another file's states are never touched. Runs as the runtime role, so the privilege class
/// of `ledger_block_state` (select, insert, delete) is exercised too.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_block_states_go_when_the_agents_change_requests_close(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let owner_pool = runtime.owner.clone();
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let (doc, _root, owner, _) = setup(&router, &pool, "states", true).await;
    let (other, _, _, _) = setup(&router, &pool, "states-other", true).await;
    let principal: Uuid =
        sqlx::query_scalar("select id from identity where email='states-owner@example.test'")
            .fetch_one(&owner_pool)
            .await
            .unwrap();
    let agent = Uuid::new_v4();
    // Both rows in one transaction: an agent identity needs its agent_identity row (schema 117).
    let mut tx = owner_pool.begin().await.unwrap();
    sqlx::query(
        "insert into identity(id,display_name,disabled_at,kind) values($1,'Agent',now(),'agent')",
    )
    .bind(agent)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("insert into agent_identity(identity_id,principal_id,client_kind,client_ref) values($1,$2,'claude','k')")
        .bind(agent).bind(principal).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let request = |by: Uuid, name: &'static str| {
        let owner_pool = owner_pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>("insert into workspace_draft(document_id,name,base_seq,base_state,created_by,submitted_at) values($1,$2,1,$3,$4,now()) returning id")
                .bind(doc).bind(name).bind(json!({"$dynodoc_log":1})).bind(by)
                .fetch_one(&owner_pool).await.unwrap()
        }
    };
    let first = request(agent, "Agent one").await;
    let second = request(agent, "Agent two").await;
    let person = request(principal, "Person").await;
    for (file, seed) in [(doc, "a"), (doc, "b"), (other, "c")] {
        sqlx::query("insert into ledger_block_state(document_id,block_hash,fields) values($1,decode($2,'hex'),'{}')")
            .bind(file).bind(hash(seed)).execute(&pool).await.unwrap();
    }
    let held = |file: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "select count(*) from ledger_block_state where document_id=$1",
            )
            .bind(file)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let decline = |draft: Uuid| format!("/documents/{doc}/change-requests/{draft}/decline");

    // A person's request closing, and an agent request closing while another is open: kept.
    let (status, body) = post(&router, &decline(person), &owner.web, json!({"note":""})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(held(doc).await, 2);
    let (status, body) = post(&router, &decline(first), &owner.web, json!({"note":""})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(held(doc).await, 2);
    // The file's last open agent request closes: its states go, the other file's stay.
    let (status, body) = post(&router, &decline(second), &owner.web, json!({"note":""})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(held(doc).await, 0);
    assert_eq!(held(other).await, 1);
}
