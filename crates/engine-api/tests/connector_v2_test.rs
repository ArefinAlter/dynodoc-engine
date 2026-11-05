//! Decision 024 connector routes, driven through the real router: structural bundles
//! with host-native fields, the pane's own-request merge, delta pull, per-block
//! history with contributor attribution, and content-addressed media.
//! Requires a reachable Postgres (DATABASE_URL), like the other API integration tests.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::Router;
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
async fn send(
    router: &Router,
    req: Request<Body>,
) -> (StatusCode, Value, axum::http::HeaderMap, Vec<u8>) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        headers,
        bytes,
    )
}
async fn post(router: &Router, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header(header::AUTHORIZATION, token)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let r = send(router, req).await;
    (r.0, r.1)
}
async fn get(router: &Router, uri: &str, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, token)
        .body(Body::empty())
        .unwrap();
    let r = send(router, req).await;
    (r.0, r.1)
}
async fn put_media(
    router: &Router,
    doc: Uuid,
    token: &str,
    kind: &str,
    bytes: &[u8],
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/connector/documents/{doc}/media"))
        .header(header::AUTHORIZATION, token)
        .header("content-type", "application/octet-stream")
        .header("x-dynodoc-media-type", kind)
        .body(Body::from(bytes.to_vec()))
        .unwrap();
    let r = send(router, req).await;
    (r.0, r.1)
}
fn native(xml: &str) -> Value {
    json!({"host":"word","v":1,"xml":xml,"media":[],"content_hash":"0".repeat(64)})
}
fn para(text: &str) -> Value {
    json!({"type":"paragraph","content":[{"type":"text","text":text}]})
}
/// A document with a root and two blocks; returns (doc, root, first block, second block).
async fn document(router: &Router, owner: &str) -> (Uuid, String, String, String) {
    let (status, body) = post(router, "/documents", owner, json!({"title":"Pilot report"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    assert_eq!(
        post(
            router,
            &format!("/documents/{doc}/metadata"),
            owner,
            json!({"settings":{"kind":"document"}})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (root, a, b) = (
        ulid::Ulid::generate().to_string(),
        ulid::Ulid::generate().to_string(),
        ulid::Ulid::generate().to_string(),
    );
    let ops = json!([
        {"type":"NodeCreated","node_id":root,"node_type":"form","pos":"000000","fields":{"label":"Report"}},
        {"type":"NodeCreated","node_id":a,"node_type":"item","parent_id":root,"pos":"B","fields":{"label":"First","content":para("First"),"native":native("<w:p>First</w:p>")}},
        {"type":"NodeCreated","node_id":b,"node_type":"item","parent_id":root,"pos":"D","fields":{"label":"Second","content":para("Second"),"native":native("<w:p>Second</w:p>")}}
    ]);
    let (status, body) = post(
        router,
        &format!("/documents/{doc}/batch"),
        owner,
        json!({"base_seq":0,"ops":ops}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (doc, root, a, b)
}
async fn connector(router: &Router, doc: Uuid, person: &str) -> String {
    let (status, grant) = post(
        router,
        &format!("/documents/{doc}/connectors"),
        person,
        json!({"host":"word"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    format!("Bearer {}", grant["token"].as_str().unwrap())
}
fn bundle(doc: Uuid, checkpoint: &Value, message: &str, ops: Vec<Value>) -> Value {
    json!({"name":message,"note":"","submit":true,"bundle":{
        "format":"dynodoc.change-bundle","version":1,"bundle_id":Uuid::new_v4(),"client_id":Uuid::new_v4(),"document_id":doc,
        "base_seq":checkpoint["through_seq"],"base_chain_hash":checkpoint["chain_hash"],
        "capture":{"host":"word","mode":"observed_snapshot","document_name":"report.docx"},
        "changes":ops.into_iter().map(|op| json!({"id":Uuid::new_v4(),"observed_at":"2026-11-05T08:00:00Z","operation":op})).collect::<Vec<_>>()
    }})
}

#[sqlx::test(migrations = "../../migrations")]
async fn structural_commits_merge_from_the_pane_and_pull_as_deltas(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let owner = identity(&pool, "pilot-owner@example.test").await;
    let colleague = identity(&pool, "pilot-colleague@example.test").await;
    let (doc, root, a, b) = document(&router, &owner).await;
    assert_eq!(
        post(
            &router,
            &format!("/documents/{doc}/members"),
            &owner,
            json!({"email":"pilot-colleague@example.test","role":"editor"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let mine = connector(&router, doc, &owner).await;
    let theirs = connector(&router, doc, &colleague).await;
    let base = get(
        &router,
        &format!("/connector/documents/{doc}/checkpoint"),
        &mine,
    )
    .await
    .1;
    // One commit: edit the first block's Word form, insert a block, move the second.
    let new = ulid::Ulid::generate().to_string();
    let ops = vec![
        json!({"type":"FieldEdited","node_id":a,"field":"native","value":native("<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>First</w:t></w:r></w:p>")}),
        json!({"type":"FieldEdited","node_id":a,"field":"content","value":{"type":"paragraph","content":[{"type":"text","text":"First","marks":[{"type":"bold"}]}]}}),
        json!({"type":"NodeCreated","node_id":new,"node_type":"item","parent_id":root,"pos":"C","fields":{"label":"Inserted","content":para("Inserted"),"native":native("<w:p>Inserted</w:p>")}}),
        json!({"type":"NodeMoved","node_id":b,"new_parent_id":root,"new_pos":"A"}),
    ];
    let (status, receipt) = post(
        &router,
        &format!("/connector/documents/{doc}/bundles"),
        &mine,
        bundle(doc, &base, "Bold the opening and add a paragraph", ops),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let draft = receipt["id"].as_str().unwrap().to_string();
    // Nothing reaches the team version before the merge.
    let still = get(
        &router,
        &format!("/connector/documents/{doc}/checkpoint"),
        &mine,
    )
    .await
    .1;
    assert_eq!(still["through_seq"], base["through_seq"]);
    // A colleague's pane cannot merge someone else's request.
    assert_eq!(
        post(
            &router,
            &format!("/connector/documents/{doc}/requests/{draft}/merge"),
            &theirs,
            json!({})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // A stale request can be withdrawn by its author's pane only, once.
    let (status, extra) = post(
        &router,
        &format!("/connector/documents/{doc}/bundles"),
        &mine,
        bundle(
            doc,
            &base,
            "Second try",
            vec![json!({"type":"FieldEdited","node_id":b,"field":"label","value":"Second"})],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{extra}");
    let stale = extra["id"].as_str().unwrap().to_string();
    assert_eq!(
        post(
            &router,
            &format!("/connector/documents/{doc}/requests/{stale}/withdraw"),
            &theirs,
            json!({})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(
            &router,
            &format!("/connector/documents/{doc}/requests/{stale}/withdraw"),
            &mine,
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        post(
            &router,
            &format!("/connector/documents/{doc}/requests/{stale}/withdraw"),
            &mine,
            json!({})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, merged) = post(
        &router,
        &format!("/connector/documents/{doc}/requests/{draft}/merge"),
        &mine,
        json!({"note":"publish"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{merged}");
    // The colleague pulls only what changed since their base.
    let since = format!(
        "/connector/documents/{doc}/changes?since_seq={}&since_chain_hash={}",
        base["through_seq"],
        base["chain_hash"].as_str().unwrap()
    );
    let (status, delta) = get(&router, &since, &theirs).await;
    assert_eq!(status, StatusCode::OK, "{delta}");
    let nodes = delta["nodes"].as_object().unwrap();
    let mut changed: Vec<&String> = nodes.keys().collect();
    changed.sort();
    let mut want = vec![&a, &b, &new];
    want.sort();
    assert_eq!(changed, want, "only changed blocks travel: {delta}");
    assert!(!nodes.contains_key(&root));
    assert_eq!(nodes[&b]["pos"], "A");
    assert!(nodes[&a]["current_fields"]["native"]["xml"]
        .as_str()
        .unwrap()
        .contains("<w:b/>"));
    assert!(delta["through_seq"].as_i64().unwrap() > base["through_seq"].as_i64().unwrap());
    // A base that is not this history is refused, not guessed.
    let forged = format!(
        "/connector/documents/{doc}/changes?since_seq={}&since_chain_hash={}",
        base["through_seq"],
        "a".repeat(64)
    );
    assert_eq!(get(&router, &forged, &theirs).await.0, StatusCode::CONFLICT);
    let ahead = format!(
        "/connector/documents/{doc}/changes?since_seq=99999&since_chain_hash={}",
        "0".repeat(64)
    );
    assert_eq!(
        get(&router, &ahead, &theirs).await.0,
        StatusCode::BAD_REQUEST
    );
    // Block history names the contributor and the commit message.
    let (status, history) = get(
        &router,
        &format!("/connector/documents/{doc}/nodes/{a}/history"),
        &theirs,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    let events = history["events"].as_array().unwrap();
    let edit = events
        .iter()
        .find(|e| e["field"] == "native")
        .expect("native edit in history");
    assert_eq!(
        edit["request"]["name"],
        "Bold the opening and add a paragraph"
    );
    assert_eq!(edit["request"]["author"]["name"], "Tester");
    assert_eq!(edit["request"]["agent"], false);
    assert_eq!(events.last().unwrap()["type"], "NodeCreated");
    assert_eq!(
        get(
            &router,
            &format!("/connector/documents/{doc}/nodes/not-a-block/history"),
            &theirs
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn media_is_content_addressed_typed_scoped_and_inert(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let owner = identity(&pool, "media-owner@example.test").await;
    let viewer = identity(&pool, "media-viewer@example.test").await;
    let (doc, ..) = document(&router, &owner).await;
    let (other, ..) = document(&router, &owner).await;
    let token = connector(&router, doc, &owner).await;
    let other_token = connector(&router, other, &owner).await;
    let (status, first) = put_media(&router, doc, &token, "image/png", PNG).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["stored"], true);
    let sha = first["sha256"].as_str().unwrap().to_string();
    assert_eq!(sha.len(), 64);
    assert_eq!(
        put_media(&router, doc, &token, "image/png", PNG).await.1["stored"],
        false
    );
    // Bytes must match the claimed type; unknown types are refused.
    assert_eq!(
        put_media(&router, doc, &token, "image/jpeg", PNG).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put_media(&router, doc, &token, "text/html", b"<script>")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put_media(
            &router,
            doc,
            &token,
            "image/svg+xml",
            b"<!DOCTYPE svg [<!ENTITY x 'y'>]><svg/>"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put_media(&router, doc, &token, "image/png", b"").await.0,
        StatusCode::BAD_REQUEST
    );
    let absent = "b".repeat(64);
    let (status, missing) = post(
        &router,
        &format!("/connector/documents/{doc}/media/missing"),
        &token,
        json!({"hashes":[sha, absent]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{missing}");
    assert_eq!(missing["missing"], json!([absent]));
    assert_eq!(
        post(
            &router,
            &format!("/connector/documents/{doc}/media/missing"),
            &token,
            json!({"hashes":["ABC"]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let req = Request::builder()
        .uri(format!("/connector/documents/{doc}/media/{sha}"))
        .header(header::AUTHORIZATION, &token)
        .body(Body::empty())
        .unwrap();
    let (status, _, headers, bytes) = send(&router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, PNG);
    assert_eq!(headers["content-type"], "application/octet-stream");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-dynodoc-media-type"], "image/png");
    assert!(headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("sandbox"));
    // Scoped to the credential's document; session tokens are not connector keys.
    assert_eq!(
        get(
            &router,
            &format!("/connector/documents/{doc}/media/{sha}"),
            &other_token
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(
            &router,
            &format!("/connector/documents/{other}/media/{sha}"),
            &other_token
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(
            &router,
            &format!("/connector/documents/{doc}/media/{sha}"),
            &owner
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    // A viewer cannot obtain a connector at all, so cannot add media.
    assert_eq!(
        post(
            &router,
            &format!("/documents/{doc}/members"),
            &owner,
            json!({"email":"media-viewer@example.test","role":"viewer"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        post(
            &router,
            &format!("/documents/{doc}/connectors"),
            &viewer,
            json!({"host":"word"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // The runtime login has no UPDATE, and the trigger refuses it even for the owner.
    for db in [&pool, &runtime.owner] {
        let edit =
            sqlx::query("update connector_media set content_type='image/gif' where document_id=$1")
                .bind(doc)
                .execute(db)
                .await;
        assert!(edit.is_err());
    }
    runtime.close().await;
}
