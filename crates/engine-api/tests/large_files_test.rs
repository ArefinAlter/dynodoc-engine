//! Decision 034 trust boundaries and paths, through the real router: resumable uploads
//! (per-chunk and whole-file SHA-256, offsets, ownership, quota under concurrency),
//! streaming server import of a Word file (bounded, resumable, bombs refused) and
//! streaming egress (checkpoint NDJSON and .docx). Requires DATABASE_URL like the
//! other API integration tests. Synthetic content only.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use engine_api::auth::{store as auth_store, token, AuthConfig};
use engine_api::{app, AppState};
use engine_core::ooxml::{docx, zip::ZipWriter};
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod common;

const KEY: [u8; 32] = [9u8; 32];

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
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    hex(digest(&SHA256, bytes).as_ref())
}
async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Value, Vec<u8>) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
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
async fn get(router: &Router, uri: &str, token: &str) -> (StatusCode, Value, Vec<u8>) {
    let req = Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, token)
        .body(Body::empty())
        .unwrap();
    send(router, req).await
}
async fn chunk(
    router: &Router,
    base: &str,
    token: &str,
    offset: usize,
    bytes: &[u8],
    hash: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("{base}/chunks?offset={offset}"))
        .header(header::AUTHORIZATION, token)
        .header("content-type", "application/octet-stream")
        .header("x-dynodoc-chunk-sha256", hash)
        .body(Body::from(bytes.to_vec()))
        .unwrap();
    let r = send(router, req).await;
    (r.0, r.1)
}
async fn document(router: &Router, owner: &str) -> Uuid {
    let (status, body) = post(router, "/documents", owner, json!({"title":"Large report"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    let (status, _) = post(
        router,
        &format!("/documents/{doc}/metadata"),
        owner,
        json!({"settings":{"kind":"document"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    doc
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
fn png(len: usize) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut x = 0x9e37_79b9u32;
    while bytes.len() < len {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        bytes.push(x as u8);
    }
    bytes
}

#[sqlx::test(migrations = "../../migrations")]
async fn resumable_media_checks_every_chunk_resumes_and_completes_once(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let owner = identity(&pool, "upload-owner@example.test").await;
    let other = identity(&pool, "upload-other@example.test").await;
    let doc = document(&router, &owner).await;
    let key = connector(&router, doc, &owner).await;
    let image = png(3 * 1024 * 1024 + 17);
    let uploads = format!("/connector/documents/{doc}/uploads");
    // The whole-file hash is declared up front.
    let (status, created) = post(
        &router,
        &uploads,
        &key,
        json!({"kind":"media","size":image.len(),"sha256":sha(&image),"media_type":"image/png"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["offset"], 0);
    let base = format!("{uploads}/{}", created["id"].as_str().unwrap());
    let (first, rest) = image.split_at(2 * 1024 * 1024);
    // A chunk whose bytes differ from its hash is refused and changes nothing.
    let mut damaged = first.to_vec();
    damaged[10] ^= 1;
    assert_eq!(
        chunk(&router, &base, &key, 0, &damaged, &sha(first))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(get(&router, &base, &key).await.1["offset"], 0);
    // A missing or malformed hash header is refused.
    assert_eq!(
        chunk(&router, &base, &key, 0, first, "ABC").await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, after) = chunk(&router, &base, &key, 0, first, &sha(first)).await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(after["offset"], first.len());
    // The client lost the response and resends at 0: the server says where it is.
    let (status, conflict) = chunk(&router, &base, &key, 0, first, &sha(first)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["details"]["offset"], first.len(), "{conflict}");
    // Nobody else can read or append to this upload, even with their own key.
    let other_doc = document(&router, &other).await;
    let other_key = connector(&router, other_doc, &other).await;
    assert_eq!(
        get(&router, &base, &other_key).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, _) = post(&router, &format!("{base}/complete"), &key, json!({})).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "complete before the last byte"
    );
    assert_eq!(
        chunk(&router, &base, &key, first.len(), rest, &sha(rest))
            .await
            .0,
        StatusCode::OK
    );
    let (status, done) = post(&router, &format!("{base}/complete"), &key, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["sha256"], sha(&image));
    assert_eq!(done["stored"], true);
    // A retried completion returns the stored result; nothing is stored twice.
    let (status, again) = post(&router, &format!("{base}/complete"), &key, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["result"]["sha256"], sha(&image));
    let (_, _, bytes) = get(
        &router,
        &format!("/connector/documents/{doc}/media/{}", sha(&image)),
        &key,
    )
    .await;
    assert_eq!(bytes, image);
    let staged: i64 = sqlx::query_scalar("select count(*) from upload_chunk")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(staged, 0, "staging is freed once complete");
    // A wrong declared whole-file hash fails at completion, after every chunk passed.
    let small = png(5000);
    let (_, lying) = post(
        &router,
        &uploads,
        &key,
        json!({"kind":"media","size":small.len(),"sha256":"0".repeat(64),"media_type":"image/png"}),
    )
    .await;
    let base = format!("{uploads}/{}", lying["id"].as_str().unwrap());
    assert_eq!(
        chunk(&router, &base, &key, 0, &small, &sha(&small)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        post(&router, &format!("{base}/complete"), &key, json!({}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&router, &format!("{base}/cancel"), &key, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        chunk(&router, &base, &key, 0, &small, &sha(&small)).await.0,
        StatusCode::GONE
    );
    // Imports are not a connector upload kind.
    assert_eq!(
        post(
            &router,
            &uploads,
            &key,
            json!({"kind":"import","size":10,"sha256":"0".repeat(64),"filename":"x.docx"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn quota_and_session_limits_hold_under_concurrent_creates(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let owner = identity(&pool, "quota-owner@example.test").await;
    let doc = document(&router, &owner).await;
    let key = connector(&router, doc, &owner).await;
    let uploads = format!("/connector/documents/{doc}/uploads");
    let create = |size: usize| {
        let (router, uploads, key) = (router.clone(), uploads.clone(), key.clone());
        async move {
            post(&router, &uploads, &key, json!({"kind":"media","size":size,"sha256":"a".repeat(64),"media_type":"image/png"})).await.0
        }
    };
    // Eight at once: exactly four open sessions per person.
    let results = futures::future::join_all((0..8).map(|_| create(1000))).await;
    assert_eq!(
        results.iter().filter(|s| **s == StatusCode::OK).count(),
        4,
        "{results:?}"
    );
    assert!(results
        .iter()
        .all(|s| *s == StatusCode::OK || *s == StatusCode::TOO_MANY_REQUESTS));
    // Other people's open reservations: twenty fill the document's session limit.
    identity(&pool, "quota-filler@example.test").await;
    let filler: Uuid =
        sqlx::query_scalar("select id from identity where email='quota-filler@example.test'")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("delete from upload_session")
        .execute(&pool)
        .await
        .unwrap();
    for _ in 0..20 {
        sqlx::query("insert into upload_session(document_id,created_by,kind,media_type,size,sha256) values($1,$2,'media','image/png',26214400,$3)")
            .bind(doc).bind(filler).bind(vec![0u8; 32]).execute(&pool).await.unwrap();
    }
    assert_eq!(create(1000).await, StatusCode::TOO_MANY_REQUESTS);
    // Eighteen left, reserving 495 MiB of the 512 MiB image quota: of two concurrent
    // 10 MiB uploads, exactly one fits.
    sqlx::query("delete from upload_session where id in (select id from upload_session limit 2)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("update upload_session set size=73400320 where id in (select id from upload_session limit 1)").execute(&pool).await.unwrap();
    let ten = 10 * 1024 * 1024;
    let both = futures::future::join(create(ten), create(ten)).await;
    let mut both = [both.0, both.1];
    both.sort();
    assert_eq!(both, [StatusCode::OK, StatusCode::BAD_REQUEST]);
    runtime.close().await;
}

async fn word_file(paragraphs: usize) -> (Vec<u8>, Vec<docx::Paragraph>) {
    let mut zip = ZipWriter::new(Vec::new());
    zip.start("[Content_Types].xml", 6).await.unwrap();
    zip.write(docx::CONTENT_TYPES.as_bytes()).await.unwrap();
    zip.start("_rels/.rels", 6).await.unwrap();
    zip.write(docx::PACKAGE_RELS.as_bytes()).await.unwrap();
    zip.start("word/document.xml", 6).await.unwrap();
    let mut xml = String::from(docx::DOCUMENT_HEAD);
    let mut expected = Vec::new();
    for i in 0..paragraphs {
        let level = if i % 50 == 0 { 1 } else { 0 };
        let text = format!("Paragraph {i}: synthetic text with <markup> & “quotes” বাংলা");
        docx::paragraph_xml(&text, level, i % 3 == 0, &mut xml);
        expected.push(docx::Paragraph { text, level });
    }
    xml.push_str(docx::DOCUMENT_TAIL);
    zip.write(xml.as_bytes()).await.unwrap();
    (zip.finish().await.unwrap().0, expected)
}

async fn upload_import(
    router: &Router,
    doc: Uuid,
    owner: &str,
    file: &[u8],
) -> (StatusCode, Value) {
    let imports = format!("/documents/{doc}/imports");
    let (status, created) = post(
        router,
        &imports,
        owner,
        json!({"kind":"import","size":file.len(),"sha256":sha(file),"filename":"report.docx"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let base = format!("{imports}/{}", created["id"].as_str().unwrap());
    let half = file.len() / 2;
    for (at, part) in [(0, &file[..half]), (half, &file[half..])] {
        assert_eq!(
            chunk(router, &base, owner, at, part, &sha(part)).await.0,
            StatusCode::OK
        );
    }
    let (status, _) = post(router, &format!("{base}/complete"), owner, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..300 {
        let (_, body, _) = get(router, &base, owner).await;
        if matches!(body["import"]["state"].as_str(), Some("done" | "failed")) {
            return (StatusCode::OK, body);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("import did not finish");
}

#[sqlx::test(migrations = "../../migrations")]
async fn word_import_streams_in_batches_and_exports_streaming(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let owner = identity(&pool, "import-owner@example.test").await;
    let viewer = identity(&pool, "import-viewer@example.test").await;
    let doc = document(&router, &owner).await;
    let (file, expected) = word_file(4_321).await;
    // Only an editor may import.
    let (status, _) = post(
        &router,
        &format!("/documents/{doc}/imports"),
        &viewer,
        json!({"kind":"import","size":file.len(),"sha256":sha(&file),"filename":"x.docx"}),
    )
    .await;
    assert!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
        "{status}"
    );
    let (_, body) = upload_import(&router, doc, &owner, &file).await;
    assert_eq!(body["import"]["state"], "done", "{body}");
    assert_eq!(body["import"]["paragraphs"], expected.len());
    assert!(body["import"]["original_root"]
        .as_str()
        .is_some_and(|r| r.len() == 64));
    let events: i64 = sqlx::query_scalar("select count(*) from event where document_id=$1")
        .bind(doc)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        events,
        expected.len() as i64 + 1,
        "one root and one event per paragraph"
    );
    let staged: i64 = sqlx::query_scalar("select count(*) from upload_chunk")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(staged, 0);
    // The kept original reads back byte for byte from its content tree.
    let root: String =
        sqlx::query_scalar("select original_root from import_job where document_id=$1")
            .bind(doc)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let mut store = engine_core::shared_checkpoint::postgres::PgStore::new(&mut connection);
    let mut original = Vec::new();
    engine_core::shared_checkpoint::typed::read_asset(
        &mut store,
        engine_shared::DocumentId(doc),
        &root.try_into().unwrap(),
        &mut original,
        Default::default(),
    )
    .await
    .unwrap();
    drop(store);
    assert_eq!(original, file);
    // Streaming export: the same paragraphs, in order.
    let (status, _, exported) =
        get(&router, &format!("/documents/{doc}/export.docx"), &owner).await;
    assert_eq!(status, StatusCode::OK);
    let mut source = exported.as_slice();
    let entries = engine_core::ooxml::zip::central_directory(&mut source, Default::default())
        .await
        .unwrap();
    let entry = entries
        .iter()
        .find(|e| e.name == "word/document.xml")
        .unwrap();
    let start = engine_core::ooxml::zip::data_offset(&mut source, entry)
        .await
        .unwrap() as usize;
    let mut inflater = engine_core::ooxml::zip::Inflater::new(entry);
    let mut parsed = docx::Body::default();
    inflater
        .feed(
            &exported[start..start + entry.compressed as usize],
            &mut |d| parsed.feed(d, false),
        )
        .unwrap();
    parsed.feed(&[], true).unwrap();
    assert_eq!(parsed.take(), expected);
    // Checkpoint egress: publish a v3 checkpoint, stream its nodes without loading the state.
    let head = expected.len() as i64 + 1;
    engine_core::shared_checkpoint::postgres::take_with_codec(
        &pool,
        engine_shared::DocumentId(doc),
        head,
        Default::default(),
        engine_core::shared_checkpoint::postgres::Codec::V3,
    )
    .await
    .unwrap();
    let (status, _, lines) = get(
        &router,
        &format!("/documents/{doc}/checkpoints/{head}/nodes"),
        &owner,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let lines: Vec<Value> = lines
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    assert_eq!(lines.len(), expected.len() + 2);
    assert_eq!(lines.last().unwrap()["end"]["nodes"], expected.len() + 1);
    assert_ne!(
        get(
            &router,
            &format!("/documents/{doc}/checkpoints/{head}/nodes"),
            &viewer
        )
        .await
        .0,
        StatusCode::OK
    );
    // A second import into the now non-empty file is refused by the job.
    let (_, body) = upload_import(&router, doc, &owner, &file).await;
    assert_eq!(body["import"]["state"], "failed");
    assert_eq!(body["import"]["error"], "Import into an empty file");
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn import_bombs_and_hostile_xml_fail_without_touching_history(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let pool = runtime.pool.clone();
    let router = app(test_state(pool.clone()));
    let owner = identity(&pool, "bomb-owner@example.test").await;
    // 100 MiB of zeros deflates to about 100 KB: far over the 100:1 expansion cap.
    let mut zip = ZipWriter::new(Vec::new());
    zip.start("word/document.xml", 9).await.unwrap();
    let zeros = vec![0u8; 1 << 20];
    for _ in 0..100 {
        zip.write(&zeros).await.unwrap();
    }
    let bomb = zip.finish().await.unwrap().0;
    let doc = document(&router, &owner).await;
    let (_, body) = upload_import(&router, doc, &owner, &bomb).await;
    assert_eq!(body["import"]["state"], "failed", "{body}");
    assert!(
        body["import"]["error"].as_str().unwrap().contains("limit"),
        "{body}"
    );
    // An entity declaration is refused by the XML reader.
    let mut zip = ZipWriter::new(Vec::new());
    zip.start("word/document.xml", 6).await.unwrap();
    zip.write(br#"<!DOCTYPE w [<!ENTITY a "aaaaaaaaaa">]><w:document><w:body><w:p><w:r><w:t>&a;</w:t></w:r></w:p></w:body></w:document>"#).await.unwrap();
    let hostile = zip.finish().await.unwrap().0;
    let doc2 = document(&router, &owner).await;
    let (_, body) = upload_import(&router, doc2, &owner, &hostile).await;
    assert_eq!(body["import"]["state"], "failed", "{body}");
    for d in [doc, doc2] {
        let events: i64 = sqlx::query_scalar("select count(*) from event where document_id=$1")
            .bind(d)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(events, 0);
    }
    runtime.close().await;
}
