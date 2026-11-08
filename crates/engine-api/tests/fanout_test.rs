//! Several API replicas on one database (docs/SELF-HOSTED-EDITION.md 6.2 and 6.6, decision 037):
//! an event written through one replica reaches a stream held by another, each sequence once
//! and in order (`DYNODOC_EVENT_FANOUT=postgres`, and `poll`); `/readyz` reports the database
//! and the event listener. Real PostgreSQL, the restricted runtime login, the real router.
mod common;

use std::time::Duration;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use engine_api::{
    app,
    auth::{store, token, AuthConfig},
    fanout::{self, Mode},
    AppState,
};
use futures::StreamExt;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

const KEY: [u8; 32] = [9; 32];

fn state(pool: PgPool, mode: Mode) -> AppState {
    let mut state = AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.fanout.mode = mode;
    state
}

/// A second pool to the same database as the same login: another process's pool.
async fn second_pool(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap()
}

async fn send(router: &Router, method: &str, uri: &str, token: &str, body: Value) -> Value {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(status.is_success(), "{uri}: {status} {bytes:?}");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn ready(router: &Router) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn wait_ready(router: &Router) {
    for _ in 0..100 {
        if ready(router).await.0 == StatusCode::OK {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the replica never became ready: {:?}", ready(router).await);
}

/// The `id:` sequences in the frames of `stream` until `count` arrived; each must arrive within
/// `within` of the previous one.
async fn sequences(
    stream: &mut (impl futures::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin),
    count: usize,
    within: Duration,
) -> Vec<i64> {
    let mut seen = Vec::new();
    let mut text = String::new();
    while seen.len() < count {
        let chunk = tokio::time::timeout(within, stream.next())
            .await
            .unwrap_or_else(|_| panic!("no event within {within:?}; had {seen:?}"))
            .expect("stream ended")
            .unwrap();
        text.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = text.find("\n\n") {
            let frame: String = text.drain(..end + 2).collect();
            for line in frame.lines() {
                if let Some(id) = line.strip_prefix("id:") {
                    seen.push(id.trim().parse().unwrap());
                }
            }
        }
    }
    seen
}

async fn open_stream(
    router: &Router,
    doc: Uuid,
    token: &str,
) -> impl futures::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin {
    let request = Request::get(format!("/documents/{doc}/stream"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).starts_with(": connected"));
    body
}

async fn write(router: &Router, doc: Uuid, token: &str, pos: &str) -> i64 {
    let made = send(
        router,
        "POST",
        &format!("/documents/{doc}/ops/node-create"),
        token,
        json!({"node_type": "form", "pos": pos}),
    )
    .await;
    made["event"]["seq"].as_i64().unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_write_on_one_replica_reaches_a_stream_on_another_once_and_in_order(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let a_state = state(runtime.pool.clone(), Mode::Postgres);
    let b_state = state(second_pool(&runtime.pool).await, Mode::Postgres);
    fanout::spawn(a_state.clone()).expect("fan-out on A");
    fanout::spawn(b_state.clone()).expect("fan-out on B");
    let (a, b) = (app(a_state), app(b_state));
    wait_ready(&a).await;
    wait_ready(&b).await;

    let author = store::upsert_identity(&runtime.pool, "author@example.test", None)
        .await
        .unwrap()
        .id
        .0;
    let token = token::mint(&KEY, author, 3600).unwrap();
    let created = send(&a, "POST", "/documents", &token, json!({"title": "Shared"})).await;
    let doc: Uuid = serde_json::from_value(created["id"].clone()).unwrap();
    let head = write(&a, doc, &token, "a0").await;

    let mut on_b = open_stream(&b, doc, &token).await;
    // Through A, then B (its own fast path and the notification of the same write), then A.
    let mut written = Vec::new();
    for (router, pos) in [(&a, "a1"), (&a, "a2"), (&b, "a3"), (&a, "a4"), (&a, "a5")] {
        written.push(write(router, doc, &token, pos).await);
    }
    let last = *written.last().unwrap();
    assert!(head < written[0]);
    // The backfill (1 to head) and then every write, from whichever replica.
    let got = sequences(&mut on_b, last as usize, Duration::from_secs(2)).await;
    let expected: Vec<i64> = (1..=last).collect();
    assert_eq!(got, expected, "each sequence once, in order");
    // Nothing more arrives (no duplicate after the last).
    let extra = tokio::time::timeout(Duration::from_millis(300), on_b.next()).await;
    if let Ok(Some(Ok(chunk))) = extra {
        assert!(
            !String::from_utf8_lossy(&chunk).contains("id:"),
            "{chunk:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn poll_mode_delivers_another_replicas_writes(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let a = app(state(runtime.pool.clone(), Mode::Local));
    let b_state = state(second_pool(&runtime.pool).await, Mode::Poll);
    fanout::spawn(b_state.clone()).expect("fan-out on B");
    let b = app(b_state);
    let author = store::upsert_identity(&runtime.pool, "author@example.test", None)
        .await
        .unwrap()
        .id
        .0;
    let token = token::mint(&KEY, author, 3600).unwrap();
    let created = send(&a, "POST", "/documents", &token, json!({"title": "Polled"})).await;
    let doc: Uuid = serde_json::from_value(created["id"].clone()).unwrap();
    let mut on_b = open_stream(&b, doc, &token).await;
    let first = write(&a, doc, &token, "a0").await;
    let second = write(&a, doc, &token, "a1").await;
    let got = sequences(&mut on_b, 2, Duration::from_secs(2)).await;
    assert_eq!(got, vec![first, second]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn readiness_reports_the_database_and_the_listener(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool).await;
    let local = app(state(runtime.pool.clone(), Mode::Local));
    let (status, body) = ready(&local).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(body["checks"]["database"], true);
    // Postgres mode with no listener running: not ready, and it says which check failed.
    let waiting = app(state(runtime.pool.clone(), Mode::Postgres));
    let (status, body) = ready(&waiting).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["checks"]["event_listener"], false);
    assert_eq!(body["checks"]["database"], true);
    // A closed pool: the database check fails, with no error detail in the answer.
    let closed = second_pool(&runtime.pool).await;
    let down = app(state(closed.clone(), Mode::Local));
    closed.close().await;
    let (status, body) = ready(&down).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["checks"]["database"], false);
    assert_eq!(body.as_object().unwrap().len(), 2, "{body}");
}
