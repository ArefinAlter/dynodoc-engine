//! Remote MCP sessions shared by API replicas (migration 0114): two routers on one database stand
//! for two replicas. A session opened on one is served by the other, only for the key that opened
//! it, ends everywhere when ended on either, and ends when idle.
mod common;

mod agent_world;
use agent_world::*;

use axum::Router;
use engine_api::{app, auth::AuthConfig, AppState};
use serde_json::json;
use sqlx::PgPool;

/// A second replica: another router, with its own memory, on the same database and keys.
fn replica(w: &World) -> Router {
    let mut state = AppState::new(
        w.runtime.pool.clone(),
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.agent_gateway = true;
    app(state)
}

async fn initialize(app: &Router, bearer: &str) -> String {
    let init = raw(app, "POST", "/mcp", Some(bearer), &[], Some(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}))).await;
    assert_eq!(init.code(), 200, "{}", init.text());
    init.header("mcp-session-id").unwrap()
}

async fn list(app: &Router, bearer: &str, session: &str) -> u16 {
    raw(
        app,
        "POST",
        "/mcp",
        Some(bearer),
        &[("mcp-session-id", session)],
        Some(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})),
    )
    .await
    .code()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_session_opened_on_one_replica_is_served_and_ended_on_every_replica(pool: PgPool) {
    let w = World::new(pool, true).await;
    let b = replica(&w);
    let (_, bearer) = w.owner_reader().await;
    let session = initialize(&w.app, &bearer).await;
    // Only the hash of the session id is stored.
    let stored: Vec<u8> = sqlx::query_scalar("select id_hash from mcp_http_session")
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert_eq!(stored.len(), 32);
    assert_ne!(stored, session.as_bytes());

    assert_eq!(
        list(&b, &bearer, &session).await,
        200,
        "the other replica serves it"
    );
    assert_eq!(list(&w.app, &bearer, &session).await, 200);

    // Another key of the same person is not the session's owner, on either replica.
    let other = w.agent_key(&w.owner_login, 8, None).await;
    let (status, body) = w.grant(&other, w.project, &["content:read"]).await;
    assert_eq!(status.as_u16(), 200, "{body}");
    let other_bearer = w.token(&other, w.project, &["content:read"]).await;
    assert_eq!(list(&b, &other_bearer, &session).await, 404);
    assert_eq!(list(&w.app, &other_bearer, &session).await, 404);

    // Ended on B: gone on A too, although A still holds its server in memory.
    let end = raw(
        &b,
        "DELETE",
        "/mcp",
        Some(&bearer),
        &[("mcp-session-id", &session)],
        None,
    )
    .await;
    assert_eq!(end.code(), 204);
    assert_eq!(list(&w.app, &bearer, &session).await, 404);
    assert_eq!(list(&b, &bearer, &session).await, 404);

    // Idle past the limit: over on every replica.
    let idle = initialize(&b, &bearer).await;
    assert_eq!(list(&w.app, &bearer, &idle).await, 200);
    sqlx::query("update mcp_http_session set seen_at=now()-interval '2 hours'")
        .execute(&w.runtime.owner)
        .await
        .unwrap();
    assert_eq!(list(&w.app, &bearer, &idle).await, 404);
    assert_eq!(list(&b, &bearer, &idle).await, 404);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_account_keeps_at_most_fifty_live_sessions(pool: PgPool) {
    let w = World::new(pool, true).await;
    let (_, bearer) = w.owner_reader().await;
    let first = initialize(&w.app, &bearer).await;
    sqlx::query("update mcp_http_session set seen_at=now()-interval '10 minutes'")
        .execute(&w.runtime.owner)
        .await
        .unwrap();
    for _ in 0..50 {
        initialize(&w.app, &bearer).await;
    }
    let count: i64 = sqlx::query_scalar("select count(*) from mcp_http_session")
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert_eq!(count, 50);
    assert_eq!(
        list(&w.app, &bearer, &first).await,
        404,
        "the least recently used went"
    );
}
