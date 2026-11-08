//! OAuth 2.1 grants for remote MCP clients (migration 0058) through the real router: a
//! client registers, a person consents for one project, the code is single use and bound
//! to PKCE and the redirect URI, refresh tokens rotate, the access token is an ordinary
//! agent device session that reads, a revoked key ends the grant, and an MCP session is
//! bound to the key that opened it. Requires a reachable Postgres (DATABASE_URL).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sqlx::PgPool;

mod agent_world;
mod common;
use agent_world::*;

const REDIRECT: &str = "https://chatgpt.com/connector_platform_oauth_redirect";

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ))
}

async fn enable_agents(w: &World) {
    let view = get(
        &w.app,
        &format!("/projects/{}/agent-policy", w.project),
        &w.owner_login,
    )
    .await;
    let revision = view.json()["revision"].as_i64().unwrap().to_string();
    let saved = raw(
        &w.app,
        "PUT",
        &format!("/projects/{}/agent-policy", w.project),
        Some(&w.owner_login),
        &[("if-match", &revision)],
        Some(json!({"enabled":true})),
    )
    .await;
    assert_eq!(saved.code(), 200, "{}", saved.text());
}

async fn consent(w: &World, client: &str, verifier: &str) -> String {
    let (status, body) = call(
        &w.app,
        "POST",
        "/oauth/authorize",
        Some(&w.owner_login),
        json!({"client_id":client,"redirect_uri":REDIRECT,"code_challenge":challenge(verifier),"code_challenge_method":"S256","project":w.project}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    body["code"].as_str().unwrap().to_owned()
}

async fn token(w: &World, body: Value) -> (u16, Value) {
    let (status, v) = call(&w.app, "POST", "/oauth/token", None, body).await;
    (status.as_u16(), v)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_remote_client_gets_read_access_through_a_persons_consent(pool: PgPool) {
    let w = World::new(pool, true).await;
    enable_agents(&w).await;

    // Registration: HTTPS redirect URIs only.
    let (status, bad) = call(
        &w.app,
        "POST",
        "/oauth/register",
        None,
        json!({"redirect_uris":["http://evil.example/cb"]}),
    )
    .await;
    assert_eq!(status, 400, "{bad}");
    let (status, reg) = call(
        &w.app,
        "POST",
        "/oauth/register",
        None,
        json!({"redirect_uris":[REDIRECT],"client_name":"ChatGPT"}),
    )
    .await;
    assert_eq!(status, 201, "{reg}");
    let client = reg["client_id"].as_str().unwrap().to_owned();

    // Consent needs a signed-in person, a registered redirect URI and S256.
    let (status, _) = call(&w.app, "POST", "/oauth/authorize", None, json!({"client_id":client,"redirect_uri":REDIRECT,"code_challenge":challenge(&"v".repeat(43)),"code_challenge_method":"S256","project":w.project})).await;
    assert_eq!(status, 401);
    let (status, _) = call(&w.app, "POST", "/oauth/authorize", Some(&w.owner_login), json!({"client_id":client,"redirect_uri":"https://chatgpt.com/other","code_challenge":challenge(&"v".repeat(43)),"code_challenge_method":"S256","project":w.project})).await;
    assert_eq!(status, 400);
    let (status, _) = call(&w.app, "POST", "/oauth/authorize", Some(&w.owner_login), json!({"client_id":client,"redirect_uri":REDIRECT,"code_challenge":"x","code_challenge_method":"plain","project":w.project})).await;
    assert_eq!(status, 400);

    // The code: wrong verifier refused, and the code is gone after any attempt.
    let verifier = "a".repeat(64);
    let code = consent(&w, &client, &verifier).await;
    let (status, e) = token(&w, json!({"grant_type":"authorization_code","code":code,"redirect_uri":REDIRECT,"client_id":client,"code_verifier":"b".repeat(64)})).await;
    assert_eq!((status, e["error"].as_str()), (400, Some("invalid_grant")));
    let (status, _) = token(&w, json!({"grant_type":"authorization_code","code":code,"redirect_uri":REDIRECT,"client_id":client,"code_verifier":verifier})).await;
    assert_eq!(
        status, 400,
        "a code is single use, even after a failed attempt"
    );

    let code = consent(&w, &client, &verifier).await;
    let (status, t) = token(&w, json!({"grant_type":"authorization_code","code":code,"redirect_uri":REDIRECT,"client_id":client,"code_verifier":verifier})).await;
    assert_eq!(status, 200, "{t}");
    assert_eq!(t["scope"], "content:read");
    let access = t["access_token"].as_str().unwrap().to_owned();
    let refresh = t["refresh_token"].as_str().unwrap().to_owned();
    // A second consent reused the same key: one grant per client, person and project.
    let keys: i64 = sqlx::query_scalar("select count(*) from oauth_grant")
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert_eq!(keys, 1);

    // The token is an agent device session: it reads, and cannot use account routes.
    let files = get(&w.app, &w.url("/files"), &access).await;
    assert_eq!(files.code(), 200, "{}", files.text());
    assert_ne!(get(&w.app, "/devices", &access).await.code(), 200);
    let (status, _) = call(&w.app, "POST", "/oauth/authorize", Some(&access), json!({"client_id":client,"redirect_uri":REDIRECT,"code_challenge":challenge(&verifier),"code_challenge_method":"S256","project":w.project})).await;
    assert_eq!(status, 401, "an agent token cannot consent");

    // Refresh rotates (presenting the old token again ends the grant: see
    // `a_reused_refresh_token_ends_the_grant`).
    let (status, t2) = token(
        &w,
        json!({"grant_type":"refresh_token","refresh_token":refresh,"client_id":client}),
    )
    .await;
    assert_eq!(status, 200, "{t2}");
    let refresh2 = t2["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(refresh2, refresh);

    // MCP: no bearer is 401; initialize opens a session bound to this key.
    let none = raw(&w.app, "POST", "/mcp", None, &[], Some(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}))).await;
    assert_eq!(none.code(), 401);
    assert!(none
        .header("www-authenticate")
        .unwrap()
        .starts_with("Bearer"));
    let init = raw(&w.app, "POST", "/mcp", Some(&access), &[], Some(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}))).await;
    assert_eq!(init.code(), 200, "{}", init.text());
    let session = init.header("mcp-session-id").unwrap();
    let list = raw(
        &w.app,
        "POST",
        "/mcp",
        Some(&access),
        &[("mcp-session-id", &session)],
        Some(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})),
    )
    .await;
    assert_eq!(list.code(), 200, "{}", list.text());
    let names: Vec<String> = list.json()["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        names.contains(&"memory".to_owned()) && !names.contains(&"propose".to_owned()),
        "{names:?}"
    );
    let unknown = raw(
        &w.app,
        "POST",
        "/mcp",
        Some(&access),
        &[("mcp-session-id", "0".repeat(32).as_str())],
        Some(json!({"jsonrpc":"2.0","id":3,"method":"tools/list"})),
    )
    .await;
    assert_eq!(unknown.code(), 404);

    // Revoking the key in the profile ends the grant.
    let key: uuid::Uuid = sqlx::query_scalar("select key_id from oauth_grant")
        .fetch_one(w.pool())
        .await
        .unwrap();
    let (status, body) = call(
        &w.app,
        "POST",
        &format!("/devices/{key}/revoke"),
        Some(&w.owner_login),
        json!({}),
    )
    .await;
    assert!(status.is_success(), "{body}");
    let (status, e) = token(
        &w,
        json!({"grant_type":"refresh_token","refresh_token":refresh2,"client_id":client}),
    )
    .await;
    assert_eq!(
        (status, e["error"].as_str()),
        (400, Some("invalid_grant")),
        "{e}"
    );
    assert_ne!(get(&w.app, &w.url("/files"), &access).await.code(), 200);
}

/// A client registered and consented for the world's project: (client id, first token reply).
async fn granted(w: &World) -> (String, Value) {
    let (status, reg) = call(
        &w.app,
        "POST",
        "/oauth/register",
        None,
        json!({"redirect_uris":[REDIRECT]}),
    )
    .await;
    assert_eq!(status, 201, "{reg}");
    let client = reg["client_id"].as_str().unwrap().to_owned();
    let verifier = "c".repeat(64);
    let code = consent(w, &client, &verifier).await;
    let (status, t) = token(w, json!({"grant_type":"authorization_code","code":code,"redirect_uri":REDIRECT,"client_id":client,"code_verifier":verifier})).await;
    assert_eq!(status, 200, "{t}");
    (client, t)
}

fn refreshing(client: &str, t: &Value) -> Value {
    json!({"grant_type":"refresh_token","refresh_token":t["refresh_token"],"client_id":client})
}

/// Security review of main 362d4b1, finding 6: a rotated refresh token presented again means a
/// copy exists elsewhere, so the grant ends for every holder.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reused_refresh_token_ends_the_grant(pool: PgPool) {
    let w = World::new(pool, true).await;
    enable_agents(&w).await;
    let (client, first) = granted(&w).await;
    let (status, second) = token(&w, refreshing(&client, &first)).await;
    assert_eq!(status, 200, "{second}");
    let access = second["access_token"].as_str().unwrap().to_owned();
    assert_eq!(get(&w.app, &w.url("/files"), &access).await.code(), 200);
    let (status, e) = token(&w, refreshing(&client, &first)).await;
    assert_eq!((status, e["error"].as_str()), (400, Some("invalid_grant")));
    // The newest refresh token and its access token are dead too.
    let (status, e) = token(&w, refreshing(&client, &second)).await;
    assert_eq!(
        (status, e["error"].as_str()),
        (400, Some("invalid_grant")),
        "{e}"
    );
    assert_ne!(get(&w.app, &w.url("/files"), &access).await.code(), 200);
    let audited: i64 = sqlx::query_scalar(
        "select count(*) from operation_audit where action='oauth.refresh_reused'",
    )
    .fetch_one(w.pool())
    .await
    .unwrap();
    assert_eq!(audited, 1);
}

/// Finding 6: the refresh token is found and rotated in one statement, so two requests with
/// one token never both get tokens.
#[sqlx::test(migrations = "../../migrations")]
async fn two_refreshes_with_one_token_never_both_succeed(pool: PgPool) {
    let w = World::new(pool, true).await;
    enable_agents(&w).await;
    let (client, first) = granted(&w).await;
    let ((a, _), (b, _)) = tokio::join!(
        token(&w, refreshing(&client, &first)),
        token(&w, refreshing(&client, &first))
    );
    let mut codes = [a, b];
    codes.sort();
    assert_eq!(codes, [200, 400]);
}

/// Security review of main 362d4b1, finding 7: one address registers at most 20 clients an hour
/// (the address counts only when the web tier names it with the service key).
#[sqlx::test(migrations = "../../migrations")]
async fn registration_is_limited_per_address(pool: PgPool) {
    const SERVICE: &str = "isolated-oauth-registration-test-service-key";
    let w = World::bare_with(pool, true, Some(SERVICE.into())).await;
    let register = |address: &'static str, service: bool| {
        let app = w.app.clone();
        async move {
            let mut headers = vec![("x-dynodoc-client-address", address)];
            if service {
                headers.push(("x-dynodoc-service-key", SERVICE));
            }
            raw(
                &app,
                "POST",
                "/oauth/register",
                None,
                &headers,
                Some(json!({"redirect_uris":[REDIRECT]})),
            )
            .await
            .code()
        }
    };
    for _ in 0..20 {
        assert_eq!(register("203.0.113.7", true).await, 201);
    }
    assert_eq!(register("203.0.113.7", true).await, 429);
    assert_eq!(register("203.0.113.8", true).await, 201);
    // Without the service key the header is anyone's to send, and is ignored.
    assert_eq!(register("203.0.113.7", false).await, 201);
}
