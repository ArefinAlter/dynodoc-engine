//! Decision 038 trust boundaries through the real router and the runtime login: an
//! organisation's denied client kinds are refused on every path (agent routes, the remote MCP
//! endpoint, OAuth consent and token), and the client and person filters of the proposals
//! inbox, usage and audit only narrow what a caller could already see. Requires a reachable
//! Postgres (DATABASE_URL).

use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

mod agent_world;
mod common;
use agent_world::*;

const REDIRECT: &str = "https://chatgpt.com/connector_platform_oauth_redirect";
const VERIFIER: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        VERIFIER.as_bytes(),
    ))
}

async fn register(w: &World) -> String {
    let (status, reg) = call(
        &w.app,
        "POST",
        "/oauth/register",
        None,
        json!({"redirect_uris":[REDIRECT],"client_name":"ChatGPT"}),
    )
    .await;
    assert_eq!(status, 201, "{reg}");
    reg["client_id"].as_str().unwrap().to_owned()
}

async fn consent(w: &World, client: &str) -> (StatusCode, Value) {
    call(&w.app, "POST", "/oauth/authorize", Some(&w.owner_login), json!({"client_id":client,"redirect_uri":REDIRECT,"code_challenge":challenge(),"code_challenge_method":"S256","project":w.project,"propose":false})).await
}

async fn deny(w: &World, org: Uuid, kinds: &[&str]) {
    sqlx::query("update organisation set agent_clients_denied=$2 where id=$1")
        .bind(org)
        .bind(kinds)
        .execute(&w.runtime.owner)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_denied_client_kind_is_refused_everywhere(pool: PgPool) {
    let w = World::new(pool, true).await;
    let (_, local) = w.owner_reader().await;
    assert_eq!(get(&w.app, &w.url("/files"), &local).await.code(), 200);
    let client = register(&w).await;
    let (status, granted) = consent(&w, &client).await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    let (status, token) = call(&w.app, "POST", "/oauth/token", None, json!({"grant_type":"authorization_code","code":granted["code"],"redirect_uri":REDIRECT,"client_id":client,"code_verifier":VERIFIER})).await;
    assert_eq!(status, StatusCode::OK, "{token}");
    let remote = token["access_token"].as_str().unwrap().to_owned();
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"chatgpt","version":"1"}}});
    assert_eq!(
        raw(
            &w.app,
            "POST",
            "/mcp",
            Some(&remote),
            &[],
            Some(init.clone())
        )
        .await
        .code(),
        200
    );

    // The owner's organisation denies ChatGPT.
    let org: Uuid = sqlx::query_scalar(
        "insert into organisation(name,created_by) values('Synthetic org',$1) returning id",
    )
    .bind(w.owner)
    .fetch_one(&w.runtime.owner)
    .await
    .unwrap();
    sqlx::query("insert into organisation_member(organisation_id,identity_id,source,role) values($1,$2,'manual','owner')")
        .bind(org)
        .bind(w.owner)
        .execute(&w.runtime.owner)
        .await
        .unwrap();
    deny(&w, org, &["chatgpt"]).await;
    // Agent routes (the gateway), the remote MCP endpoint, a new consent and a refresh.
    assert_eq!(get(&w.app, &w.url("/files"), &remote).await.code(), 403);
    assert_eq!(
        raw(
            &w.app,
            "POST",
            "/mcp",
            Some(&remote),
            &[],
            Some(init.clone())
        )
        .await
        .code(),
        403
    );
    let (status, refused) = consent(&w, &client).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    let (status, refreshed) = call(&w.app, "POST", "/oauth/token", None, json!({"grant_type":"refresh_token","refresh_token":token["refresh_token"],"client_id":client})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refreshed}");
    assert_eq!(refreshed["error"], "invalid_grant");
    // Another kind is unaffected, and denying it too stops it.
    assert_eq!(get(&w.app, &w.url("/files"), &local).await.code(), 200);
    deny(&w, org, &["chatgpt", "device"]).await;
    assert_eq!(get(&w.app, &w.url("/files"), &local).await.code(), 403);
    // The settings route refuses an unknown kind.
    let view = get(
        &w.app,
        &format!("/organisations/{org}/sign-in"),
        &w.owner_login,
    )
    .await;
    assert_eq!(view.code(), 200, "{}", view.text());
    assert_eq!(
        view.json()["organisation"]["agent_clients_denied"],
        json!(["chatgpt", "device"])
    );
    let revision = view.json()["organisation"]["revision"].as_i64().unwrap();
    let settings = format!("/organisations/{org}/sign-in/settings");
    let (status, _) = call(
        &w.app,
        "PUT",
        &settings,
        Some(&w.owner_login),
        json!({"revision":revision,"agent_clients_denied":["skynet"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, saved) = call(
        &w.app,
        "PUT",
        &settings,
        Some(&w.owner_login),
        json!({"revision":revision,"agent_clients_denied":[]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(get(&w.app, &w.url("/files"), &local).await.code(), 200);
}

#[sqlx::test(migrations = "../../migrations")]
async fn filters_narrow_and_never_widen_the_inbox_usage_and_audit(pool: PgPool) {
    let w = World::new(pool, true).await;
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
        Some(json!({"enabled":true,"write_mode":"draft"})),
    )
    .await;
    assert_eq!(saved.code(), 200, "{}", saved.text());
    let (olivia, olivia_login) = person(w.pool(), "olivia@example.test").await;
    w.member(w.project, olivia, "editor").await;
    let agent = w.agent_key(&olivia_login, 7, None).await;
    let scopes = ["content:propose", "content:read"];
    let (status, body) = w.grant(&agent, w.project, &scopes).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = w.token(&agent, w.project, &scopes).await;
    let mut ops = Ops::default();
    let root = ops.node("form", None, 0, json!({"label":"Plan"}));
    ops.block(&root, 10, para("Alpha policy paragraph."));
    let doc = w.file("Plan", "document", ops).await;
    let outline = get(&w.app, &w.url(&format!("/files/{doc}/outline")), &token)
        .await
        .json();
    let proposed = raw(&w.app, "POST", &w.url(&format!("/files/{doc}/propose")), Some(&token), &[], Some(json!({"rev":outline["rev"],"request_id":Uuid::new_v4(),"ops":[{"op":"set_text","ref":outline["blocks"][0]["ref"],"text":"The alpha policy, revised."}]}))).await;
    assert_eq!(proposed.code(), 200, "{}", proposed.text());

    let inbox = |login: String, query: String| {
        let w = &w;
        async move {
            call(
                &w.app,
                "GET",
                &format!("/projects/{}/agent-proposals?state=all{query}", w.project),
                Some(&login),
                Value::Null,
            )
            .await
        }
    };
    // The unsubmitted draft is Olivia's alone: naming her as the principal shows the owner
    // nothing more.
    let (status, page) = inbox(w.owner_login.clone(), format!("&principal={olivia}")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["items"].as_array().unwrap().len(), 0, "{page}");
    let (_, page) = inbox(olivia_login.clone(), format!("&principal={olivia}")).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "{page}");
    let (_, page) = inbox(olivia_login.clone(), "&client_kind=device".into()).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "{page}");
    let (_, page) = inbox(olivia_login.clone(), "&client_kind=chatgpt".into()).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 0, "{page}");
    let (_, page) = inbox(olivia_login.clone(), format!("&principal={}", w.owner)).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 0, "{page}");
    let (status, _) = inbox(olivia_login.clone(), "&client_kind=skynet".into()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Usage and audit stay with owners and managers, whatever the filter.
    for route in ["agent-usage", "agent-audit"] {
        let (status, _) = call(
            &w.app,
            "GET",
            &format!(
                "/projects/{}/{route}?principal={olivia}&client_kind=device",
                w.project
            ),
            Some(&olivia_login),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route}");
    }
    let owner_get = |tail: String| {
        let w = &w;
        async move {
            let (status, body) = call(
                &w.app,
                "GET",
                &format!("/projects/{}/{tail}", w.project),
                Some(&w.owner_login),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{tail} {body}");
            body
        }
    };
    let calls = |v: &Value| -> i64 {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["calls"].as_i64().unwrap())
            .sum()
    };
    assert!(calls(&owner_get("agent-usage?client_kind=device".into()).await) > 0);
    assert_eq!(
        calls(&owner_get("agent-usage?client_kind=claude".into()).await),
        0
    );
    assert!(calls(&owner_get(format!("agent-usage?principal={olivia}")).await) > 0);
    assert_eq!(
        calls(&owner_get(format!("agent-usage?principal={}", w.owner)).await),
        0
    );
    let audit = owner_get(format!("agent-audit?principal={olivia}")).await;
    let actions: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"agent.proposal.created"), "{audit}");
    assert!(audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["principal"]["id"] == json!(olivia)));
    let none = owner_get("agent-audit?client_kind=claude".into()).await;
    assert!(none["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["client_kind"] == "claude"));
    assert!(
        !none.to_string().contains("agent.proposal.created"),
        "{none}"
    );
}
