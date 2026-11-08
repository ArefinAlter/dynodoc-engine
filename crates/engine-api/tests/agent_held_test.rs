//! Held writes of remote AI agents (decision 029 section 5, migration 0066) through the real
//! router and the restricted runtime login: a person ticks "propose" at OAuth consent, the
//! client's writes are held (nothing staged, nobody else sees them), only that person's
//! account login confirms or declines them (never an agent session, an OAuth token or a
//! connector key), a confirmed proposal goes to review, and a held write expires after seven
//! days. Requires a reachable Postgres (DATABASE_URL).

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

async fn enable_writes(w: &World) {
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
        Some(json!({"enabled":true,"write_mode":"change_request","submit_requires_person":false,"proposals_per_day":1000,"open_proposals":100})),
    )
    .await;
    assert_eq!(saved.code(), 200, "{}", saved.text());
}

/// Register a client, consent as the owner (`propose` ticked or not) and exchange the code.
async fn remote_token(w: &World, propose: bool) -> Value {
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
    let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        VERIFIER.as_bytes(),
    ));
    let (status, consent) = call(&w.app, "POST", "/oauth/authorize", Some(&w.owner_login), json!({"client_id":client,"redirect_uri":REDIRECT,"code_challenge":challenge,"code_challenge_method":"S256","project":w.project,"propose":propose})).await;
    assert_eq!(status, 200, "{consent}");
    let (status, token) = call(&w.app, "POST", "/oauth/token", None, json!({"grant_type":"authorization_code","code":consent["code"],"redirect_uri":REDIRECT,"client_id":client,"code_verifier":VERIFIER})).await;
    assert_eq!(status, 200, "{token}");
    token
}

async fn propose(w: &World, token: &str, doc: Uuid, text: &str) -> Reply {
    let outline = get(&w.app, &w.url(&format!("/files/{doc}/outline")), token)
        .await
        .json();
    let (r, h) = (
        outline["blocks"][0]["ref"].as_str().unwrap().to_owned(),
        outline["blocks"][0]["h"].as_str().unwrap().to_owned(),
    );
    let body = json!({"rev":outline["rev"],"request_id":Uuid::new_v4(),"name":"Clearer","ops":[{"op":"set_text","ref":r,"text":text,"base":h}]});
    raw(
        &w.app,
        "POST",
        &w.url(&format!("/files/{doc}/propose")),
        Some(token),
        &[],
        Some(body),
    )
    .await
}

async fn count(w: &World, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(w.pool()).await.unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn remote_writes_wait_for_their_person_and_only_a_person_decides(pool: PgPool) {
    let w = World::new(pool, true).await;
    enable_writes(&w).await;
    let mut ops = Ops::default();
    let root = ops.node("form", None, 0, json!({"label":"Plan"}));
    ops.block(&root, 10, para("Alpha policy paragraph."));
    let doc = w.file("Plan", "document", ops).await;

    // Read-only unless the person ticks it.
    let read = remote_token(&w, false).await;
    assert_eq!(read["scope"], "content:read");
    let refused = propose(&w, read["access_token"].as_str().unwrap(), doc, "No.").await;
    assert_eq!(refused.code(), 403, "{}", refused.text());

    let token = remote_token(&w, true).await;
    assert_eq!(token["scope"], "content:propose content:read");
    let access = token["access_token"].as_str().unwrap().to_owned();
    // The write profile on /mcp.
    let init = raw(&w.app, "POST", "/mcp", Some(&access), &[], Some(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"chatgpt","version":"1"}}}))).await;
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
    assert!(list.text().contains("\"propose\""), "{}", list.text());

    // A remote proposal is held: nothing is staged, the inbox and other people see nothing.
    let held = propose(&w, &access, doc, "Alpha procedure paragraph.").await;
    assert_eq!(held.code(), 200, "{}", held.text());
    assert_eq!(held.json()["state"], "held", "{}", held.text());
    let held_id = held.json()["held"].as_str().unwrap().to_owned();
    assert_eq!(count(&w, "select count(*) from workspace_draft").await, 0);
    assert_eq!(
        count(&w, "select count(*) from agent_proposal_receipt").await,
        0
    );
    let inbox = get(
        &w.app,
        &format!("/projects/{}/agent-proposals", w.project),
        &w.owner_login,
    )
    .await;
    assert_eq!(inbox.code(), 200, "{}", inbox.text());
    assert!(!inbox.text().contains("Clearer"), "{}", inbox.text());
    let (olivia, olivia_login) = person(w.pool(), "olivia@example.test").await;
    w.member(w.project, olivia, "editor").await;
    let theirs = get(&w.app, "/agent-held", &olivia_login).await;
    assert_eq!(theirs.json()["items"], json!([]), "{}", theirs.text());

    // The person sees the tool, the client, the summary and the dry-run diff.
    let mine = get(&w.app, "/agent-held", &w.owner_login).await.json();
    let item = &mine["items"][0];
    assert_eq!(item["id"], json!(held_id), "{mine}");
    assert_eq!(item["tool"], "propose");
    assert_eq!(item["client_name"], "ChatGPT");
    assert!(item["summary"]
        .as_str()
        .unwrap()
        .contains("Alpha procedure paragraph."));
    assert!(
        item["preview"].as_str().is_some_and(|p| !p.is_empty()),
        "{mine}"
    );

    // No agent credential can confirm: a local agent's device session, the OAuth access
    // token, a connector key. Another person cannot either.
    let local = w.agent_key(&w.owner_login, 7, None).await;
    let (status, body) = w
        .grant(&local, w.project, &["content:read", "content:propose"])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let device = w
        .token(&local, w.project, &["content:read", "content:propose"])
        .await;
    let (status, grant) = call(
        &w.app,
        "POST",
        &format!("/documents/{doc}/connectors"),
        Some(&w.owner_login),
        json!({"host":"word"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let connector = grant["token"].as_str().unwrap().to_owned();
    for (who, credential) in [
        ("device session", device.as_str()),
        ("oauth token", access.as_str()),
        ("connector key", connector.as_str()),
    ] {
        for action in ["confirm", "decline"] {
            let reply = raw(
                &w.app,
                "POST",
                &format!("/agent-held/{held_id}/{action}"),
                Some(credential),
                &[],
                Some(json!({})),
            )
            .await;
            assert!(
                matches!(reply.code(), 401 | 403),
                "{who} {action}: {}",
                reply.code()
            );
        }
        assert!(matches!(
            get(&w.app, "/agent-held", credential).await.code(),
            401 | 403
        ));
    }
    let other = raw(
        &w.app,
        "POST",
        &format!("/agent-held/{held_id}/confirm"),
        Some(&olivia_login),
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(other.code(), 404);
    assert_eq!(count(&w, "select count(*) from workspace_draft").await, 0);

    // The person confirms: the proposal is staged as the agent's and goes to review.
    let (status, confirmed) = call(
        &w.app,
        "POST",
        &format!("/agent-held/{held_id}/confirm"),
        Some(&w.owner_login),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    assert_eq!(confirmed["state"], "confirmed", "{confirmed}");
    assert_eq!(confirmed["result"]["state"], "open", "{confirmed}");
    let submitted: (bool, bool) = sqlx::query_as("select submitted_at is not null,exists(select 1 from agent_identity a where a.identity_id=d.created_by) from workspace_draft d")
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert_eq!(submitted, (true, true));
    assert_eq!(
        count(
            &w,
            "select count(*) from operation_audit where action='agent.held.confirmed'"
        )
        .await,
        1
    );
    // Once only.
    let again = raw(
        &w.app,
        "POST",
        &format!("/agent-held/{held_id}/confirm"),
        Some(&w.owner_login),
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(again.code(), 404);

    // Declined: nothing happens and the text is gone.
    let second = propose(&w, &access, doc, "Alpha rules paragraph.").await;
    let second = second.json()["held"].as_str().unwrap().to_owned();
    let (status, declined) = call(
        &w.app,
        "POST",
        &format!("/agent-held/{second}/decline"),
        Some(&w.owner_login),
        json!({}),
    )
    .await;
    assert_eq!(
        (status, declined["state"].as_str()),
        (StatusCode::OK, Some("declined"))
    );
    let kept: (Value, Option<String>) =
        sqlx::query_as("select body,preview from agent_held_write where id=$1")
            .bind(Uuid::parse_str(&second).unwrap())
            .fetch_one(w.pool())
            .await
            .unwrap();
    assert_eq!(kept, (json!({}), None));
    assert_eq!(count(&w, "select count(*) from workspace_draft").await, 1);
    assert_eq!(
        count(
            &w,
            "select count(*) from operation_audit where action='agent.held.declined'"
        )
        .await,
        1
    );

    // Expired after seven days: it leaves the list and cannot be confirmed.
    let third = propose(&w, &access, doc, "Alpha guidance paragraph.").await;
    let third = third.json()["held"].as_str().unwrap().to_owned();
    let days: f64 = sqlx::query_scalar("select (extract(epoch from expires_at-created_at)/86400)::float8 from agent_held_write where id=$1")
        .bind(Uuid::parse_str(&third).unwrap())
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert!((days - 7.0).abs() < 0.01, "{days}");
    let owner = &w.runtime.owner;
    sqlx::raw_sql("alter table agent_held_write disable trigger agent_held_write_guard")
        .execute(owner)
        .await
        .unwrap();
    sqlx::query("update agent_held_write set created_at=now()-interval '8 days',expires_at=now()-interval '1 day' where id=$1")
        .bind(Uuid::parse_str(&third).unwrap())
        .execute(owner)
        .await
        .unwrap();
    sqlx::raw_sql("alter table agent_held_write enable trigger agent_held_write_guard")
        .execute(owner)
        .await
        .unwrap();
    assert_eq!(
        get(&w.app, "/agent-held", &w.owner_login).await.json()["items"],
        json!([])
    );
    let late = raw(
        &w.app,
        "POST",
        &format!("/agent-held/{third}/confirm"),
        Some(&w.owner_login),
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(late.code(), 404);
    let expired: (String, Value) =
        sqlx::query_as("select state,body from agent_held_write where id=$1")
            .bind(Uuid::parse_str(&third).unwrap())
            .fetch_one(w.pool())
            .await
            .unwrap();
    assert_eq!(expired, ("expired".to_owned(), json!({})));

    // A remote memory proposal is held as well, and becomes a proposed memory on confirm.
    let remembered = raw(
        &w.app,
        "POST",
        &w.url("/memory"),
        Some(&access),
        &[],
        Some(json!({"kind":"fact","body":"Budgets are in euros."})),
    )
    .await;
    assert_eq!(remembered.json()["state"], "held", "{}", remembered.text());
    assert_eq!(count(&w, "select count(*) from agent_memory").await, 0);
    let id = remembered.json()["held"].as_str().unwrap().to_owned();
    let (status, confirmed) = call(
        &w.app,
        "POST",
        &format!("/agent-held/{id}/confirm"),
        Some(&w.owner_login),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    assert_eq!(confirmed["result"]["state"], "proposed", "{confirmed}");
    assert_eq!(
        count(
            &w,
            "select count(*) from agent_memory where state='proposed'"
        )
        .await,
        1
    );

    // A local agent (not a remote grant) is not held.
    let direct = propose(&w, &device, doc, "Alpha direct paragraph.").await;
    assert_eq!(direct.code(), 200, "{}", direct.text());
    assert_ne!(direct.json()["state"], "held");
}

#[sqlx::test(migrations = "../../migrations")]
async fn held_writes_expire_on_the_retention_timer_without_a_read(pool: PgPool) {
    let w = World::new(pool, true).await;
    enable_writes(&w).await;
    let mut ops = Ops::default();
    let root = ops.node("form", None, 0, json!({"label":"Plan"}));
    ops.block(&root, 10, para("Alpha policy paragraph."));
    let doc = w.file("Plan", "document", ops).await;
    let token = remote_token(&w, true).await;
    let access = token["access_token"].as_str().unwrap().to_owned();
    let old = propose(&w, &access, doc, "Alpha old paragraph.").await;
    let old = Uuid::parse_str(old.json()["held"].as_str().unwrap()).unwrap();
    let fresh = propose(&w, &access, doc, "Alpha new paragraph.").await;
    let fresh = Uuid::parse_str(fresh.json()["held"].as_str().unwrap()).unwrap();
    let owner = &w.runtime.owner;
    sqlx::raw_sql("alter table agent_held_write disable trigger agent_held_write_guard")
        .execute(owner)
        .await
        .unwrap();
    sqlx::query("update agent_held_write set created_at=now()-interval '8 days',expires_at=now()-interval '1 day' where id=$1")
        .bind(old)
        .execute(owner)
        .await
        .unwrap();
    sqlx::raw_sql("alter table agent_held_write enable trigger agent_held_write_guard")
        .execute(owner)
        .await
        .unwrap();

    // Nobody reads the list: the retention pass alone expires the old item and clears its text.
    let outcome = engine_api::retention::run_once(
        w.pool(),
        &engine_api::retention::RetentionConfig::default(),
        &Default::default(),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, engine_api::retention::Outcome::Ran(_)));
    assert_eq!(
        held_state(w.pool(), old).await,
        ("expired".into(), json!({}), String::new())
    );
    assert_eq!(held_state(w.pool(), fresh).await.0, "held");
}

async fn held_state(pool: &PgPool, id: Uuid) -> (String, Value, String) {
    sqlx::query_as("select state,body,summary from agent_held_write where id=$1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}
