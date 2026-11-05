//! Agent sessions, turns and agent blame (decision 026, migration 0056) through the real
//! router and the restricted runtime login: an agent opens a session, records a turn with
//! a prompt (secrets redacted), proposes with the session and turn named, a person merges,
//! and the block's history names the agent, model, turn and, only for whom the capture
//! policy allows, the prompt. Requires a reachable Postgres (DATABASE_URL).

use axum::http::StatusCode;
use engine_api::agent::session::{session_head, turn_hash};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

mod agent_world;
mod common;
use agent_world::*;

/// seq, at, prompt, prompt_source, reasoning, redactions, hash
type TurnRow = (
    i32,
    chrono::DateTime<chrono::Utc>,
    Option<String>,
    Option<String>,
    Option<String>,
    i32,
    Vec<u8>,
);

const WRITE: [&str; 3] = ["content:read", "content:propose", "content:submit"];

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

async fn capture(w: &World, capture: &str, visibility: &str) -> Reply {
    let view = get(
        &w.app,
        &format!("/projects/{}/agent-capture", w.project),
        &w.owner_login,
    )
    .await;
    assert_eq!(view.code(), 200, "{}", view.text());
    let revision = view.json()["revision"].as_i64().unwrap().to_string();
    raw(
        &w.app,
        "PUT",
        &format!("/projects/{}/agent-capture", w.project),
        Some(&w.owner_login),
        &[("if-match", &revision)],
        Some(json!({"capture":capture,"prompt_visibility":visibility})),
    )
    .await
}

async fn connector_history(w: &World, login: &str, doc: Uuid, node: &str) -> Value {
    let (status, grant) = call(
        &w.app,
        "POST",
        &format!("/documents/{doc}/connectors"),
        Some(login),
        json!({"host":"word"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let key = grant["token"].as_str().unwrap().to_owned();
    let reply = raw(
        &w.app,
        "GET",
        &format!("/connector/documents/{doc}/nodes/{node}/history"),
        Some(&key),
        &[],
        None,
    )
    .await;
    assert_eq!(reply.code(), 200, "{}", reply.text());
    reply.json()
}

#[sqlx::test(migrations = "../../migrations")]
async fn sessions_turns_and_agent_blame_follow_the_capture_policy(pool: PgPool) {
    let w = World::new(pool, true).await;
    enable_writes(&w).await;
    let (olivia, olivia_login) = person(w.pool(), "olivia@example.test").await;
    w.member(w.project, olivia, "editor").await;
    let agent = w.agent_key(&olivia_login, 7, None).await;
    let (status, body) = w.grant(&agent, w.project, &WRITE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = w.token(&agent, w.project, &WRITE).await;

    // Default policy: full capture, prompts visible to their author only.
    let view = get(
        &w.app,
        &format!("/projects/{}/agent-capture", w.project),
        &w.owner_login,
    )
    .await;
    assert_eq!(view.json()["capture"], "full");
    assert_eq!(view.json()["prompt_visibility"], "author");
    assert_eq!(view.json()["configured"], false);
    // The agent cannot read or change the capture policy.
    assert_ne!(
        get(
            &w.app,
            &format!("/projects/{}/agent-capture", w.project),
            &token
        )
        .await
        .code(),
        200
    );

    let mut ops = Ops::default();
    let root = ops.node("form", None, 0, json!({"label":"Plan"}));
    let first = ops.block(&root, 10, para("Alpha policy paragraph."));
    ops.block(&root, 20, para("Beta budget paragraph."));
    let doc = w.file("Plan", "document", ops).await;

    // Open a session and record a turn whose prompt carries a secret.
    let opened = raw(&w.app, "POST", &w.url("/sessions"), Some(&token), &[], Some(json!({"source":"acp","product":"Claude Code","product_version":"2.1","model":"claude-opus"}))).await;
    assert_eq!(opened.code(), 200, "{}", opened.text());
    let session = opened.json()["session"].as_str().unwrap().to_owned();
    assert_eq!(opened.json()["capture"], "full");
    // The DCT form for the MCP server.
    let dct = raw(
        &w.app,
        "POST",
        &w.url("/sessions"),
        Some(&token),
        &[("accept", "text/vnd.dynodoc.dct; v=1")],
        Some(json!({"source":"mcp","product":"Claude Desktop"})),
    )
    .await;
    assert_eq!(dct.code(), 200, "{}", dct.text());
    assert!(
        dct.text().starts_with("dd/1 session session="),
        "{}",
        dct.text()
    );
    assert!(dct.text().contains(" capture=full "), "{}", dct.text());
    let turned = raw(&w.app, "POST", &w.url(&format!("/sessions/{session}/turns")), Some(&token), &[], Some(json!({"prompt":"Make the first paragraph clearer. My key is sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV","prompt_source":"launcher","reasoning":"The first paragraph is vague."}))).await;
    assert_eq!(turned.code(), 200, "{}", turned.text());
    assert_eq!(turned.json()["turn"], 1);
    assert_eq!(turned.json()["redactions"], 1);

    // Naming a turn the session does not have, or another agent's session, is refused.
    let outline = get(&w.app, &w.url(&format!("/files/{doc}/outline")), &token)
        .await
        .json();
    let (r, h) = (
        outline["blocks"][0]["ref"].as_str().unwrap().to_owned(),
        outline["blocks"][0]["h"].as_str().unwrap().to_owned(),
    );
    let rev = outline["rev"].as_u64().unwrap();
    let body = |turn: i64| json!({"rev":rev,"request_id":Uuid::new_v4(),"session":session,"turn":turn,"ops":[{"op":"set_text","ref":r,"text":"Alpha procedure paragraph.","base":h}]});
    assert_eq!(
        raw(
            &w.app,
            "POST",
            &w.url(&format!("/files/{doc}/propose")),
            Some(&token),
            &[],
            Some(body(2))
        )
        .await
        .code(),
        400
    );
    let mut foreign = body(1);
    foreign["session"] = json!(Uuid::new_v4());
    assert_eq!(
        raw(
            &w.app,
            "POST",
            &w.url(&format!("/files/{doc}/propose")),
            Some(&token),
            &[],
            Some(foreign)
        )
        .await
        .code(),
        400
    );
    let proposed = raw(
        &w.app,
        "POST",
        &w.url(&format!("/files/{doc}/propose")),
        Some(&token),
        &[],
        Some(body(1)),
    )
    .await;
    assert_eq!(proposed.code(), 200, "{}", proposed.text());
    let proposal = proposed.json()["proposal"].as_str().unwrap().to_owned();
    let receipt: (Option<Uuid>, Option<i32>, Vec<String>) = sqlx::query_as("select session_id,turn,nodes from agent_proposal_receipt where draft_id=$1 and kind='propose'")
        .bind(Uuid::parse_str(&proposal).unwrap())
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert_eq!(receipt.0.map(|u| u.to_string()), Some(session.clone()));
    assert_eq!(receipt.1, Some(1));
    assert_eq!(receipt.2, vec![first.clone()]);

    // The agent submits; the owner (a person) merges.
    let submitted = raw(
        &w.app,
        "POST",
        &w.url(&format!("/proposals/{proposal}/submit")),
        Some(&token),
        &[],
        Some(json!({"note":"Clearer."})),
    )
    .await;
    assert_eq!(submitted.code(), 200, "{}", submitted.text());
    let detail = call(
        &w.app,
        "GET",
        &format!("/documents/{doc}/change-requests/{proposal}"),
        Some(&w.owner_login),
        Value::Null,
    )
    .await
    .1;
    let head = w.head(doc).await;
    let (status, merged) = call(
        &w.app,
        "POST",
        &format!("/documents/{doc}/change-requests/{proposal}/merge"),
        Some(&w.owner_login),
        json!({"team_seq":head,"revision":detail["revision"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{merged}");

    // Olivia, for whom the agent acted, sees the prompt (redacted); the owner does not.
    let hers = connector_history(&w, &olivia_login, doc, &first).await;
    let s = &hers["events"][0]["request"]["session"];
    assert_eq!(hers["events"][0]["request"]["agent"], true);
    assert_eq!(s["product"], "Claude Code");
    assert_eq!(s["model"], "claude-opus");
    assert_eq!(s["source"], "acp");
    assert_eq!(s["turn"], 1);
    assert_eq!(s["prompt_source"], "launcher");
    let prompt = s["prompt"].as_str().unwrap();
    assert!(
        prompt.starts_with("Make the first paragraph clearer."),
        "{prompt}"
    );
    assert!(!prompt.contains("ABCDEFGHIJ"), "secret stored: {prompt}");
    assert_eq!(s["redactions"], 1);
    let owners = connector_history(&w, &w.owner_login, doc, &first).await;
    let s = &owners["events"][0]["request"]["session"];
    assert_eq!(s["product"], "Claude Code");
    assert_eq!(s["prompt"], Value::Null);
    assert_eq!(s["prompt_hidden"], true);
    // Members may read prompts once the policy says so.
    assert_eq!(capture(&w, "full", "members").await.code(), 200);
    let owners = connector_history(&w, &w.owner_login, doc, &first).await;
    assert!(owners["events"][0]["request"]["session"]["prompt"].is_string());

    // The turns form a verifiable chain from the session header.
    let (product, model, started, head_db): (
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Vec<u8>,
    ) = sqlx::query_as("select product,model,started_at,head from agent_session where id=$1")
        .bind(Uuid::parse_str(&session).unwrap())
        .fetch_one(w.pool())
        .await
        .unwrap();
    let started = started.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let mut link = session_head(
        Uuid::parse_str(&session).unwrap(),
        &product,
        model.as_deref(),
        &started,
    );
    let turns: Vec<TurnRow> = sqlx::query_as("select seq,at,prompt,prompt_source,reasoning,redactions,hash from agent_turn where session_id=$1 order by seq")
        .bind(Uuid::parse_str(&session).unwrap())
        .fetch_all(w.pool())
        .await
        .unwrap();
    for (seq, at, prompt, source, reasoning, redactions, hash) in turns {
        let at = at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        link = turn_hash(
            &link,
            seq,
            &at,
            prompt.as_deref(),
            source.as_deref(),
            reasoning.as_deref(),
            redactions,
        );
        assert_eq!(link.to_vec(), hash);
    }
    assert_eq!(link.to_vec(), head_db);
    // A turn cannot be rewritten, only have its text removed (erasure).
    let rewrite = sqlx::query("update agent_turn set prompt='forged' where session_id=$1")
        .bind(Uuid::parse_str(&session).unwrap())
        .execute(w.pool())
        .await;
    assert!(rewrite.is_err());

    // Actions-only capture stores turns without text; off refuses sessions.
    assert_eq!(capture(&w, "actions", "author").await.code(), 200);
    let t2 = raw(
        &w.app,
        "POST",
        &w.url(&format!("/sessions/{session}/turns")),
        Some(&token),
        &[],
        Some(json!({"prompt":"Second request"})),
    )
    .await;
    assert_eq!(t2.code(), 200, "{}", t2.text());
    assert_eq!(t2.json()["stored_text"], false);
    let stored: Option<String> =
        sqlx::query_scalar("select prompt from agent_turn where session_id=$1 and seq=2")
            .bind(Uuid::parse_str(&session).unwrap())
            .fetch_one(w.pool())
            .await
            .unwrap();
    assert_eq!(stored, None);
    assert_eq!(capture(&w, "off", "author").await.code(), 200);
    let refused = raw(
        &w.app,
        "POST",
        &w.url("/sessions"),
        Some(&token),
        &[],
        Some(json!({"product":"Codex"})),
    )
    .await;
    assert_eq!(refused.code(), 403, "{}", refused.text());
}
