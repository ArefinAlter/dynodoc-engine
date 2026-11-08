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

async fn connector_key(w: &World, login: &str, doc: Uuid) -> String {
    let (status, grant) = call(
        &w.app,
        "POST",
        &format!("/documents/{doc}/connectors"),
        Some(login),
        json!({"host":"word"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    grant["token"].as_str().unwrap().to_owned()
}

async fn connector_history(w: &World, login: &str, doc: Uuid, node: &str) -> Value {
    let key = connector_key(w, login, doc).await;
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

    // The panes' Team activity (and the Word preview's revision author) names the agent's
    // product and the person it acted for, never an address.
    let key = connector_key(&w, &olivia_login, doc).await;
    let changes = raw(
        &w.app,
        "GET",
        &format!(
            "/connector/documents/{doc}/changes?since_seq=0&since_chain_hash={}",
            "0".repeat(64)
        ),
        Some(&key),
        &[],
        None,
    )
    .await;
    assert_eq!(changes.code(), 200, "{}", changes.text());
    let latest = &changes.json()["activity"][0];
    assert_eq!(latest["agent"], true, "{latest}");
    assert_eq!(latest["agent_product"], "Claude Code", "{latest}");
    assert_eq!(latest["agent_for"], "Tester", "{latest}");
    assert!(!latest.to_string().contains("@"), "{latest}");
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
    // The desktop's signed-in route applies the same rules, and needs membership.
    let path = format!("/documents/{doc}/nodes/{first}/history");
    let mine = raw(&w.app, "GET", &path, Some(&olivia_login), &[], None).await;
    assert_eq!(mine.code(), 200, "{}", mine.text());
    assert!(mine.json()["events"][0]["request"]["session"]["prompt"].is_string());
    let theirs = raw(&w.app, "GET", &path, Some(&w.owner_login), &[], None).await;
    assert_eq!(
        theirs.json()["events"][0]["request"]["session"]["prompt_hidden"],
        true
    );
    assert_eq!(
        theirs.json()["events"][0]["request"]["session"]["prompt"],
        Value::Null
    );
    let (_, stranger) = person(w.pool(), "stranger@example.test").await;
    let refused = raw(&w.app, "GET", &path, Some(&stranger), &[], None).await;
    assert!([403, 404].contains(&refused.code()), "{}", refused.text());
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
    // Without an installed receipt key the chain verifies and the head is unsigned.
    let report = get(
        &w.app,
        &format!("/projects/{}/agent-sessions/{session}/verify", w.project),
        &w.owner_login,
    )
    .await
    .json();
    assert_eq!(report["chain"], "valid", "{report}");
    assert_eq!(report["seal"], "unsigned");
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

/// Open a session with one turn and propose `ops` in it; return (session, proposal).
async fn session_proposal(w: &World, token: &str, doc: Uuid, ops: Value) -> (String, String) {
    let opened = raw(
        &w.app,
        "POST",
        &w.url("/sessions"),
        Some(token),
        &[],
        Some(json!({"source":"mcp","product":"Claude Code","model":"claude-opus"})),
    )
    .await;
    assert_eq!(opened.code(), 200, "{}", opened.text());
    let session = opened.json()["session"].as_str().unwrap().to_owned();
    let turned = raw(
        &w.app,
        "POST",
        &w.url(&format!("/sessions/{session}/turns")),
        Some(token),
        &[],
        Some(json!({"prompt":"Tighten both paragraphs.","prompt_source":"agent"})),
    )
    .await;
    assert_eq!(turned.code(), 200, "{}", turned.text());
    let rev = get(&w.app, &w.url(&format!("/files/{doc}/outline")), token)
        .await
        .json()["rev"]
        .as_u64()
        .unwrap();
    let body = json!({"rev":rev,"request_id":Uuid::new_v4(),"session":session,"turn":1,"ops":ops});
    let proposed = raw(
        &w.app,
        "POST",
        &w.url(&format!("/files/{doc}/propose")),
        Some(token),
        &[],
        Some(body),
    )
    .await;
    assert_eq!(proposed.code(), 200, "{}", proposed.text());
    (
        session,
        proposed.json()["proposal"].as_str().unwrap().to_owned(),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_person_who_rewrites_an_agent_block_before_the_merge_takes_its_blame(pool: PgPool) {
    let w = World::new(pool, true).await;
    enable_writes(&w).await;
    let (olivia, olivia_login) = person(w.pool(), "olivia@example.test").await;
    w.member(w.project, olivia, "editor").await;
    let agent = w.agent_key(&olivia_login, 7, None).await;
    let (status, body) = w.grant(&agent, w.project, &WRITE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = w.token(&agent, w.project, &WRITE).await;
    let mut ops = Ops::default();
    let root = ops.node("form", None, 0, json!({"label":"Plan"}));
    let rewritten = ops.block(&root, 10, para("Alpha policy paragraph."));
    let light = ops.block(&root, 20, para("Beta budget paragraph."));
    let untouched = ops.block(&root, 30, para("Gamma closing paragraph."));
    let doc = w.file("Plan", "document", ops).await;
    let outline = get(&w.app, &w.url(&format!("/files/{doc}/outline")), &token)
        .await
        .json();
    let r = |i: usize| outline["blocks"][i]["ref"].as_str().unwrap().to_owned();
    let (_, proposal) = session_proposal(&w, &token, doc, json!([
        {"op":"set_text","ref":r(0),"text":"The alpha policy now covers every regional office and its staff."},
        {"op":"set_text","ref":r(1),"text":"The beta budget now lists every cost line for the coming year."}
    ])).await;
    let submitted = raw(
        &w.app,
        "POST",
        &w.url(&format!("/proposals/{proposal}/submit")),
        Some(&token),
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(submitted.code(), 200, "{}", submitted.text());

    // Olivia, for whom the agent acted, edits its draft before anyone merges: she rewrites the
    // first block, changes one word of the second and writes the third herself.
    let draft = call(
        &w.app,
        "GET",
        &format!("/documents/{doc}/drafts/{proposal}"),
        Some(&olivia_login),
        Value::Null,
    )
    .await;
    assert_eq!(draft.0, StatusCode::OK, "{}", draft.1);
    let revision = draft.1["draft"]["revision"].clone();
    let mut edits = Ops::default();
    for (node, text) in [
        (
            &rewritten,
            "Olivia wrote this sentence herself from scratch.",
        ),
        (
            &light,
            "The beta budget now lists every cost line for the next year.",
        ),
        (&untouched, "Gamma closing paragraph, signed off."),
    ] {
        edits.edit(node, "content", para(text));
        edits.edit(node, "label", json!(text));
    }
    let (status, saved) = call(
        &w.app,
        "POST",
        &format!("/documents/{doc}/drafts/{proposal}"),
        Some(&olivia_login),
        json!({"ops":edits.0,"revision":revision}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");

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

    // Rewritten: the person's block, no agent, no session.
    let blame = connector_history(&w, &olivia_login, doc, &rewritten).await;
    let request = &blame["events"][0]["request"];
    assert_eq!(request["author"]["id"], json!(olivia), "{blame}");
    assert_eq!(request["agent"], false);
    assert_eq!(request["edited_from_agent_draft"], false);
    assert_eq!(request["session"], Value::Null);
    // Lightly edited: still the agent's, with its session, marked as edited by Olivia.
    let blame = connector_history(&w, &olivia_login, doc, &light).await;
    let request = &blame["events"][0]["request"];
    assert_eq!(request["agent"], true, "{blame}");
    assert_eq!(request["edited_from_agent_draft"], true);
    assert_eq!(request["edited_by"]["id"], json!(olivia));
    assert_eq!(request["session"]["product"], "Claude Code");
    assert_eq!(request["session"]["turn"], 1);
    // A block only the person wrote in the agent's request is the person's.
    let blame = connector_history(&w, &olivia_login, doc, &untouched).await;
    assert_eq!(
        blame["events"][0]["request"]["author"]["id"],
        json!(olivia),
        "{blame}"
    );
    assert_eq!(blame["events"][0]["request"]["agent"], false);
}

async fn verify(w: &World, session: &str) -> Value {
    let reply = get(
        &w.app,
        &format!("/projects/{}/agent-sessions/{session}/verify", w.project),
        &w.owner_login,
    )
    .await;
    assert_eq!(reply.code(), 200, "{}", reply.text());
    reply.json()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_signed_session_head_exposes_a_tampered_record(pool: PgPool) {
    let w = World::with_signer(pool, true, Some(99)).await;
    w.enable_agents(w.project).await;
    enable_writes(&w).await;
    let (olivia, olivia_login) = person(w.pool(), "olivia@example.test").await;
    w.member(w.project, olivia, "editor").await;
    let agent = w.agent_key(&olivia_login, 7, None).await;
    let (status, body) = w.grant(&agent, w.project, &WRITE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = w.token(&agent, w.project, &WRITE).await;
    let opened = raw(
        &w.app,
        "POST",
        &w.url("/sessions"),
        Some(&token),
        &[],
        Some(json!({"source":"mcp","product":"Claude Code"})),
    )
    .await;
    let session = opened.json()["session"].as_str().unwrap().to_owned();
    for prompt in ["First request.", "Second request."] {
        let turned = raw(
            &w.app,
            "POST",
            &w.url(&format!("/sessions/{session}/turns")),
            Some(&token),
            &[],
            Some(json!({"prompt":prompt,"prompt_source":"agent"})),
        )
        .await;
        assert_eq!(turned.code(), 200, "{}", turned.text());
    }
    let report = verify(&w, &session).await;
    assert_eq!(report["verified"], true, "{report}");
    assert_eq!(
        (report["chain"].as_str(), report["seal"].as_str()),
        (Some("valid"), Some("valid"))
    );
    assert_eq!(
        (
            report["turns"].as_i64(),
            report["sealed_turns"].as_i64(),
            report["epoch"].as_i64()
        ),
        (Some(2), Some(2), Some(1))
    );
    // The agent itself cannot ask.
    let theirs = get(
        &w.app,
        &format!("/projects/{}/agent-sessions/{session}/verify", w.project),
        &token,
    )
    .await;
    assert_ne!(theirs.code(), 200);

    // Someone with database access rewrites a prompt: the chain breaks.
    let id = Uuid::parse_str(&session).unwrap();
    let owner = &w.runtime.owner;
    sqlx::raw_sql("alter table agent_turn disable trigger agent_turn_guard")
        .execute(owner)
        .await
        .unwrap();
    sqlx::query("update agent_turn set prompt='Forged request.' where session_id=$1 and seq=1")
        .bind(id)
        .execute(owner)
        .await
        .unwrap();
    let report = verify(&w, &session).await;
    assert_eq!(
        (report["verified"].as_bool(), report["chain"].as_str()),
        (Some(false), Some("broken")),
        "{report}"
    );

    // They also recompute every hash and the head: the chain is whole again, the seal is not.
    let (product, model, started): (String, Option<String>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("select product,model,started_at from agent_session where id=$1")
            .bind(id)
            .fetch_one(owner)
            .await
            .unwrap();
    let started = started.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let mut link = session_head(id, &product, model.as_deref(), &started);
    let turns: Vec<TurnRow> = sqlx::query_as("select seq,at,prompt,prompt_source,reasoning,redactions,hash from agent_turn where session_id=$1 order by seq").bind(id).fetch_all(owner).await.unwrap();
    for (seq, at, prompt, source, reasoning, redactions, _) in turns {
        let at = at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let prev = link;
        link = turn_hash(
            &prev,
            seq,
            &at,
            prompt.as_deref(),
            source.as_deref(),
            reasoning.as_deref(),
            redactions,
        );
        sqlx::query("update agent_turn set prev=$3,hash=$4 where session_id=$1 and seq=$2")
            .bind(id)
            .bind(seq)
            .bind(&prev[..])
            .bind(&link[..])
            .execute(owner)
            .await
            .unwrap();
    }
    sqlx::raw_sql("alter table agent_turn enable trigger agent_turn_guard")
        .execute(owner)
        .await
        .unwrap();
    sqlx::raw_sql("alter table agent_session disable trigger agent_session_guard")
        .execute(owner)
        .await
        .unwrap();
    sqlx::query("update agent_session set head=$2 where id=$1")
        .bind(id)
        .bind(&link[..])
        .execute(owner)
        .await
        .unwrap();
    sqlx::raw_sql("alter table agent_session enable trigger agent_session_guard")
        .execute(owner)
        .await
        .unwrap();
    let report = verify(&w, &session).await;
    assert_eq!(report["chain"], "valid", "{report}");
    assert_eq!(report["seal"], "invalid");
    assert_eq!(report["verified"], false);
}

/// The `ChangeAttributed` events of a document, the latest first.
async fn seals(w: &World, doc: Uuid) -> Vec<(i64, Value)> {
    sqlx::query_as("select seq,payload from event where document_id=$1 and type='ChangeAttributed' order by seq desc")
        .bind(doc)
        .fetch_all(&w.runtime.owner)
        .await
        .unwrap()
}

async fn verify_document(w: &World, doc: Uuid) -> Value {
    let (status, body) = call(
        &w.app,
        "GET",
        &format!("/documents/{doc}/verify"),
        Some(&w.owner_login),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn event_of(w: &World, doc: Uuid, node: &str, from: i64, to: i64) -> i64 {
    sqlx::query_scalar("select seq from event where document_id=$1 and target_node_id=$2 and seq between $3 and $4 order by seq limit 1")
        .bind(doc)
        .bind(node)
        .bind(from)
        .bind(to)
        .fetch_one(&w.runtime.owner)
        .await
        .unwrap()
}

/// Attribution layer C (decision 038): merging an agent's request seals who wrote each merged
/// event into the chain, the existing verify route checks it, a seal changed afterwards breaks
/// the chain, and a client cannot send one.
#[sqlx::test(migrations = "../../migrations")]
async fn a_merge_seals_agent_authorship_and_a_tampered_seal_fails_verification(pool: PgPool) {
    let w = World::new(pool, true).await;
    enable_writes(&w).await;
    let (olivia, olivia_login) = person(w.pool(), "olivia@example.test").await;
    w.member(w.project, olivia, "editor").await;
    let agent = w.agent_key(&olivia_login, 7, None).await;
    let (status, body) = w.grant(&agent, w.project, &WRITE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = w.token(&agent, w.project, &WRITE).await;
    let mut ops = Ops::default();
    let root = ops.node("form", None, 0, json!({"label":"Plan"}));
    let agents = ops.block(&root, 10, para("Alpha policy paragraph."));
    let taken = ops.block(&root, 20, para("Beta budget paragraph."));
    let doc = w.file("Plan", "document", ops).await;
    // A document without agent merges holds no seal and verifies as before.
    assert_eq!(verify_document(&w, doc).await["attributions"], 0);

    let outline = get(&w.app, &w.url(&format!("/files/{doc}/outline")), &token)
        .await
        .json();
    let r = |i: usize| outline["blocks"][i]["ref"].as_str().unwrap().to_owned();
    let (session, proposal) = session_proposal(&w, &token, doc, json!([
        {"op":"set_text","ref":r(0),"text":"The alpha policy now covers every regional office and its staff."},
        {"op":"set_text","ref":r(1),"text":"The beta budget now lists every cost line for the coming year."}
    ])).await;
    let submitted = raw(
        &w.app,
        "POST",
        &w.url(&format!("/proposals/{proposal}/submit")),
        Some(&token),
        &[],
        Some(json!({})),
    )
    .await;
    assert_eq!(submitted.code(), 200, "{}", submitted.text());
    // Olivia rewrites the second block in the agent's draft before the merge.
    let draft = call(
        &w.app,
        "GET",
        &format!("/documents/{doc}/drafts/{proposal}"),
        Some(&olivia_login),
        Value::Null,
    )
    .await;
    assert_eq!(draft.0, StatusCode::OK, "{}", draft.1);
    let mut edits = Ops::default();
    let text = "Olivia wrote this sentence herself from scratch.";
    edits.edit(&taken, "content", para(text));
    edits.edit(&taken, "label", json!(text));
    let (status, saved) = call(
        &w.app,
        "POST",
        &format!("/documents/{doc}/drafts/{proposal}"),
        Some(&olivia_login),
        json!({"ops":edits.0,"revision":draft.1["draft"]["revision"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    // A client cannot put a seal into a draft: it is not a content change.
    let forged = json!({"type":"ChangeAttributed","draft_id":proposal,"agent":olivia,"principal":olivia,"client_kind":"claude","merger":olivia,"first_seq":1,"last_seq":1,"parts":[{"seqs":[1]}]});
    let latest = call(
        &w.app,
        "GET",
        &format!("/documents/{doc}/drafts/{proposal}"),
        Some(&olivia_login),
        Value::Null,
    )
    .await;
    let (status, refused) = call(
        &w.app,
        "POST",
        &format!("/documents/{doc}/drafts/{proposal}"),
        Some(&olivia_login),
        json!({"ops":[forged],"revision":latest.1["draft"]["revision"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");

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
    let sealed = seals(&w, doc).await;
    assert_eq!(sealed.len(), 1);
    let (seq, seal) = &sealed[0];
    let seq = *seq;
    assert_eq!(
        merged["team_seq"],
        json!(seq),
        "the draft's new base includes the seal"
    );
    assert_eq!(seal["agent"], detail["request"]["agent"]["id"]);
    assert_eq!(seal["principal"], json!(olivia));
    assert_eq!(seal["merger"], json!(w.owner));
    assert_eq!(seal["last_seq"], json!(seq - 1));
    // Each merged event is named once: the agent's block by its session turn, the rewritten
    // one as Olivia's.
    let first = seal["first_seq"].as_i64().unwrap();
    let parts = seal["parts"].as_array().unwrap();
    let part_of = |s: i64| {
        parts
            .iter()
            .find(|p| p["seqs"].as_array().unwrap().contains(&json!(s)))
            .unwrap()
    };
    let mine = part_of(event_of(&w, doc, &agents, first, seq - 1).await);
    assert_eq!(mine["session"], json!(session), "{seal}");
    assert_eq!(mine["turn"], 1);
    assert!(mine.get("person").is_none());
    let hers = part_of(event_of(&w, doc, &taken, first, seq - 1).await);
    assert_eq!(hers["person"], json!(olivia), "{seal}");
    assert!(hers.get("session").is_none());
    assert_eq!(seal["sessions"][0]["id"], json!(session));
    assert_eq!(seal["sessions"][0]["turns"], 1);
    // The existing verify route checks the seal; block history points at it.
    let verdict = verify_document(&w, doc).await;
    assert_eq!(verdict["ok"], true, "{verdict}");
    assert_eq!(verdict["attributions"], 1);
    let blame = connector_history(&w, &olivia_login, doc, &agents).await;
    assert_eq!(blame["events"][0]["sealed_seq"], json!(seq), "{blame}");

    // Tampering: claim Olivia's block for the agent. The seal's content hash no longer matches.
    let owner = &w.runtime.owner;
    sqlx::raw_sql("alter table event disable trigger user")
        .execute(owner)
        .await
        .unwrap();
    let mut forged = seal.clone();
    for part in forged["parts"].as_array_mut().unwrap() {
        let part = part.as_object_mut().unwrap();
        part.remove("person");
        part.insert("session".into(), json!(session));
        part.insert("turn".into(), json!(1));
    }
    let rewrite = |payload: &Value| {
        sqlx::query("update event set payload=$3 where document_id=$1 and seq=$2")
            .bind(doc)
            .bind(seq)
            .bind(payload.clone())
            .execute(owner)
    };
    rewrite(&forged).await.unwrap();
    let verdict = verify_document(&w, doc).await;
    assert_eq!(verdict["ok"], false, "{verdict}");
    assert_eq!(verdict["broken_at_seq"], json!(seq));
    assert!(
        verdict["detail"].as_str().unwrap().contains("content_hash"),
        "{verdict}"
    );
    // The true payload verifies again.
    rewrite(seal).await.unwrap();
    assert_eq!(verify_document(&w, doc).await["ok"], true);
    sqlx::raw_sql("alter table event enable trigger user")
        .execute(owner)
        .await
        .unwrap();
}
