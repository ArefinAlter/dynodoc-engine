//! Shared agent memory (decision 026 part 2, migration 0057) through the real router and the
//! restricted runtime login: an agent proposes a memory citing a block, the proposal stays
//! out of the agents' briefing until a person accepts it, the server pins each cited block's
//! content and reports when it changes or goes, edits need the revision read, and every
//! change is a chained revision the database refuses to rewrite. Requires a reachable
//! Postgres (DATABASE_URL).

use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

mod agent_world;
mod common;
use agent_world::*;

const WRITE: [&str; 2] = ["content:read", "content:propose"];

fn ids(v: &Value) -> Vec<String> {
    v["memories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_owned())
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn agents_propose_people_decide_and_citations_track_their_blocks(pool: PgPool) {
    let w = World::new(pool, true).await;
    let (olivia, olivia_login) = person(w.pool(), "olivia@example.test").await;
    w.member(w.project, olivia, "editor").await;
    let (victor, victor_login) = person(w.pool(), "victor@example.test").await;
    w.member(w.project, victor, "viewer").await;
    let agent = w.agent_key(&olivia_login, 9, None).await;
    let (status, body) = w.grant(&agent, w.project, &WRITE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = w.token(&agent, w.project, &WRITE).await;

    let mut ops = Ops::default();
    let root = ops.node("form", None, 0, json!({"label":"Plan"}));
    let first = ops.block(&root, 10, para("We cite sources in author-date style."));
    let second = ops.block(&root, 20, para("Budget figures are in euros."));
    let doc = w.file("Plan", "document", ops).await;
    let memory_url = w.url("/memory");

    // The agent proposes a memory citing the first block; the server pins the block hash.
    let proposed = raw(&w.app, "POST", &memory_url, Some(&token), &[], Some(json!({"kind":"style","body":"Citations use author-date style.","citations":[{"file":&doc.simple().to_string()[..8],"ref":&first[first.len()-6..]}]}))).await;
    assert_eq!(proposed.code(), 200, "{}", proposed.text());
    assert_eq!(proposed.json()["state"], "proposed");
    let memory = proposed.json()["memory"].as_str().unwrap().to_owned();
    // A hash supplied by the agent is ignored; an unknown or foreign block is refused.
    for bad in [
        json!({"kind":"fact","body":"x","citations":[{"file":doc,"ref":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}]}),
        json!({"kind":"fact","body":"x","citations":[{"file":doc,"ref":"ZZZZZZZZ"}]}),
        // Agents cite by file and ref, never by raw document and node ids.
        json!({"kind":"fact","body":"x","citations":[{"document":doc,"node":first}]}),
        json!({"kind":"instruction","body":"x"}),
        json!({"kind":"fact","body":""}),
        json!({"kind":"fact","body":"x","session":Uuid::new_v4()}),
    ] {
        let reply = raw(
            &w.app,
            "POST",
            &memory_url,
            Some(&token),
            &[],
            Some(bad.clone()),
        )
        .await;
        assert_eq!(reply.code(), 400, "{bad} {}", reply.text());
    }
    // A file the agent cannot see is the file tools' uniform 404.
    let foreign = json!({"kind":"fact","body":"x","citations":[{"file":Uuid::new_v4(),"ref":&first[first.len()-6..]}]});
    let reply = raw(
        &w.app,
        "POST",
        &memory_url,
        Some(&token),
        &[],
        Some(foreign),
    )
    .await;
    assert_eq!(reply.code(), 404, "{}", reply.text());

    // A proposal is not in the briefing.
    let brief = raw(&w.app, "GET", &memory_url, Some(&token), &[], None).await;
    assert_eq!(brief.code(), 200, "{}", brief.text());
    assert!(ids(&brief.json()).is_empty());

    // A viewer reads but cannot decide; agents cannot use the people routes.
    let people = format!("/projects/{}/agent-memory", w.project);
    let listed = get(&w.app, &people, &victor_login).await;
    assert_eq!(listed.code(), 200, "{}", listed.text());
    assert_eq!(listed.json()["items"][0]["state"], "proposed");
    assert_eq!(listed.json()["items"][0]["by_agent"], true);
    assert_eq!(
        listed.json()["items"][0]["citations"][0]["validity"],
        "valid"
    );
    let pinned = listed.json()["items"][0]["citations"][0]["hash"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(pinned.len(), 64);
    let accept = format!("{people}/{memory}/accept");
    assert_eq!(
        raw(&w.app, "POST", &accept, Some(&victor_login), &[], None)
            .await
            .code(),
        403
    );
    assert_ne!(
        raw(&w.app, "POST", &accept, Some(&token), &[], None)
            .await
            .code(),
        200
    );
    assert_ne!(get(&w.app, &people, &token).await.code(), 200);

    // Olivia accepts: agents now see it, with its citation valid.
    let accepted = raw(&w.app, "POST", &accept, Some(&olivia_login), &[], None).await;
    assert_eq!(accepted.code(), 200, "{}", accepted.text());
    assert_eq!(accepted.json()["revision"], 2);
    let brief = raw(&w.app, "GET", &memory_url, Some(&token), &[], None)
        .await
        .json();
    assert_eq!(ids(&brief), vec![memory.clone()]);
    assert_eq!(brief["trust"], "data");
    // The DCT form (what the MCP server asks for): one line per memory, text quoted last.
    let dct = raw(
        &w.app,
        "GET",
        &memory_url,
        Some(&token),
        &[("accept", "text/vnd.dynodoc.dct; v=1")],
        None,
    )
    .await;
    assert_eq!(dct.code(), 200, "{}", dct.text());
    let dct = dct.text();
    assert!(
        dct.starts_with("dd/1 memory mode=briefing n=1 trust=data"),
        "{dct}"
    );
    assert!(dct.contains(&format!("@{memory} kind=style state=active rev=2 by=agent cites={}/{first}:valid \"Citations use author-date style.\"", &doc.simple().to_string()[..8])), "{dct}");
    // The same proposal again answers with the memory it already is.
    let again = raw(
        &w.app,
        "POST",
        &memory_url,
        Some(&token),
        &[],
        Some(json!({"kind":"style","body":"Citations use author-date style."})),
    )
    .await;
    assert_eq!(again.json()["memory"], memory.as_str(), "{}", again.text());
    assert_eq!(again.json()["duplicate"], true);
    assert_eq!(again.json()["state"], "active");
    let found = raw(
        &w.app,
        "GET",
        &format!("{memory_url}?mode=search&q=AUTHOR-date"),
        Some(&token),
        &[],
        None,
    )
    .await
    .json();
    assert_eq!(ids(&found), vec![memory.clone()]);
    let none = raw(
        &w.app,
        "GET",
        &format!("{memory_url}?mode=search&q=%25"),
        Some(&token),
        &[],
        None,
    )
    .await
    .json();
    assert!(ids(&none).is_empty(), "a % is a literal, not a wildcard");

    // The cited block changes: the memory leaves the briefing and search marks it stale.
    let mut change = Ops::default();
    change.edit(
        &first,
        "content",
        para("We cite sources with numbered notes."),
    );
    w.edit(doc, change).await;
    let brief = raw(&w.app, "GET", &memory_url, Some(&token), &[], None)
        .await
        .json();
    assert!(ids(&brief).is_empty());
    let found = raw(
        &w.app,
        "GET",
        &format!("{memory_url}?mode=search&q=author"),
        Some(&token),
        &[],
        None,
    )
    .await
    .json();
    assert_eq!(found["memories"][0]["citations"][0]["validity"], "stale");

    // An edit needs the revision read; a stale one is a conflict, not an overwrite.
    let item = format!("{people}/{memory}");
    let stale = raw(
        &w.app,
        "PUT",
        &item,
        Some(&w.owner_login),
        &[("if-match", "1")],
        Some(json!({"body":"Citations use numbered notes."})),
    )
    .await;
    assert_eq!(stale.code(), 409, "{}", stale.text());
    assert_eq!(stale.json()["code"], "memory_changed");
    assert_eq!(stale.json()["details"]["current"]["revision"], 2);
    assert_eq!(
        stale.json()["details"]["yours"]["body"],
        "Citations use numbered notes."
    );
    let edited = raw(&w.app, "PUT", &item, Some(&w.owner_login), &[("if-match", "2")], Some(json!({"body":"Citations use numbered notes.","citations":[{"document":doc,"node":first}]}))).await;
    assert_eq!(edited.code(), 200, "{}", edited.text());
    assert_eq!(edited.json()["revision"], 3);
    assert_eq!(edited.json()["citations"][0]["validity"], "valid");
    assert_ne!(edited.json()["citations"][0]["hash"], pinned);
    let brief = raw(&w.app, "GET", &memory_url, Some(&token), &[], None)
        .await
        .json();
    assert_eq!(
        brief["memories"][0]["body"],
        "Citations use numbered notes."
    );

    // A person writes a memory directly; it is active at once. Deleting the cited block
    // marks the citation gone.
    let written = raw(&w.app, "POST", &people, Some(&olivia_login), &[], Some(json!({"kind":"fact","body":"Budget is in euros.","citations":[{"document":doc,"node":second}]}))).await;
    assert_eq!(written.code(), 200, "{}", written.text());
    assert_eq!(written.json()["state"], "active");
    let budget = written.json()["id"].as_str().unwrap().to_owned();
    let mut gone = Ops::default();
    gone.0.push(json!({"type":"NodeDeleted","node_id":second}));
    w.edit(doc, gone).await;
    let found = raw(
        &w.app,
        "GET",
        &format!("{memory_url}?mode=search&q=euros"),
        Some(&token),
        &[],
        None,
    )
    .await
    .json();
    assert_eq!(found["memories"][0]["citations"][0]["validity"], "gone");

    // Delete: agents see a tombstone in changes, without the text.
    let since = "2000-01-01T00:00:00Z";
    let deleted = raw(
        &w.app,
        "POST",
        &format!("{people}/{budget}/delete"),
        Some(&olivia_login),
        &[],
        None,
    )
    .await;
    assert_eq!(deleted.code(), 200, "{}", deleted.text());
    let changes = raw(
        &w.app,
        "GET",
        &format!("{memory_url}?mode=changes&since={since}"),
        Some(&token),
        &[],
        None,
    )
    .await
    .json();
    let tomb = changes["memories"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == budget.as_str())
        .unwrap();
    assert_eq!(tomb["state"], "deleted");
    assert_eq!(tomb["body"], Value::Null);
    assert_eq!(
        raw(
            &w.app,
            "POST",
            &format!("{people}/{budget}/restore"),
            Some(&olivia_login),
            &[],
            None
        )
        .await
        .code(),
        409
    );

    // The chain: each revision's prev is the hash before it, and the database refuses a
    // rewrite of a revision or a move of the memory without one.
    let chain: Vec<(i32, String, Vec<u8>, Vec<u8>)> = sqlx::query_as("select revision,action,prev,hash from agent_memory_revision where memory_id=$1::uuid order by revision")
        .bind(&memory)
        .fetch_all(w.pool())
        .await
        .unwrap();
    assert_eq!(
        chain.iter().map(|c| c.1.as_str()).collect::<Vec<_>>(),
        ["propose", "accept", "edit"]
    );
    assert_eq!(chain[0].2, vec![0u8; 32]);
    assert_eq!(chain[1].2, chain[0].3);
    assert_eq!(chain[2].2, chain[1].3);
    assert!(
        sqlx::query("update agent_memory_revision set body='forged' where memory_id=$1::uuid")
            .bind(&memory)
            .execute(w.pool())
            .await
            .is_err()
    );
    assert!(sqlx::query(
        "update agent_memory set body='forged', revision=revision+1 where id=$1::uuid"
    )
    .bind(&memory)
    .execute(w.pool())
    .await
    .is_err());
}
