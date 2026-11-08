//! Token-efficiency harness, H0 and the byte half of H1 (docs/AI-AGENT-TOKEN-EFFICIENCY.md
//! sections 5 and 8, decision 038): reproducible read tasks over a synthetic document, run
//! against the local stack (the real router over the restricted runtime login, served on a
//! loopback port) by a scripted MCP client that drives the real `engine-mcp` server and its
//! HTTP backend, exactly what `engine-cli mcp` runs. No model is called.
//!
//! Arms, per task:
//! - `dct`: the MCP tool results as shipped (Dynodoc Compact Text);
//! - `json`: the same calls answered as the JSON mirror (the routes with `Accept: application/json`);
//! - `have` / `no_have`: re-reads with and without the hashes of blocks already held.
//!
//! It counts UTF-8 bytes and estimates tokens as `ceil(bytes / 4)`; these are not provider
//! token counts and must never be reported as such (section 9.2). Every id is derived from a
//! counter, so a rerun gives the same bytes. Set `DYNODOC_BENCH_OUT=<file>` to write the report
//! (with the transcripts, synthetic text only) for `scripts/agent-bench-count-tokens.mjs`, the
//! optional, off-by-default provider token count.

use std::fmt::Write as _;

use axum::http::StatusCode;
use engine_mcp::{
    backend::{parse_base, BackendConfig, HttpBackend},
    request::{plan, Method},
    Profile, Server, Session, SessionError, Token, Tool,
};
use serde_json::{json, Map, Value};
use sqlx::PgPool;
use uuid::Uuid;

mod agent_world;
mod common;
use agent_world::*;

#[derive(Clone)]
struct Fixed(String);
impl Session for Fixed {
    async fn token(&self) -> Result<Token, SessionError> {
        Ok(Token::new(self.0.clone(), 0).without_writes())
    }
    async fn rejected(&self, _: &Token) -> Result<(), SessionError> {
        Err(SessionError::Refused)
    }
}

/// Deterministic ULIDs (Crockford base32, 26 characters).
fn id(n: usize) -> String {
    format!("01J9Z0000000000000000{n:05}")
}

/// A deterministic 200-block report: 12 sections, each a heading and 16 paragraphs of
/// 30 to 60 words from a fixed vocabulary (a linear congruential generator, seed 42).
fn synthetic() -> (Ops, Vec<String>) {
    const WORDS: [&str; 24] = [
        "policy", "budget", "regional", "office", "review", "staff", "target", "report", "annual",
        "service", "quality", "measure", "funding", "partner", "outcome", "risk", "training",
        "delivery", "audit", "schedule", "council", "district", "survey", "plan",
    ];
    let mut seed: u64 = 42;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let mut ops = Ops::default();
    let mut blocks = Vec::new();
    let root = ops.node("form", None, 0, json!({"label":"Synthetic annual report"}));
    let mut pos = 0;
    for (section, word) in WORDS.iter().enumerate().take(12) {
        pos += 10;
        blocks.push(ops.block(
            &root,
            pos,
            heading(2, &format!("Section {} {}", section + 1, word)),
        ));
        for _ in 0..16 {
            pos += 10;
            let n = 30 + next() % 31;
            let mut text: Vec<&str> = (0..n).map(|_| WORDS[next() % WORDS.len()]).collect();
            text[0] = "The";
            let mut sentence = text.join(" ");
            sentence.push('.');
            blocks.push(ops.block(&root, pos, para(&sentence)));
        }
    }
    // Replace the random ids by counter ids, so refs (shortest unique prefixes) are stable.
    let mut text = serde_json::to_string(&ops.0).unwrap();
    let mut ids = vec![root.clone()];
    ids.extend(blocks.iter().cloned());
    for (n, old) in ids.iter().enumerate() {
        text = text.replace(old.as_str(), &id(n));
    }
    let blocks = (1..ids.len()).map(id).collect();
    (Ops(serde_json::from_str(&text).unwrap()), blocks)
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~,:!".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

struct Client {
    server: Server<HttpBackend<Fixed>>,
    project: Uuid,
    token: String,
    next: u64,
    transcript: Vec<Value>,
}

/// One measured call: the bytes of the MCP tool result text (`dct`) and of the JSON mirror.
#[derive(Default, Clone, Copy)]
struct Bytes {
    dct: usize,
    json: usize,
    request: usize,
}
impl std::ops::AddAssign for Bytes {
    fn add_assign(&mut self, o: Self) {
        self.dct += o.dct;
        self.json += o.json;
        self.request += o.request;
    }
}

impl Client {
    async fn rpc(&mut self, method: &str, params: Value) -> (Value, usize) {
        self.next += 1;
        let line =
            json!({"jsonrpc":"2.0","id":self.next,"method":method,"params":params}).to_string();
        let reply = self.server.handle_line(&line).await.expect("a reply");
        let len = reply.len();
        (serde_json::from_str(&reply).unwrap(), len)
    }

    /// Call `tool` through MCP (DCT) and the same planned route as JSON.
    async fn call(
        &mut self,
        app: &axum::Router,
        tool: Tool,
        name: &str,
        args: Value,
    ) -> (String, Value, Bytes) {
        let params = json!({"name":name,"arguments":args});
        let request = params.to_string().len();
        let (reply, _) = self.rpc("tools/call", params).await;
        assert_ne!(reply["result"]["isError"], true, "{reply}");
        let text = reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let planned = plan(tool, args.as_object().unwrap(), self.project).unwrap();
        let mut uri = format!("/{}", planned.path);
        if !planned.query.is_empty() {
            let q: Vec<String> = planned
                .query
                .iter()
                .map(|(k, v)| format!("{k}={}", encode(v)))
                .collect();
            uri = format!("{uri}?{}", q.join("&"));
        }
        let method = if planned.method == Method::Get {
            "GET"
        } else {
            "POST"
        };
        let mirror = raw(
            app,
            method,
            &uri,
            Some(&self.token),
            &[("accept", "application/json")],
            planned.body.clone(),
        )
        .await;
        assert_eq!(mirror.status, StatusCode::OK, "{uri}: {}", mirror.text());
        self.transcript
            .push(json!({"tool":name,"arguments":args,"dct":text,"json":mirror.text()}));
        let bytes = Bytes {
            dct: text.len(),
            json: mirror.bytes.len(),
            request,
        };
        (text, mirror.json(), bytes)
    }
}

fn tok(bytes: usize) -> usize {
    bytes.div_ceil(4)
}

fn row(task: &str, arm: &str, b: Bytes, calls: usize) -> Value {
    json!({"task":task,"arm":arm,"calls":calls,"result_bytes_dct":b.dct,"result_bytes_json":b.json,"request_bytes":b.request,"est_tokens_dct":tok(b.dct),"est_tokens_json":tok(b.json)})
}

/// `have` for blocks of a JSON `read` answer: `{ref: hash}`.
fn held(answer: &Value) -> Map<String, Value> {
    answer["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer}"))
        .iter()
        .map(|b| {
            (
                b["ref"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{b}"))
                    .to_owned(),
                b["h"].clone(),
            )
        })
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn token_efficiency_byte_benchmark_over_the_local_stack(pool: PgPool) {
    let w = World::new(pool, true).await;
    let (ops, blocks) = synthetic();
    let doc = w.file("Synthetic annual report", "document", ops).await;
    let (_, token) = w.owner_reader().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = w.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let base = parse_base(&format!("http://127.0.0.1:{port}/"), true).unwrap();
    let backend =
        HttpBackend::new(BackendConfig::new(base, w.project), Fixed(token.clone())).unwrap();
    let mut c = Client {
        server: Server::new(backend, Profile::read_only()),
        project: w.project,
        token,
        next: 0,
        transcript: Vec::new(),
    };
    let (init, _) = c.rpc("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"dynodoc-bench","version":"1"}})).await;
    assert!(init["result"].is_object(), "{init}");
    let (tools, _) = c.rpc("tools/list", json!({})).await;
    let definitions = tools["result"]["tools"].to_string().len();
    let file = doc.to_string()[..8].to_owned();
    let mut rows = Vec::new();

    // T1 orient: list files, then the outline.
    let mut t1 = Bytes::default();
    t1 += c.call(&w.app, Tool::Files, "files", json!({})).await.2;
    let (_, outline, b) = c
        .call(&w.app, Tool::Outline, "outline", json!({"file":file}))
        .await;
    t1 += b;
    rows.push(row("T1 orient (files, outline)", "dct vs json", t1, 2));

    // T2 locate and read: find a term, then read the first eight hits.
    let mut t2 = Bytes::default();
    let (_, found, b) = c
        .call(
            &w.app,
            Tool::Find,
            "find",
            json!({"file":file,"q":"council"}),
        )
        .await;
    t2 += b;
    let mut refs: Vec<Value> = Vec::new();
    for hit in found["hits"].as_array().unwrap() {
        if refs.len() < 8 && !refs.contains(&hit["at"]) {
            refs.push(hit["at"].clone());
        }
    }
    assert!(!refs.is_empty(), "{found}");
    let (_, first, b) = c
        .call(&w.app, Tool::Read, "read", json!({"file":file,"refs":refs}))
        .await;
    t2 += b;
    rows.push(row(
        "T2 locate and read 8 blocks (find, read)",
        "dct vs json",
        t2,
        2,
    ));

    // T3 re-read the same eight, unchanged: without and with `have`.
    let have = held(&first);
    let (_, _, plain) = c
        .call(&w.app, Tool::Read, "read", json!({"file":file,"refs":refs}))
        .await;
    rows.push(row("T3 re-read 8 unchanged blocks", "no_have", plain, 1));
    let (_, _, cached) = c
        .call(
            &w.app,
            Tool::Read,
            "read",
            json!({"file":file,"refs":refs,"have":have}),
        )
        .await;
    rows.push(row("T3 re-read 8 unchanged blocks", "have", cached, 1));

    // T4 the team changes one of the eight; re-read without and with `have`.
    // Refs here are the counter digits of the ids (their shortest unique suffix).
    let first_ref = first["items"][0]["ref"].as_str().unwrap();
    let target = blocks
        .iter()
        .find(|b| b.ends_with(first_ref))
        .cloned()
        .unwrap_or_else(|| panic!("{first_ref}"));
    let mut edit = Ops::default();
    let text = "The council approved the revised regional budget.";
    edit.edit(&target, "content", para(text));
    edit.edit(&target, "label", json!(text));
    w.edit(doc, edit).await;
    let (_, _, plain) = c
        .call(&w.app, Tool::Read, "read", json!({"file":file,"refs":refs}))
        .await;
    rows.push(row("T4 re-read 8 blocks, 1 changed", "no_have", plain, 1));
    let (_, _, cached) = c
        .call(
            &w.app,
            Tool::Read,
            "read",
            json!({"file":file,"refs":refs,"have":have}),
        )
        .await;
    rows.push(row("T4 re-read 8 blocks, 1 changed", "have", cached, 1));

    // T5 review what changed since the first read.
    let rev = outline["rev"].clone();
    let (_, _, b) = c
        .call(&w.app, Tool::Diff, "diff", json!({"file":file,"from":rev}))
        .await;
    rows.push(row("T5 diff since the first read", "dct vs json", b, 1));

    let report = json!({
        "benchmark": "dynodoc agent byte benchmark v1 (decision 038)",
        "corpus": {"blocks": blocks.len(), "sections": 12, "generator": "LCG seed 42, 24-word vocabulary"},
        "tool_definitions_bytes_read_only": definitions,
        "est_tokens_rule": "ceil(bytes / 4); not provider tokens",
        "rows": rows,
        "transcript": c.transcript,
    });
    let mut summary = report.clone();
    summary.as_object_mut().unwrap().remove("transcript");
    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    if let Ok(out) = std::env::var("DYNODOC_BENCH_OUT") {
        std::fs::write(out, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    }
    // Sanity, not a claim: the cache never costs more than a plain re-read, and an
    // unchanged re-read with it is smaller.
    let by = |task: &str, arm: &str| {
        rows.iter()
            .find(|r| r["task"].as_str().unwrap().starts_with(task) && r["arm"] == arm)
            .unwrap()["result_bytes_dct"]
            .as_u64()
            .unwrap()
    };
    assert!(by("T3", "have") < by("T3", "no_have"));
    assert!(by("T4", "have") <= by("T4", "no_have"));
}
