//! Model-in-the-loop evaluation of the read-only MCP tools (docs/AI-AGENT-TOKEN-EFFICIENCY.md
//! section 5, decision 043). Off by default, twice over: the test is `#[ignore]`d, and it does
//! nothing unless `DYNODOC_EVAL=on`. Only then does it read `ANTHROPIC_API_KEY` and
//! `DYNODOC_EVAL_MODEL` (no default model: the operator names one) from the environment.
//!
//! It serves the real router over the restricted runtime login on a loopback port, drives the real
//! `engine-mcp` server and HTTP backend (what `engine-cli mcp` runs), and lets the model call the
//! tools to answer questions about a synthetic report with planted facts. Per task it records
//! whether the answer holds the planted fact, the turns, the tool calls, the provider's own token
//! counts and the tool-result bytes. The document is synthetic; the key goes only into the request
//! header, never into the transcript (`DYNODOC_EVAL_OUT=<file>` writes it), a log line or an error.
//!
//!   DYNODOC_EVAL=on ANTHROPIC_API_KEY=... DYNODOC_EVAL_MODEL=<model id> \
//!     cargo test -p engine-api --test agent_eval_test -- --ignored --nocapture

use engine_mcp::{
    backend::{parse_base, BackendConfig, HttpBackend},
    Profile, Server, Session, SessionError, Token,
};
use serde_json::{json, Value};
use sqlx::PgPool;

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

/// The questions, and the text a correct answer must contain.
const TASKS: [(&str, &str); 3] = [
    (
        "What is the training budget of the north district? Answer with the figure.",
        "4,200",
    ),
    ("In which month is the external audit scheduled?", "March"),
    (
        "Which partner runs the survey programme? Answer with the name.",
        "Harbour Trust",
    ),
];

/// A synthetic report: four sections of filler with the three planted facts among them.
fn report() -> Ops {
    let filler = "The office reviewed the annual service measures and the regional delivery plan.";
    let facts = [
        "The training budget of the north district is 4,200 units for the year.",
        "The external audit is scheduled for March, after the council review.",
        "The survey programme is run by the partner Harbour Trust.",
    ];
    let mut ops = Ops::default();
    let root = ops.node(
        "form",
        None,
        0,
        json!({"label":"Synthetic district report"}),
    );
    let mut pos = 0;
    for section in 0..4 {
        pos += 10;
        ops.block(&root, pos, heading(2, &format!("Section {}", section + 1)));
        for n in 0..12 {
            pos += 10;
            let text = if n == 7 && section < facts.len() {
                facts[section]
            } else {
                filler
            };
            ops.block(&root, pos, para(text));
        }
    }
    ops
}

/// What a transcript keeps of one provider exchange: never a header, so never the key.
fn record(task: usize, turn: usize, request: &Value, response: &Value) -> Value {
    json!({"task":task,"turn":turn,"request":request,"response":response})
}

#[test]
fn a_transcript_never_holds_the_provider_key() {
    let key = "sk-ant-DYNODOC-CANARY-0123456789";
    let body = json!({"model":"m","messages":[{"role":"user","content":"q"}]});
    let line = record(0, 0, &body, &json!({"content":[]})).to_string();
    assert!(!line.contains(key) && !line.contains("x-api-key"));
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "calls a model provider; DYNODOC_EVAL=on to run"]
async fn mcp_tools_answer_planted_questions_with_a_model(pool: PgPool) {
    if std::env::var("DYNODOC_EVAL").as_deref() != Ok("on") {
        eprintln!("skipped: DYNODOC_EVAL is not on");
        return;
    }
    let (Ok(key), Ok(model)) = (
        std::env::var("ANTHROPIC_API_KEY"),
        std::env::var("DYNODOC_EVAL_MODEL"),
    ) else {
        panic!("DYNODOC_EVAL=on needs ANTHROPIC_API_KEY and DYNODOC_EVAL_MODEL");
    };
    let w = World::new(pool, true).await;
    w.file("Synthetic district report", "document", report())
        .await;
    let (_, token) = w.owner_reader().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = w.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let base = parse_base(&format!("http://127.0.0.1:{port}/"), true).unwrap();
    let backend = HttpBackend::new(BackendConfig::new(base, w.project), Fixed(token)).unwrap();
    let server = Server::new(backend, Profile::read_only());
    let mut next = 0u64;
    let mut rpc = async |method: &str, params: Value| -> Value {
        next += 1;
        let line = json!({"jsonrpc":"2.0","id":next,"method":method,"params":params}).to_string();
        serde_json::from_str(&server.handle_line(&line).await.expect("a reply")).unwrap()
    };
    rpc("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"dynodoc-eval","version":"1"}})).await;
    let listed = rpc("tools/list", json!({})).await;
    let tools: Vec<Value> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| json!({"name":t["name"],"description":t["description"],"input_schema":t["inputSchema"]}))
        .collect();

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .unwrap();
    let system = "You answer questions about the documents of a Dynodoc project using only the tools. Reply with a short answer.";
    let (mut transcript, mut rows) = (Vec::new(), Vec::new());
    for (index, (question, expected)) in TASKS.iter().enumerate() {
        let mut messages = vec![json!({"role":"user","content":question})];
        let (mut calls, mut result_bytes, mut input, mut output) = (0, 0, 0, 0);
        let mut answer = String::new();
        for turn in 0..8 {
            let body = json!({"model":model,"max_tokens":1024,"system":system,"tools":tools,"messages":messages});
            let response: Value = http
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", &key)
                .header("anthropic-version", "2023-06-01")
                .json(&body)
                .send()
                .await
                .unwrap_or_else(|e| panic!("provider unreachable: {}", e.without_url()))
                .json()
                .await
                .expect("a JSON answer");
            transcript.push(record(index, turn, &body, &response));
            assert!(
                response["error"].is_null(),
                "provider error: {}",
                response["error"]
            );
            input += response["usage"]["input_tokens"].as_u64().unwrap_or(0);
            output += response["usage"]["output_tokens"].as_u64().unwrap_or(0);
            let content = response["content"].as_array().cloned().unwrap_or_default();
            messages.push(json!({"role":"assistant","content":content}));
            let mut results = Vec::new();
            for block in &content {
                match block["type"].as_str() {
                    Some("text") => answer.push_str(block["text"].as_str().unwrap_or("")),
                    Some("tool_use") => {
                        calls += 1;
                        let reply = rpc(
                            "tools/call",
                            json!({"name":block["name"],"arguments":block["input"]}),
                        )
                        .await;
                        let text = reply["result"]["content"][0]["text"]
                            .as_str()
                            .unwrap_or("")
                            .to_owned();
                        result_bytes += text.len();
                        results.push(json!({"type":"tool_result","tool_use_id":block["id"],"content":text,"is_error":reply["result"]["isError"] == true}));
                    }
                    _ => {}
                }
            }
            if results.is_empty() {
                break;
            }
            messages.push(json!({"role":"user","content":results}));
        }
        let passed = answer.contains(expected);
        rows.push(json!({"task":question,"passed":passed,"tool_calls":calls,"tool_result_bytes":result_bytes,"input_tokens":input,"output_tokens":output}));
        eprintln!(
            "task {}: {} ({calls} calls, {input} in, {output} out)",
            index + 1,
            if passed { "passed" } else { "failed" }
        );
    }
    let report = json!({"model":model,"tasks":rows,"transcript":transcript});
    let text = serde_json::to_string_pretty(&report).unwrap();
    assert!(
        !text.contains(&key),
        "the transcript holds the provider key"
    );
    if let Ok(path) = std::env::var("DYNODOC_EVAL_OUT") {
        std::fs::write(path, &text).unwrap();
    }
}
