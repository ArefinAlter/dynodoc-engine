//! The real `engine-cli mcp` process and its write switch, against a loopback service that
//! plays the device-session routes and the agent routes: what it asks for, what it lists,
//! what it sends, and that standard output carries protocol messages and nothing else even
//! when a write is refused. The service is a stand-in written for this test; nothing here ran
//! against `engine-api`, a real MCP client or a model.
use axum::{
    body::Body,
    extract::State,
    http::{header, Request},
    response::Response,
    Router,
};
use engine_core::repository::device_session::{SessionChallenge, SessionProof};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const AUTHORITY: &str = "55555555-5555-4555-8555-555555555555";
const PROPOSAL: &str = "4d0e9b1c-5f2a-4b8e-9c31-0a7d6e2f8b14";
/// What the stand-in service issues; it must appear nowhere in the process's output.
const TOKEN: &str = "v4.local.MOCK-TOKEN-SECRET";
const DCT: &str = "text/vnd.dynodoc.dct; v=1; charset=utf-8";

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_engine-cli")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// --- the stand-in service ---------------------------------------------------------------------

#[derive(Default)]
struct Log {
    /// The scopes of each challenge asked for, as sent.
    challenges: Vec<Vec<String>>,
    /// Method, path and whether the bearer was the issued token, per agent request.
    requests: Vec<(String, String, bool)>,
    /// The JSON bodies of the propose and submit requests.
    bodies: Vec<Value>,
}

struct Shared {
    log: Mutex<Log>,
    /// Refuse every challenge that asks for a write scope, as for a key without the grant.
    refuse_writes: bool,
}

struct Service {
    base: String,
    shared: Arc<Shared>,
}

impl Service {
    fn log<T>(&self, read: impl FnOnce(&Log) -> T) -> T {
        read(&self.shared.log.lock().unwrap())
    }
}

fn answer(body: String) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, DCT)
        .body(Body::from(body))
        .unwrap()
}

fn status(code: u16) -> Response {
    Response::builder()
        .status(code)
        .body(Body::empty())
        .unwrap()
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let path = parts.uri.path().to_owned();
    let method = parts.method.to_string();

    if path.ends_with("/device-sessions/challenge") {
        let asked: Vec<String> = serde_json::from_value(body["scopes"].clone()).unwrap();
        let writes = asked
            .iter()
            .any(|s| s == "content:propose" || s == "content:submit");
        shared.log.lock().unwrap().challenges.push(asked.clone());
        if writes && shared.refuse_writes {
            return status(403);
        }
        let mut sorted = asked;
        sorted.sort();
        let challenge = SessionChallenge {
            version: 1,
            id: Uuid::new_v4(),
            authority: Uuid::parse_str(AUTHORITY).unwrap(),
            public_key: body["public_key"].as_str().unwrap().to_owned(),
            project: Uuid::parse_str(PROJECT).unwrap(),
            scopes: sorted,
            nonce: "ab".repeat(32),
            issued_at_ms: 1_000_000,
            expires_at_ms: 1_100_000,
            token_ttl_seconds: 3600,
        };
        let issued = json!({"challenge": challenge, "mac": "cd".repeat(32)});
        return Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(issued.to_string()))
            .unwrap();
    }
    if path.ends_with("/device-sessions") {
        let proof: SessionProof = serde_json::from_value(body).unwrap();
        if proof.verify_signature().is_err() {
            return status(401);
        }
        let granted = json!({"access_token": TOKEN, "expires_in": 3600});
        return Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(granted.to_string()))
            .unwrap();
    }

    let bearer = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"));
    {
        let mut log = shared.log.lock().unwrap();
        log.requests.push((method, path.clone(), bearer));
        if path.ends_with("/propose") || path.ends_with("/submit") || path.ends_with("/withdraw") {
            log.bodies.push(body.clone());
        }
    }
    if !bearer {
        return status(401);
    }
    if path.ends_with("/propose") {
        return answer(if body["dry_run"] == true {
            "dd/1 propose file=7034d450 rev=412 applied=0 would_apply=1 expanded=1 stale=0 trust=data ~tok=30\n~7C02 P #b7a210>a41c07 -6 +9\n".to_owned()
        } else {
            format!("dd/1 propose file=7034d450 proposal={PROPOSAL} rev=412 applied=1 expanded=1 stale=0 state=draft revision=1 trust=data ~tok=40\n~7C02 P #b7a210>a41c07 -6 +9\n")
        });
    }
    if path.ends_with("/submit") {
        return answer(format!("dd/1 submit action=submit proposal={PROPOSAL} file=7034d450 state=awaiting_person changed=0 behind=0 trust=data\n"));
    }
    if path.contains("/proposals/") {
        return answer(format!("dd/1 status what=proposal proposal={PROPOSAL} file=7034d450 state=draft base=412 head=412 behind=0 revision=1 edits=1 approvals=0 required=0 satisfied=1 conflicts=0 trust=data\n"));
    }
    if path.ends_with("/access") {
        return answer("dd/1 status what=access project=33333333 role=editor scopes=content:propose,content:read,content:submit write_mode=draft calc=none\n".to_owned());
    }
    status(404)
}

fn start(refuse_writes: bool) -> Service {
    let shared = Arc::new(Shared {
        log: Mutex::new(Log::default()),
        refuse_writes,
    });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let app = Router::new().fallback(handle).with_state(shared.clone());
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    Service { base, shared }
}

// --- the process --------------------------------------------------------------------------------

fn scratch() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "dynodoc-mcp-write-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

/// A key made by the binary itself and a remote file that points at the stand-in service.
fn setup(service: &Service) -> (PathBuf, PathBuf, PathBuf) {
    let dir = scratch();
    let key = dir.join("agent.der");
    let output = Command::new(exe())
        .args(["device", "keygen", "--out"])
        .arg(&key)
        .stdin(Stdio::null())
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    let public_key = text(&output.stdout)
        .split_whitespace()
        .find(|w| w.len() == 64 && w.bytes().all(|b| b.is_ascii_hexdigit()))
        .expect("keygen prints the public key")
        .to_owned();
    let remote = dir.join("remote.json");
    std::fs::write(
        &remote,
        json!({"version": 1, "url": service.base, "authority": AUTHORITY, "public_key": public_key})
            .to_string(),
    )
    .unwrap();
    (dir, key, remote)
}

/// Run the process with `extra` arguments and environment, send `messages`, close its input.
fn converse(
    service: &Service,
    extra: &[&str],
    environment: &[(&str, &str)],
    messages: &[Value],
) -> (Output, Vec<Value>) {
    let (dir, key, remote) = setup(service);
    let mut command = Command::new(exe());
    command
        .arg("mcp")
        .arg("--remote")
        .arg(&remote)
        .args([
            "--project",
            PROJECT,
            "--allow-loopback-http",
            "--device-key",
        ])
        .arg(&key)
        .args(extra)
        .env_remove("DYNODOC_KEY_PASSPHRASE_FILE")
        .env_remove("DYNODOC_WRITE")
        .env("RUST_LOG", "trace");
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for message in messages {
        stdin.write_all(message.to_string().as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let stdout = text(&output.stdout);
    let replies: Vec<Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON on stdout: {l:?}")))
        .collect();
    for reply in &replies {
        assert_eq!(reply["jsonrpc"], "2.0", "{reply}");
        assert!(
            reply.get("id").is_some()
                && (reply.get("result").is_some() != reply.get("error").is_some()),
            "{reply}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
    (output, replies)
}

fn call(id: u64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
}

fn list(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
}

fn names(reply: &Value) -> Vec<&str> {
    reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect()
}

/// Neither the issued token nor an `Authorization` header appears anywhere in the output.
fn assert_no_secrets(output: &Output) {
    for stream in [text(&output.stdout), text(&output.stderr)] {
        assert!(
            !stream.contains("MOCK-TOKEN"),
            "the token leaked:\n{stream}"
        );
        assert!(!stream.contains("Bearer"));
    }
}

// --- tests -------------------------------------------------------------------------------------

#[test]
fn without_the_flag_nothing_asks_for_a_write_scope_and_the_write_tools_do_not_exist() {
    let service = start(false);
    let (output, replies) = converse(
        &service,
        &[],
        &[],
        &[
            list(1),
            call(2, "status", json!({})),
            call(
                3,
                "propose",
                json!({"file": "7034d450", "rev": 1, "ops": [{"op": "delete", "ref": "A"}]}),
            ),
            call(
                4,
                "submit",
                json!({"proposal": PROPOSAL, "action": "submit"}),
            ),
        ],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(
        names(&replies[0]),
        ["files", "outline", "read", "find", "diff", "status"]
    );
    assert!(replies[1]["result"].get("isError").is_none());
    // A hidden tool is a protocol error and sends nothing anywhere.
    for reply in &replies[2..] {
        assert_eq!(reply["error"]["code"], -32602, "{reply}");
    }
    assert_eq!(service.log(|l| l.challenges.clone()), [["content:read"]]);
    assert_eq!(service.log(|l| l.requests.len()), 1);
    assert_no_secrets(&output);
}

#[test]
fn write_mode_is_refused_before_any_key_or_network_use_and_only_a_clear_yes_asks_for_it() {
    // The stock command has no per-request human confirmation surface, so it refuses write
    // mode outright: from the flag and from DYNODOC_WRITE=on|1, before it reads the key or
    // asks the service for anything. Every other value of the variable leaves a read-only
    // session with the six read tools.
    let service = start(false);
    for (extra, environment) in [
        (&["--write"][..], &[][..]),
        (&[][..], &[("DYNODOC_WRITE", "on")][..]),
        (&[][..], &[("DYNODOC_WRITE", "1")][..]),
        (&["--write"][..], &[("DYNODOC_WRITE", "off")][..]),
    ] {
        let (output, replies) = converse(&service, extra, environment, &[list(1)]);
        assert!(!output.status.success(), "{extra:?} {environment:?}");
        assert!(replies.is_empty(), "nothing on stdout: {replies:?}");
        assert!(
            text(&output.stderr).contains("human confirmation"),
            "{}",
            text(&output.stderr)
        );
        assert_no_secrets(&output);
    }
    assert!(
        service.log(|l| l.requests.is_empty() && l.challenges.is_empty()),
        "a refused write mode reaches nothing"
    );
    for value in ["off", "0", "", "maybe"] {
        let (output, replies) = converse(&service, &[], &[("DYNODOC_WRITE", value)], &[list(1)]);
        assert!(output.status.success(), "{}", text(&output.stderr));
        assert_eq!(
            names(&replies[0]),
            ["files", "outline", "read", "find", "diff", "status"],
            "DYNODOC_WRITE={value:?}"
        );
    }
}

#[test]
fn help_names_the_write_switch() {
    let help = Command::new(exe())
        .args(["mcp", "--help"])
        .output()
        .unwrap();
    let help = text(&help.stdout);
    assert!(help.contains("--write"), "{help}");
    assert!(help.contains("DYNODOC_WRITE"), "{help}");
}
