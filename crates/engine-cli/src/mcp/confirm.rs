//! The person's confirmation of each MCP write (decision 029): the Dynodoc desktop app when it
//! runs, else a native dialog of the operating system. Nothing that arrives on the MCP stream
//! can answer: the server reads no further input while a write waits, and the answer comes
//! from one of these two surfaces only.
//!
//! **The desktop channel.** The desktop app, at each launch, listens on a loopback port and
//! writes `mcp-confirm.json` (`{"v":1,"port":..,"secret":"<64 hex>"}`, owner-only) into its
//! local data folder. One write is one connection carrying one line each way:
//!
//! * ask: `{"v":1,"nonce":"<32 hex>","request":"<JSON text>","mac":"<hex>"}`, where `mac` is
//!   HMAC-SHA256 under the secret of [`ASK`], the nonce, a line feed and the request text;
//! * answer: `{"approved":true|false,"mac":"<hex>"}`, where `mac` covers [`ANSWER`], the
//!   nonce, the ask's `mac` and `approve` or `decline`.
//!
//! The app refuses an ask without a valid `mac` before showing anything, so a web page or
//! another account's process cannot put a prompt in front of the person, and this process
//! accepts only an answer bound to its own fresh nonce and request, so a listener without the
//! secret (another account squatting the port of a closed app) or a replayed answer cannot
//! approve. Anything else after the connection is made is a decline, never a fallback.
//!
//! **The fallback.** When no app answers on the port, the person is asked in a native dialog
//! (Windows `MessageBoxW`, macOS `osascript`, elsewhere `zenity`) whose default is Decline.
//! With none of them, the write is declined.
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

use std::{
    future::Future,
    io::Read,
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};

use engine_mcp::server::{HumanConfirmation, WriteRequest, CONFIRM_TIMEOUT};
use ring::{hmac, rand::SecureRandom};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use uuid::Uuid;

/// Domain of the ask's MAC.
pub const ASK: &[u8] = b"dynodoc.mcp-confirm.v1 ask\n";
/// Domain of the answer's MAC.
pub const ANSWER: &[u8] = b"dynodoc.mcp-confirm.v1 answer\n";
/// The desktop app's identifier (tauri.conf.json): the folder of its local data.
const APP_ID: &str = "online.dynodoc.client";
const FILE_NAME: &str = "mcp-confirm.json";
/// Longest answer line accepted.
const MAX_ANSWER: u64 = 4096;
/// Longest preview and summary shown; the rest is cut with a note.
const MAX_SHOWN: usize = 6000;

/// Where the running desktop app announces its channel: its local data folder, as Tauri's
/// `app_local_data_dir` resolves it. A portable or test copy is named with `--confirm-file`.
pub fn default_file() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    }?;
    Some(base.join(APP_ID).join(FILE_NAME))
}

/// The confirmation sink of `engine-cli mcp --write`.
pub struct Confirmer {
    pub project: Uuid,
    /// The desktop app's announcement; `None` asks in a native dialog only.
    pub file: Option<PathBuf>,
}

impl HumanConfirmation for Confirmer {
    fn confirm<'a>(
        &'a self,
        request: WriteRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let shown = shown(self.project, &request);
        Box::pin(async move {
            if let Some(file) = &self.file {
                match ask_desktop(file, &shown, CONFIRM_TIMEOUT).await {
                    Reached::Answer(approved) => {
                        tracing::info!(
                            tool = request.tool.name(),
                            approved,
                            "desktop app answered"
                        );
                        return approved;
                    }
                    Reached::Not => {}
                }
            }
            let approved = native::ask(&dialog_text(&shown)).await;
            tracing::info!(
                tool = request.tool.name(),
                approved,
                "native dialog answered"
            );
            approved
        })
    }
}

/// What the person is shown: the tool, project, client claim, a summary built from the
/// validated arguments and the service's dry-run preview. All of it is untrusted text for
/// display only.
pub fn shown(project: Uuid, request: &WriteRequest<'_>) -> Value {
    let args = request.arguments;
    let text = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or("");
    let mut summary = Vec::new();
    let mut file = Value::Null;
    match request.tool.name() {
        "propose" => {
            file = json!(text("file"));
            summary.push(format!(
                "Proposal \"{}\" to file {} at revision {}",
                cut(text("name"), 200),
                text("file"),
                args.get("rev").and_then(Value::as_u64).unwrap_or(0)
            ));
            if let Some(proposal) = args.get("proposal").and_then(Value::as_str) {
                summary.push(format!("Adds to proposal {proposal}"));
            }
            let ops = args
                .get("ops")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            summary.push(format!("{} operation(s):", ops.len()));
            for op in ops.iter().take(20) {
                summary.push(op_line(op.as_object().unwrap_or(&Map::new())));
            }
            if ops.len() > 20 {
                summary.push(format!("... and {} more", ops.len() - 20));
            }
        }
        "submit" => summary.push(format!(
            "{} proposal {}{}",
            if text("action") == "withdraw" {
                "Withdraw"
            } else {
                "Send to reviewers"
            },
            text("proposal"),
            Some(text("note"))
                .filter(|n| !n.is_empty())
                .map(|n| format!(" with the note \"{}\"", cut(n, 300)))
                .unwrap_or_default()
        )),
        _ => summary.push(format!(
            "Propose a project memory ({}): \"{}\" citing {} block(s)",
            text("kind"),
            cut(text("body"), 2000),
            args.get("citations")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        )),
    }
    json!({
        "tool": request.tool.name(),
        "project": project,
        "client": cut(request.client, 120),
        "file": file,
        "summary": cut(&summary.join("\n"), MAX_SHOWN),
        "preview": request.preview.map(|p| cut(p, MAX_SHOWN)),
    })
}

fn op_line(op: &Map<String, Value>) -> String {
    let get = |key: &str| op.get(key).and_then(Value::as_str);
    let mut line = format!("- {}", get("op").unwrap_or("?"));
    for key in [
        "ref", "after", "before", "sheet", "range", "at", "slide", "shape",
    ] {
        if let Some(value) = get(key) {
            line.push_str(&format!(" {key}={}", cut(value, 40)));
        }
    }
    if let Some(find) = get("find") {
        line.push_str(&format!(" \"{}\" ->", cut(find, 60)));
    }
    if let Some(new) = get("text").or_else(|| get("with")) {
        line.push_str(&format!(" \"{}\"", cut(new, 120)));
    }
    if let Some(blocks) = op.get("blocks").and_then(Value::as_array) {
        line.push_str(&format!(" ({} block(s))", blocks.len()));
    }
    line
}

/// At most `max` characters, control characters but line feeds removed.
fn cut(text: &str, max: usize) -> String {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    if clean.chars().count() <= max {
        return clean;
    }
    let mut kept: String = clean.chars().take(max).collect();
    kept.push_str(" [cut]");
    kept
}

fn dialog_text(shown: &Value) -> String {
    let s = |key: &str| shown[key].as_str().unwrap_or("");
    let mut text = format!(
        "An AI agent ({}) asks to {} in Dynodoc project {}.\n\n{}",
        Some(s("client"))
            .filter(|c| !c.is_empty())
            .unwrap_or("unnamed MCP client"),
        s("tool"),
        s("project"),
        s("summary"),
    );
    if let Some(preview) = shown["preview"].as_str() {
        text.push_str("\n\nPreview from the server:\n");
        text.push_str(&cut(preview, 2500));
    }
    text.push_str(
        "\n\nApprove only if you asked for this. A proposal is not live: a person still reviews and merges it.",
    );
    text
}

// --- the desktop channel ---------------------------------------------------------------------

/// The outcome of asking the desktop app.
#[derive(Debug, PartialEq, Eq)]
pub enum Reached {
    /// No app announced a channel, or nothing listens on it: ask elsewhere.
    Not,
    /// The app (or something on its port) was reached: its verified answer, else `false`.
    Answer(bool),
}

#[derive(Deserialize)]
struct Announce {
    v: u32,
    port: u16,
    secret: String,
}

fn read_announce(path: &Path) -> Option<(u16, Vec<u8>)> {
    let file = std::fs::File::open(path).ok()?;
    if let Err(error) = crate::private_file::check_key_file(&file, path) {
        tracing::warn!(%error, "the desktop app's confirmation file is not private; not used");
        return None;
    }
    let mut bytes = Vec::new();
    file.take(4096).read_to_end(&mut bytes).ok()?;
    let a: Announce = serde_json::from_slice(&bytes).ok()?;
    let secret = hex::decode(&a.secret).ok().filter(|s| s.len() == 32)?;
    (a.v == 1 && a.port != 0).then_some((a.port, secret))
}

/// HMAC-SHA256 under `secret` of the parts, in order.
pub fn mac(secret: &[u8], parts: &[&[u8]]) -> hmac::Tag {
    let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, secret));
    for part in parts {
        ctx.update(part);
    }
    ctx.sign()
}

/// Ask the desktop app announced in `file`; see the module notes for the exchange.
pub async fn ask_desktop(file: &Path, shown: &Value, wait: Duration) -> Reached {
    let Some((port, secret)) = read_announce(file) else {
        return Reached::Not;
    };
    let connect = TcpStream::connect(("127.0.0.1", port));
    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(2), connect).await else {
        return Reached::Not;
    };
    let approved = tokio::time::timeout(wait, exchange(stream, &secret, shown))
        .await
        .unwrap_or_else(|_| {
            tracing::warn!("the desktop app did not answer in time; declined");
            false
        });
    Reached::Answer(approved)
}

async fn exchange(stream: TcpStream, secret: &[u8], shown: &Value) -> bool {
    let mut nonce = [0u8; 16];
    if ring::rand::SystemRandom::new().fill(&mut nonce).is_err() {
        return false;
    }
    let nonce = hex::encode(nonce);
    let request = shown.to_string();
    let ask_mac = hex::encode(mac(
        secret,
        &[ASK, nonce.as_bytes(), b"\n", request.as_bytes()],
    ));
    let line = json!({"v": 1, "nonce": nonce, "request": request, "mac": ask_mac}).to_string();
    let (read, mut write) = stream.into_split();
    if write
        .write_all(format!("{line}\n").as_bytes())
        .await
        .is_err()
    {
        return false;
    }
    let mut answer = String::new();
    let mut reader = BufReader::new(read.take(MAX_ANSWER));
    if reader.read_line(&mut answer).await.is_err() {
        return false;
    }
    verify_answer(secret, &nonce, &ask_mac, &answer)
}

/// The decision of an answer line, if its MAC binds it to this ask; else `false`.
pub fn verify_answer(secret: &[u8], nonce: &str, ask_mac: &str, line: &str) -> bool {
    let Ok(answer) = serde_json::from_str::<Value>(line.trim()) else {
        return false;
    };
    let (Some(approved), Some(tag)) = (
        answer["approved"].as_bool(),
        answer["mac"].as_str().and_then(|m| hex::decode(m).ok()),
    ) else {
        tracing::warn!("the desktop app refused or sent no decision; declined");
        return false;
    };
    let word: &[u8] = if approved { b"approve" } else { b"decline" };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let message = [
        ANSWER,
        nonce.as_bytes(),
        b"\n",
        ask_mac.as_bytes(),
        b"\n",
        word,
    ]
    .concat();
    if hmac::verify(&key, &message, &tag).is_err() {
        tracing::warn!("an answer on the confirmation port is not the desktop app's; declined");
        return false;
    }
    approved
}

// --- native dialogs --------------------------------------------------------------------------

mod native {
    /// Ask in a native dialog; `false` unless the person chose Approve.
    #[cfg(windows)]
    pub async fn ask(text: &str) -> bool {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST,
            MB_YESNO,
        };
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let body = wide(&format!(
            "{text}\n\nYes approves this write. No declines it."
        ));
        let title = wide("Dynodoc: approve an AI agent's write?");
        // shortcut: a box still open when the wait ends stays on screen and its answer is
        // ignored (the write was already declined); close it from here if people find that
        // confusing.
        tokio::task::spawn_blocking(move || {
            // SAFETY: both buffers are NUL-terminated UTF-16 that outlive the call; no owner window.
            let answer = unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    body.as_ptr(),
                    title.as_ptr(),
                    MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND,
                )
            };
            answer == IDYES
        })
        .await
        .unwrap_or(false)
    }

    #[cfg(target_os = "macos")]
    pub async fn ask(text: &str) -> bool {
        let script = [
            "on run argv",
            "display dialog (item 1 of argv) with title \"Dynodoc\" buttons {\"Decline\", \"Approve\"} default button \"Decline\" cancel button \"Decline\" with icon caution giving up after 115",
            "end run",
        ];
        let mut command = tokio::process::Command::new("osascript");
        for line in script {
            command.arg("-e").arg(line);
        }
        let output = command.arg(text).kill_on_drop(true).output().await;
        output.is_ok_and(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            o.status.success()
                && out.contains("button returned:Approve")
                && !out.contains("gave up:true")
        })
    }

    #[cfg(all(not(windows), not(target_os = "macos")))]
    pub async fn ask(text: &str) -> bool {
        // shortcut: zenity only (GNOME and most desktops ship it); add kdialog if KDE-only
        // users ask.
        let status = tokio::process::Command::new("zenity")
            .args([
                "--question",
                "--no-markup",
                "--default-cancel",
                "--title=Dynodoc",
                "--ok-label=Approve",
                "--cancel-label=Decline",
                "--width=640",
                "--timeout=115",
            ])
            .arg(format!("--text={text}"))
            .kill_on_drop(true)
            .status()
            .await;
        match status {
            Ok(status) => status.success(),
            Err(_) => {
                tracing::warn!("no desktop app and no zenity: the write is declined");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_mcp::Tool;
    use tokio::net::TcpListener;

    const SECRET: [u8; 32] = [0x11; 32];

    #[test]
    fn the_mac_matches_an_independent_vector() {
        // Computed with Python's hmac module; the desktop app's test pins the same values.
        let ask = mac(
            &SECRET,
            &[
                ASK,
                b"00112233445566778899aabbccddeeff",
                b"\n",
                b"{\"tool\":\"propose\"}",
            ],
        );
        assert_eq!(hex::encode(ask), ASK_VECTOR);
        let answer = mac(
            &SECRET,
            &[
                ANSWER,
                b"00112233445566778899aabbccddeeff",
                b"\n",
                ASK_VECTOR.as_bytes(),
                b"\n",
                b"approve",
            ],
        );
        assert_eq!(hex::encode(answer), ANSWER_VECTOR);
    }

    const ASK_VECTOR: &str = "a9a5c17c2d3fcf49a570df302dbff700e217b9bc9a1a9775352d74dc668d8bd4";
    const ANSWER_VECTOR: &str = "821506467d463baa58e109e02ff52701c4f651e086fdf166aba8e1471d1b21b3";

    fn announce(port: u16, secret: &[u8]) -> (tempdir::Dir, PathBuf) {
        let dir = tempdir::Dir::new();
        let path = dir.0.join(FILE_NAME);
        crate::private_file::write_new(
            &path,
            json!({"v":1,"port":port,"secret":hex::encode(secret)})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        (dir, path)
    }

    mod tempdir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let path =
                    std::env::temp_dir().join(format!("dd-confirm-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    /// A fake desktop app: checks the ask with `known` and answers `approve` signed with
    /// `signing`, or never answers.
    async fn fake_app(known: [u8; 32], signing: [u8; 32], approve: bool, silent: bool) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            let ask: Value = serde_json::from_str(&line).unwrap();
            let (nonce, request, ask_mac) = (
                ask["nonce"].as_str().unwrap(),
                ask["request"].as_str().unwrap(),
                ask["mac"].as_str().unwrap(),
            );
            let key = hmac::Key::new(hmac::HMAC_SHA256, &known);
            let message = [ASK, nonce.as_bytes(), b"\n", request.as_bytes()].concat();
            if hmac::verify(&key, &message, &hex::decode(ask_mac).unwrap()).is_err() {
                write
                    .write_all(b"{\"error\":\"unauthorized\"}\n")
                    .await
                    .unwrap();
                return;
            }
            if silent {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }
            let word: &[u8] = if approve { b"approve" } else { b"decline" };
            let tag = mac(
                &signing,
                &[
                    ANSWER,
                    nonce.as_bytes(),
                    b"\n",
                    ask_mac.as_bytes(),
                    b"\n",
                    word,
                ],
            );
            let answer = json!({"approved": approve, "mac": hex::encode(tag)});
            write
                .write_all(format!("{answer}\n").as_bytes())
                .await
                .unwrap();
        });
        port
    }

    fn sample() -> Value {
        let args = json!({"file":"7034d450","rev":3,"name":"Clearer","ops":[{"op":"set_text","ref":"7C02","text":"New text"}]});
        let request = WriteRequest {
            tool: Tool::Propose,
            arguments: args.as_object().unwrap(),
            client: "claude-code/2.1",
            preview: Some("dd/1 propose dry_run=1\n~ 7C02 \"Old\" -> \"New text\"\n"),
        };
        shown(Uuid::nil(), &request)
    }

    #[tokio::test]
    async fn only_an_answer_signed_with_the_secret_for_this_ask_approves() {
        let wait = Duration::from_secs(5);
        // The app, with the secret: its approval and its decline are taken as given.
        let (_d, file) = announce(fake_app(SECRET, SECRET, true, false).await, &SECRET);
        assert_eq!(
            ask_desktop(&file, &sample(), wait).await,
            Reached::Answer(true)
        );
        let (_d, file) = announce(fake_app(SECRET, SECRET, false, false).await, &SECRET);
        assert_eq!(
            ask_desktop(&file, &sample(), wait).await,
            Reached::Answer(false)
        );
        // A listener that signs with another secret cannot approve.
        let (_d, file) = announce(fake_app(SECRET, [0x22; 32], true, false).await, &SECRET);
        assert_eq!(
            ask_desktop(&file, &sample(), wait).await,
            Reached::Answer(false)
        );
        // An ask with a wrong secret is refused by the app: declined, no fallback.
        let (_d, file) = announce(fake_app([0x22; 32], [0x22; 32], true, false).await, &SECRET);
        assert_eq!(
            ask_desktop(&file, &sample(), wait).await,
            Reached::Answer(false)
        );
        // No answer in time is a decline.
        let (_d, file) = announce(fake_app(SECRET, SECRET, true, true).await, &SECRET);
        let quick = Duration::from_millis(300);
        assert_eq!(
            ask_desktop(&file, &sample(), quick).await,
            Reached::Answer(false)
        );
        // No announcement, or nothing listening: ask elsewhere.
        let dir = tempdir::Dir::new();
        assert_eq!(
            ask_desktop(&dir.0.join(FILE_NAME), &sample(), wait).await,
            Reached::Not
        );
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let (_d, file) = announce(port, &SECRET);
        assert_eq!(ask_desktop(&file, &sample(), wait).await, Reached::Not);
    }

    #[test]
    fn a_replayed_or_altered_answer_is_a_decline() {
        let nonce = "00112233445566778899aabbccddeeff";
        let ask_mac = "aa";
        let sign = |nonce: &str, word: &[u8]| {
            hex::encode(mac(
                &SECRET,
                &[
                    ANSWER,
                    nonce.as_bytes(),
                    b"\n",
                    ask_mac.as_bytes(),
                    b"\n",
                    word,
                ],
            ))
        };
        let good = json!({"approved":true,"mac":sign(nonce, b"approve")}).to_string();
        assert!(verify_answer(&SECRET, nonce, ask_mac, &good));
        // The same answer for another ask (another nonce) does not approve this one.
        assert!(!verify_answer(
            &SECRET,
            "ffeeddccbbaa99887766554433221100",
            ask_mac,
            &good
        ));
        // A decline's MAC does not make an approval.
        let flipped = json!({"approved":true,"mac":sign(nonce, b"decline")}).to_string();
        assert!(!verify_answer(&SECRET, nonce, ask_mac, &flipped));
        assert!(!verify_answer(
            &SECRET,
            nonce,
            ask_mac,
            "{\"approved\":true}"
        ));
        assert!(!verify_answer(&SECRET, nonce, ask_mac, "yes"));
    }

    #[test]
    fn the_person_sees_the_tool_the_ops_and_the_preview() {
        let shown = sample();
        assert_eq!(shown["tool"], "propose");
        let summary = shown["summary"].as_str().unwrap();
        assert!(
            summary.contains("set_text ref=7C02 \"New text\""),
            "{summary}"
        );
        assert!(shown["preview"]
            .as_str()
            .unwrap()
            .contains("-> \"New text\""));
        let text = dialog_text(&shown);
        assert!(
            text.contains("claude-code/2.1") && text.contains("not live"),
            "{text}"
        );
        assert_eq!(cut("a\u{7}b\u{1b}[2Jc", 10), "ab[2Jc");
    }
}
