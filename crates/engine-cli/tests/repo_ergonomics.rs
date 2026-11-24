//! End-to-end tests for Git-style `engine-cli repo` discovery, safety checks,
//! branch ref resolution, `DYNODOC_KEY`, default `--authored-at-ms`, and clean stdout.
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

const DOCUMENT: &str = "22222222-2222-4222-8222-222222222222";

fn scratch(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "dynodoc-repo-ux-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cli(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_engine-cli"));
    cmd.current_dir(cwd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .env_remove("DYNODOC_REPO")
        .env_remove("DYNODOC_PROJECT")
        .env_remove("DYNODOC_BRANCH")
        .env_remove("DYNODOC_KEY")
        .env("RUST_LOG", "info");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn json_stdout(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "command failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not clean JSON ({e}):\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn repo_init_and_subdirectory_discovery_without_flags() {
    let root = scratch("discover");
    let nested = root.join("nested").join("deep");
    std::fs::create_dir_all(&nested).unwrap();

    // Bare `repo init` creates .dynodoc/repo.sqlite and generates a valid non-nil project UUID.
    let init1 = json_stdout(&cli(&root, &["repo", "init"], &[]));
    let project_id = init1["project"].as_str().unwrap().to_string();
    let parsed = uuid::Uuid::parse_str(&project_id).unwrap();
    assert!(!parsed.is_nil());
    assert!(root.join(".dynodoc/repo.sqlite").is_file());

    // Re-running `repo init` is idempotent and returns the same project UUID.
    let init2 = json_stdout(&cli(&root, &["repo", "init"], &[]));
    assert_eq!(init2["project"].as_str(), Some(project_id.as_str()));

    // Subcommands auto-discover .dynodoc/repo.sqlite and auto-read project from a nested dir.
    let storage = json_stdout(&cli(&nested, &["repo", "storage"], &[]));
    assert_eq!(storage["commits_used"], 0);

    let branches = json_stdout(&cli(&nested, &["repo", "branches"], &[]));
    assert_eq!(branches["branches"].as_array().unwrap().len(), 0);

    let head = json_stdout(&cli(&nested, &["repo", "head"], &[]));
    assert_eq!(head, serde_json::Value::Null);

    // Explicit wrong --project still fails with a mismatch error.
    let wrong = uuid::Uuid::new_v4().to_string();
    let refused = cli(&nested, &["repo", "--project", &wrong, "storage"], &[]);
    assert!(!refused.status.success());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn read_only_commands_never_create_missing_database() {
    let root = scratch("readonly-missing");
    let missing = root.join("does-not-exist.sqlite");
    let missing_str = missing.to_str().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let fake_commit = "a".repeat(64);

    for args in [
        vec![
            "repo",
            "--repo",
            missing_str,
            "--project",
            &project,
            "storage",
        ],
        vec![
            "repo",
            "--repo",
            missing_str,
            "--project",
            &project,
            "branches",
        ],
        vec![
            "repo",
            "--repo",
            missing_str,
            "--project",
            &project,
            "head",
            "main",
        ],
        vec![
            "repo",
            "--repo",
            missing_str,
            "--project",
            &project,
            "show",
            &fake_commit,
        ],
        vec![
            "repo",
            "--repo",
            missing_str,
            "--project",
            &project,
            "log",
            &fake_commit,
        ],
    ] {
        let out = cli(&root, &args, &[]);
        assert!(!out.status.success(), "missing DB should fail for {args:?}");
        assert!(
            !missing.exists(),
            "read-only command {args:?} must never create missing DB"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn branch_ref_resolution_dynodoc_key_and_default_timestamp() {
    let root = scratch("workflow");
    let nested = root.join("sub");
    std::fs::create_dir_all(&nested).unwrap();

    let init = json_stdout(&cli(&root, &["repo", "init"], &[]));
    let project = init["project"].as_str().unwrap().to_string();

    let key = root.join("author.der");
    let key_str = key.to_str().unwrap();
    let keygen = cli(&root, &["device", "keygen", "--out", key_str], &[]);
    assert!(keygen.status.success());

    let state_file = root.join("state.json");
    std::fs::write(
        &state_file,
        r#"{"nodes":{"00000000000000000000000001":{"id":"00000000000000000000000001","parent_id":null,"type":"paragraph","pos":"p000000","var_name":null,"deleted":false,"current_fields":{"label":"Initial"}}},"comments":[],"suggestions":{},"removed_choices":[]}"#,
    )
    .unwrap();
    let stored = json_stdout(&cli(
        &nested,
        &[
            "repo",
            "store-state",
            DOCUMENT,
            state_file.to_str().unwrap(),
        ],
        &[],
    ));

    let m0 = root.join("c0.json");
    std::fs::write(
        &m0,
        serde_json::json!({
            "version": 1,
            "project": project,
            "parents": [],
            "files": {"Notes.docx": {"document": DOCUMENT, "state": stored["state"]}},
            "author_key": "",
            "authored_at_ms": 1_700_000_000_000i64,
            "message": "Initial commit"
        })
        .to_string(),
    )
    .unwrap();

    // Commit using DYNODOC_KEY without passing a positional key argument.
    let c0 = json_stdout(&cli(
        &nested,
        &["repo", "commit", m0.to_str().unwrap()],
        &[("DYNODOC_KEY", key_str)],
    ));
    let c0_addr = c0["commit"].as_str().unwrap().to_string();

    // Advance two branches (main and feature).
    let state2_file = root.join("state2.json");
    std::fs::write(
        &state2_file,
        r#"{"nodes":{"00000000000000000000000001":{"id":"00000000000000000000000001","parent_id":null,"type":"paragraph","pos":"p000000","var_name":null,"deleted":false,"current_fields":{"label":"Updated on feature"}}},"comments":[],"suggestions":{},"removed_choices":[]}"#,
    )
    .unwrap();
    let stored2 = json_stdout(&cli(
        &nested,
        &[
            "repo",
            "store-state",
            DOCUMENT,
            state2_file.to_str().unwrap(),
        ],
        &[],
    ));
    let m1 = root.join("c1.json");
    std::fs::write(
        &m1,
        serde_json::json!({
            "version": 1,
            "project": project,
            "parents": [c0_addr],
            "files": {"Notes.docx": {"document": DOCUMENT, "state": stored2["state"]}},
            "author_key": "",
            "authored_at_ms": 1_700_000_001_000i64,
            "message": "Feature edit"
        })
        .to_string(),
    )
    .unwrap();
    let c1 = json_stdout(&cli(
        &nested,
        &["repo", "commit", m1.to_str().unwrap()],
        &[("DYNODOC_KEY", key_str)],
    ));
    let c1_addr = c1["commit"].as_str().unwrap().to_string();

    json_stdout(&cli(&nested, &["repo", "set-head", "main", &c0_addr], &[]));
    json_stdout(&cli(
        &nested,
        &["repo", "set-head", "feature", &c1_addr],
        &[],
    ));

    // `repo branches` lists both branches in deterministic order.
    let branches = json_stdout(&cli(&nested, &["repo", "branches"], &[]));
    let list = branches["branches"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["branch"], "feature");
    assert_eq!(list[0]["commit"], c1_addr);
    assert_eq!(list[1]["branch"], "main");
    assert_eq!(list[1]["commit"], c0_addr);

    // `repo head` (no arg) defaults to `main`, and `repo show main` / `repo log` accept branch refs.
    let main_head = json_stdout(&cli(&nested, &["repo", "head"], &[]));
    assert_eq!(main_head["commit"], c0_addr);

    let shown = json_stdout(&cli(&nested, &["repo", "show", "main"], &[]));
    assert_eq!(shown["commit"]["message"], "Initial commit");

    let default_log = json_stdout(&cli(&nested, &["repo", "log", "--json"], &[]));
    assert_eq!(default_log["head"], c0_addr);

    let feature_log = json_stdout(&cli(&nested, &["repo", "log", "feature", "--json"], &[]));
    assert_eq!(feature_log["head"], c1_addr);
    assert_eq!(feature_log["entries"].as_array().unwrap().len(), 2);

    // `repo merge` accepts branch names, DYNODOC_KEY, and omitted `--authored-at-ms`.
    let merged = json_stdout(&cli(
        &nested,
        &[
            "repo",
            "merge",
            "main",
            "feature",
            "--same-file-merge",
            "clean",
            "--message",
            "Merge feature into main",
        ],
        &[("DYNODOC_KEY", key_str)],
    ));
    assert!(merged["commit"].as_str().unwrap().len() == 64);

    let _ = std::fs::remove_dir_all(&root);
}
