//! Selected commit transfer. The separate receipt journal is remote tracking;
//! fetch/push never move local working branches or write a native document.
use anyhow::{anyhow, ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Subcommand};
use engine_core::{
    repository::{
        attestation::{Scope, SignedReceipt},
        authority_epoch::{Kind, Refusal, SignedTransition},
        compare::{
            BoundedValue, DiffKind, DiffTotals, FileCompareReport, NodeDiffKind, ProjectDiffReport,
        },
        local::{LocalRepository, ObjectKey, ObjectPacket},
        receipt_journal::ReceiptJournal,
        Head, SignedCommit, MAX_COMMIT_BYTES,
    },
    shared_checkpoint::{self, typed, Address, Limits, ObjectStore},
};
use engine_shared::DocumentId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;
pub(crate) mod http;
use http::{Client, Credential, Remote};
#[cfg(test)]
mod tests;
mod transfer;
const MAX_COMMITS: usize = 4096;
const MAX_PLAN_BYTES: usize = 64 * 1024 * 1024;
const GRAPH_OBJECTS: usize = 65536;
const GRAPH_BYTES: usize = 64 * 1024 * 1024;

#[derive(Args)]
pub struct Options {
    /// Local SQLite repository; fetch adds verified history but never changes its branches.
    repository: PathBuf,
    project: Uuid,
    /// Independently prepared JSON with version, url, authority and public_key.
    #[arg(long)]
    remote: PathBuf,
    /// Account access token in a private file; never pass the token as an argument.
    #[arg(long, conflicts_with = "device_key")]
    token_file: Option<PathBuf>,
    /// Private file with the account refresh token. On a 401 the command calls
    /// /auth/refresh and atomically replaces this file (and --token-file).
    #[arg(long, conflicts_with = "device_key")]
    refresh_token_file: Option<PathBuf>,
    /// Enrolled Ed25519 key file: unencrypted DER PKCS#8 or an encrypted
    /// dynodoc-key-v1 file (passphrase from --passphrase-file, the
    /// DYNODOC_KEY_PASSPHRASE_FILE variable, a prompt, or an OS keystore binding).
    /// Obtains and renews short-lived tokens for this project in memory; no token or
    /// refresh secret is stored. The key must be granted this project in your
    /// profile (signing keys), unless it is an older all-projects key. On Unix a key
    /// readable by group or others is refused.
    #[arg(long)]
    device_key: Option<PathBuf>,
    /// Separate durable client receipt journal (must not be the repository database).
    #[arg(long)]
    journal: PathBuf,
    #[arg(long)]
    branch: String,
    /// Synthetic local tests only. HTTPS is required for other addresses.
    #[arg(long)]
    allow_loopback_http: bool,
    /// Explicit re-pin across a recorded authority break: the new authority public
    /// key (64 hex characters), obtained independently of the server. The next
    /// receipt must extend this journal's pinned chain; the break stays recorded.
    #[arg(long, value_name = "PUBLIC_KEY")]
    accept_authority_break: Option<String>,
    #[command(subcommand)]
    action: Action,
}
fn parse_address(s: &str) -> Result<Address, String> {
    Address::try_from(s.to_owned()).map_err(|e| e.to_string())
}

#[derive(Subcommand)]
pub enum Action {
    /// Preview every newly visible commit (including ancestry/recovery sources).
    Plan {
        candidate: String,
        /// Write a new file; refuses to overwrite an existing review plan.
        #[arg(long)]
        out: PathBuf,
        /// Publish for review without advancing the selected remote branch.
        #[arg(long)]
        publish_only: bool,
    },
    /// Execute an explicitly reviewed plan; never publishes unlisted dependencies.
    Push { plan: PathBuf },
    /// Retrieve the selected branch's signed history and advance its separate pin.
    Fetch,
    /// Fetch and fast-forward an explicitly selected local branch using exact local CAS.
    /// Divergent history needs a separate comparison/merge. Never writes a native file.
    Pull {
        local_branch: String,
        #[arg(long, requires = "expected_generation")]
        expected: Option<String>,
        #[arg(long, requires = "expected")]
        expected_generation: Option<i64>,
    },
    /// Read the last verified remote head offline, without contacting the server.
    Tracking,
    /// Save the remote's authority epoch chain and the receipts after the pin to a new
    /// file, for `receipt advance` / `receipt accept-break`. Changes nothing and does
    /// not require the configured key to reach the remote's active key.
    AuthorityProof {
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare two published remote commits across manifest paths, or node-level file detail.
    Compare {
        #[arg(long, value_parser = parse_address)]
        from: Address,
        #[arg(long, value_parser = parse_address)]
        to: Address,
        /// Compare node-level details for an exact file path.
        #[arg(long)]
        path: Option<String>,
        /// Format output as stable JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u8,
    remote: Remote,
    project: Uuid,
    branch: String,
    candidate: Address,
    expected: Option<Head>,
    update_branch: bool,
    /// Topological signed manifests: explicit disclosure of messages, paths and sources.
    publish: Vec<SignedCommit>,
}
/// The device-session scopes an action asks for: the least that works, chosen
/// here and nowhere else. The key must also be *granted* them for this project by
/// its account holder (profile -> signing keys); asking is not enough.
///
/// - plan, fetch, pull: `history:read`.
/// - push (which may stage, publish and advance a branch): `history:read` and
///   `history:write`.
/// - `history:review` (recording an approval or a change request) is requested by
///   no action: `sync` has no review command, so a pushing client can never approve
///   by accident. A command that records a review decision must ask for exactly
///   `history:review` and not `history:write`.
fn device_scopes(action: &Action) -> Vec<String> {
    let mut scopes = vec!["history:read".to_owned()];
    if matches!(action, Action::Push { .. }) {
        scopes.push("history:write".to_owned());
    }
    scopes
}

/// Build the network client. A device key asks only for the scopes this action
/// needs (see [`device_scopes`]).
fn credentials(options: &Options, remote: Remote) -> anyhow::Result<Client> {
    let loopback = options.allow_loopback_http;
    if let Some(path) = &options.device_key {
        let scopes = device_scopes(&options.action);
        let key = crate::signing::load(path)?;
        return Client::with_credential(
            remote,
            options.project,
            Credential::Device { key, scopes },
            None,
            loopback,
        );
    }
    // Rotation replaces both files; one path would let the access token overwrite
    // the refresh secret (or the reverse).
    if let (Some(access), Some(refresh)) = (&options.token_file, &options.refresh_token_file) {
        let same = access == refresh
            || matches!(
                (std::fs::canonicalize(access), std::fs::canonicalize(refresh)),
                (Ok(a), Ok(r)) if a == r
            );
        ensure!(
            !same,
            "--token-file and --refresh-token-file must be different files"
        );
    }
    let token = |path: &Path| -> anyhow::Result<String> {
        Ok(String::from_utf8(read(path, 16384)?)?.trim().to_owned())
    };
    match (&options.refresh_token_file, &options.token_file) {
        (Some(refresh_file), access_file) => {
            // An unreadable/absent access file only means: renew on first use.
            let initial = access_file
                .as_deref()
                .and_then(|path| token(path).ok())
                .filter(|t| !t.is_empty());
            Client::with_credential(
                remote,
                options.project,
                Credential::Refresh {
                    refresh_file: refresh_file.clone(),
                    access_file: access_file.clone(),
                },
                initial.as_deref(),
                loopback,
            )
        }
        (None, Some(path)) => Client::new(remote, options.project, &token(path)?, loopback),
        (None, None) => {
            anyhow::bail!("provide --device-key, or --token-file and/or --refresh-token-file")
        }
    }
}
fn read(path: &Path, cap: usize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= cap, "input exceeds byte limit");
    Ok(bytes)
}
enum SyncOutput {
    Json(Value),
    Text(String),
}

pub async fn run(options: Options) -> anyhow::Result<()> {
    ensure!(
        engine_core::repository::valid_branch(&options.branch),
        "invalid branch"
    );
    let remote: Remote = serde_json::from_slice(&read(&options.remote, 8192)?)?;
    let scope = Scope {
        authority: remote.authority,
        project: options.project,
        branch: options.branch.clone(),
    };
    // Open the repository first so the journal refuses aliases to it, even on first use.
    let repo = LocalRepository::open(&options.repository, options.project).await?;
    let journal = ReceiptJournal::open(&options.journal).await?;
    let result: anyhow::Result<SyncOutput> = async {
        if matches!(options.action, Action::Tracking) {
            return Ok(SyncOutput::Json(serde_json::to_value(
                journal.pin(&scope).await?,
            )?));
        }
        let mut client = credentials(&options, remote)?;
        if let Some(key) = options.accept_authority_break.clone() {
            client = client.accepting_break(key)?;
        }
        if !matches!(options.action, Action::AuthorityProof { .. }) {
            client.authority().await?;
        }
        match options.action {
            Action::Compare {
                from,
                to,
                path,
                json,
            } => {
                if let Some(path) = path {
                    let report = compare_file(&client, &from, &to, &path).await?;
                    if json {
                        Ok(SyncOutput::Json(format_file_compare_json(&report)?))
                    } else {
                        Ok(SyncOutput::Text(format_file_compare_text(&report)))
                    }
                } else {
                    let report = compare(&client, &from, &to).await?;
                    if json {
                        Ok(SyncOutput::Json(format_compare_json(&report)?))
                    } else {
                        Ok(SyncOutput::Text(format_compare_text(&report)))
                    }
                }
            }
            Action::Plan {
                candidate,
                out,
                publish_only,
            } => {
                let plan = plan(
                    &repo,
                    &client,
                    &journal,
                    &scope,
                    Address::try_from(candidate)?,
                    !publish_only,
                )
                .await?;
                let bytes = serde_json::to_vec_pretty(&plan)?;
                ensure!(bytes.len() <= MAX_PLAN_BYTES, "review plan byte limit");
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(out)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                Ok(SyncOutput::Json(json!({"commits_to_publish":plan.publish.len(),"candidate":plan.candidate,"update_branch":plan.update_branch,"expected":plan.expected,"instruction":"Review the complete plan, including parent and recovery commits, before sync push."})))
            }
            Action::Push { plan: input } => {
                let approved: Plan = serde_json::from_slice(&read(&input, MAX_PLAN_BYTES)?)?;
                Ok(SyncOutput::Json(
                    push(&repo, &client, &journal, &scope, approved).await?,
                ))
            }
            Action::Fetch => {
                let receipt = client.head(&scope).await?.ok_or_else(|| {
                    anyhow!("remote branch is absent; local tracking is retained")
                })?;
                proof(&client, &journal, &scope, &receipt).await?;
                let count = transfer::fetch(&repo, &client, &receipt.receipt.head.commit).await?;
                track(&client, &journal, &scope, receipt.clone()).await?;
                Ok(SyncOutput::Json(json!({
                    "head": receipt.receipt.head,
                    "new_commits": count,
                    "local_branches_changed": false
                })))
            }
            Action::Pull {
                local_branch,
                expected,
                expected_generation,
            } => {
                let expected = match (expected, expected_generation) {
                    (Some(address), Some(generation)) => Some(Head {
                        commit: Address::try_from(address)?,
                        generation,
                    }),
                    (None, None) => None,
                    _ => {
                        anyhow::bail!("expected local address and generation must be supplied together")
                    }
                };
                Ok(SyncOutput::Json(
                    pull(
                        &repo,
                        &client,
                        &journal,
                        &scope,
                        &local_branch,
                        expected.as_ref(),
                    )
                    .await?,
                ))
            }
            Action::AuthorityProof { out } => Ok(SyncOutput::Json(
                authority_proof(&client, &journal, &scope, &out).await?,
            )),
            Action::Tracking => unreachable!(),
        }
    }
    .await;
    journal.close().await;
    repo.close().await;
    match result? {
        SyncOutput::Json(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        SyncOutput::Text(text) => println!("{text}"),
    }
    Ok(())
}

async fn pull(
    repo: &LocalRepository,
    client: &Client,
    journal: &ReceiptJournal,
    scope: &Scope,
    branch: &str,
    expected: Option<&Head>,
) -> anyhow::Result<Value> {
    ensure!(
        engine_core::repository::valid_branch(branch),
        "invalid local branch"
    );
    ensure!(
        repo.head(branch).await?.as_ref() == expected,
        "local branch changed; inspect its current address and generation"
    );
    let receipt = client
        .head(scope)
        .await?
        .ok_or_else(|| anyhow!("remote branch is absent"))?;
    proof(client, journal, scope, &receipt).await?;
    transfer::fetch(repo, client, &receipt.receipt.head.commit).await?;
    track(client, journal, scope, receipt.clone()).await?;
    if let Some(head) = expected {
        if head.commit == receipt.receipt.head.commit {
            ensure!(
                repo.head(branch).await?.as_ref() == expected,
                "local branch changed during pull"
            );
            return Ok(
                json!({"local_head":head,"remote_head":receipt.receipt.head,"local_branch_changed":false,"native_file_changed":false}),
            );
        }
        ensure!(
            repo.merge_bases(&head.commit, &receipt.receipt.head.commit)
                .await?
                .contains(&head.commit),
            "local history diverged; fetched history is retained, compare and resolve explicitly"
        );
    }
    let head = repo
        .compare_and_swap(branch, expected, &receipt.receipt.head.commit)
        .await?;
    Ok(
        json!({"local_head":head,"remote_head":receipt.receipt.head,"local_branch_changed":true,"native_file_changed":false}),
    )
}

/// The recorded break that follows `pin_key` and names `new_key`.
fn break_statement(
    server: &engine_core::repository::authority_epoch::Served,
    pin_key: &str,
    new_key: &str,
) -> anyhow::Result<SignedTransition> {
    server
        .chain
        .statements()
        .iter()
        .find(|s| {
            s.transition.kind == Kind::Recovery
                && s.transition.old_key == pin_key
                && s.transition.new_key == new_key
        })
        .cloned()
        .ok_or_else(|| {
            anyhow!("no recorded break leads from this journal's pinned key to that key")
        })
}

/// Verify a bounded contiguous proof in memory before retaining its pages. An
/// initial checkpoint trusts the independently supplied authority, not old history.
///
/// The configured key and the pin are trust anchors; the remote's epoch chain only
/// connects them to the key that signed this head. A recorded break or a revocation
/// marker is a refusal, never something the server can talk past. Only an explicit
/// `--accept-authority-break NEW_KEY` crosses a break, and only with a receipt that
/// extends the pinned chain.
async fn proof(
    client: &Client,
    journal: &ReceiptJournal,
    scope: &Scope,
    target: &SignedReceipt,
) -> anyhow::Result<Vec<SignedReceipt>> {
    let server = client.server().await?;
    target.verify()?;
    ensure!(
        target.receipt.scope == *scope && server.knows(&target.receipt.issuer_key),
        "untrusted receipt scope/key"
    );
    let configured = client.break_key().unwrap_or(&client.remote.public_key);
    let Some(mut pin) = journal.pin(scope).await? else {
        server
            .vet(configured, &target.receipt.issuer_key)
            .map_err(|refusal| anyhow!("{refusal}"))?;
        return Ok(vec![]);
    };
    let mut breaking = None;
    if let Some(new_key) = client.break_key() {
        // A head the pin already holds changes nothing, whatever the key's state.
        if pin.receipt() == target {
            return Ok(vec![]);
        }
        if pin.trusted_key() != new_key {
            breaking = Some(break_statement(server, pin.trusted_key(), new_key)?);
        }
    }
    if let Some(statement) = &breaking {
        // From the independently supplied key onward: dual-signed and unrevoked.
        server
            .vet(&statement.transition.new_key, &server.active_key)
            .map_err(|refusal| anyhow!("{refusal}"))?;
    } else {
        ensure!(!pin.revoked(), "remote authority is locally revoked");
        server
            .related(configured, pin.trusted_key())
            .map_err(|refusal| match refusal {
                Refusal::UnknownKey => anyhow!(
                    "configured key differs from journal and is not on the authority chain; update remote.json from an independent source"
                ),
                other => anyhow!("configured key and journal are separated: {other}"),
            })?;
        match server.vet(pin.trusted_key(), &server.active_key) {
            Ok(()) => {}
            Err(Refusal::Revoked { marker, own }) => {
                if own {
                    // The key this journal trusts is marked unsafe: no later
                    // receipt, retry or statement may revive it implicitly.
                    journal.revoke(scope).await?;
                    let after = pin.receipt().receipt.issued_at_ms >= marker.effective_at_ms;
                    anyhow::bail!(
                        "{}; the pinned receipt was declared {} the stated compromise time{}",
                        Refusal::Revoked { marker, own },
                        if after { "at or after" } else { "before" },
                        if after {
                            ", so treat it as untrusted and re-verify out of band"
                        } else {
                            ""
                        }
                    );
                }
                anyhow::bail!("{}", Refusal::Revoked { marker, own });
            }
            Err(refusal) => anyhow::bail!("{refusal}"),
        }
    }
    ensure!(
        pin.receipt().receipt.head.generation <= target.receipt.head.generation,
        "remote rollback below pinned generation"
    );
    let mut proof = Vec::new();
    while pin.receipt().receipt.head.generation < target.receipt.head.generation {
        #[derive(Deserialize)]
        struct Page {
            items: Vec<SignedReceipt>,
        }
        let remaining = target.receipt.head.generation - pin.receipt().receipt.head.generation;
        let page: Page = client
            .get(
                "history/receipts",
                &[
                    ("branch", scope.branch.clone()),
                    (
                        "after_generation",
                        pin.receipt().receipt.head.generation.to_string(),
                    ),
                    ("limit", remaining.min(256).to_string()),
                ],
                2 * 1024 * 1024,
            )
            .await?;
        ensure!(
            !page.items.is_empty()
                && page.items.len() <= remaining.min(256) as usize
                && proof.len() + page.items.len() <= MAX_COMMITS,
            "receipt catch-up limit or missing proof; fetch in smaller trusted checkpoints"
        );
        let before = pin.receipt().receipt.head.generation;
        let (first, rest) = page.items.split_first().expect("page is not empty");
        let next = match breaking.take() {
            Some(statement) => {
                // The first receipt after the pin must be signed by NEW_KEY and
                // extend the pinned chain exactly; the break stays recorded.
                let after = pin.accept_break(&statement, &statement.transition.new_key, first)?;
                after.advance_chain(&server.chain, rest)?.0
            }
            None => pin.advance_chain(&server.chain, &page.items)?.0,
        };
        ensure!(
            next.receipt().receipt.head.generation > before,
            "receipt proof made no progress"
        );
        proof.extend(page.items);
        pin = next;
    }
    ensure!(pin.receipt() == target, "remote fork at pinned generation");
    Ok(proof)
}
async fn track(
    client: &Client,
    journal: &ReceiptJournal,
    scope: &Scope,
    receipt: SignedReceipt,
) -> anyhow::Result<()> {
    let checked = proof(client, journal, scope, &receipt).await?;
    let server = client.server().await?;
    let Some(pin) = journal.pin(scope).await? else {
        // `proof` connected the independently configured key to this issuer.
        journal
            .trust_checkpoint(scope, &receipt.receipt.issuer_key.clone(), receipt)
            .await?;
        return Ok(());
    };
    if checked.is_empty() {
        // Recheck inside a transaction: another process may have advanced/revoked.
        journal
            .advance_chain(scope, &server.chain, &[receipt])
            .await?;
        return Ok(());
    }
    let mut rest: &[SignedReceipt] = &checked;
    if let Some(new_key) = client.break_key() {
        if pin.trusted_key() != new_key && checked[0].receipt.issuer_key == new_key {
            let statement = break_statement(server, pin.trusted_key(), new_key)?;
            journal
                .accept_break(scope, &statement, new_key, &checked[0])
                .await?;
            rest = &checked[1..];
        }
    }
    for page in rest.chunks(256) {
        journal.advance_chain(scope, &server.chain, page).await?;
    }
    Ok(())
}

/// Offline-verifiable bundle for an explicit re-pin or a manual catch-up. Nothing
/// is applied: `receipt advance` / `receipt accept-break` re-verify it all.
async fn authority_proof(
    client: &Client,
    journal: &ReceiptJournal,
    scope: &Scope,
    out: &Path,
) -> anyhow::Result<Value> {
    #[derive(Deserialize)]
    struct Page {
        items: Vec<SignedReceipt>,
    }
    let server = client.server().await?;
    let after = journal
        .pin(scope)
        .await?
        .map_or(0, |pin| pin.receipt().receipt.head.generation);
    let page: Option<Page> = client
        .get_optional(
            "history/receipts",
            &[
                ("branch", scope.branch.clone()),
                ("after_generation", after.to_string()),
                ("limit", "256".into()),
            ],
            2 * 1024 * 1024,
        )
        .await?;
    let bundle = crate::authority::ChainProof {
        version: 1,
        authority: scope.authority,
        active_key: server.active_key.clone(),
        active_epoch: server.active_epoch,
        revoked: server.revoked.values().cloned().collect(),
        rotations: server.chain.statements().to_vec(),
        receipts: page.map(|p| p.items).unwrap_or_default(),
    };
    let bytes = serde_json::to_vec_pretty(&bundle)?;
    ensure!(bytes.len() <= MAX_PLAN_BYTES, "authority proof byte limit");
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(
        json!({"active_epoch":server.active_epoch,"statements":bundle.rotations.len(),"receipts_after_pin":bundle.receipts.len(),"revocation_markers":bundle.revoked.len(),"applied":false}),
    )
}

async fn plan(
    repo: &LocalRepository,
    client: &Client,
    journal: &ReceiptJournal,
    scope: &Scope,
    candidate: Address,
    update_branch: bool,
) -> anyhow::Result<Plan> {
    let head = client.head(scope).await?;
    if let Some(receipt) = &head {
        proof(client, journal, scope, receipt).await?;
    } else {
        ensure!(
            journal.pin(scope).await?.is_none(),
            "remote branch disappeared; tracking is retained"
        );
    }
    let mut stack = vec![(candidate.clone(), false)];
    let mut visited = BTreeSet::new();
    let mut waiting = BTreeMap::new();
    let mut publish = Vec::new();
    let mut bytes = 0;
    while let Some((address, exit)) = stack.pop() {
        if exit {
            if let Some(signed) = waiting.remove(&address) {
                publish.push(signed);
            }
            continue;
        }
        if !visited.insert(address.clone()) {
            continue;
        }
        ensure!(
            visited.len() <= MAX_COMMITS,
            "selected history exceeds transfer commit limit"
        );
        let signed = repo.commit(&address).await?;
        if client.published(&address).await?.is_some() {
            continue;
        }
        bytes += serde_json::to_vec(&signed)?.len();
        ensure!(bytes <= MAX_PLAN_BYTES / 2, "selected manifest byte limit");
        stack.push((address.clone(), true));
        for dependency in signed.commit.dependencies().into_iter().rev() {
            stack.push((dependency, false));
        }
        waiting.insert(address, signed);
    }
    Ok(Plan {
        version: 1,
        remote: client.remote.clone(),
        project: repo.project(),
        branch: scope.branch.clone(),
        candidate,
        expected: head.map(|r| r.receipt.head),
        update_branch,
        publish,
    })
}

async fn push(
    repo: &LocalRepository,
    client: &Client,
    journal: &ReceiptJournal,
    scope: &Scope,
    approved: Plan,
) -> anyhow::Result<Value> {
    ensure!(
        approved.version == 1
            && approved.remote == client.remote
            && approved.project == repo.project()
            && approved.branch == scope.branch,
        "plan does not match explicit remote/project/branch"
    );
    ensure!(approved.publish.len() <= MAX_COMMITS, "plan commit limit");
    let fresh = plan(
        repo,
        client,
        journal,
        scope,
        approved.candidate.clone(),
        approved.update_branch,
    )
    .await?;
    if approved.update_branch && fresh.expected != approved.expected {
        // Lost successful CAS response: verify the exact next generation, then fetch
        // receipts. Never repeat a stale mutation or overwrite someone else's work.
        let generation = approved
            .expected
            .as_ref()
            .map_or(1, |h| h.generation.saturating_add(1));
        ensure!(
            fresh.expected
                == Some(Head {
                    commit: approved.candidate.clone(),
                    generation
                }),
            "remote branch changed; fetch, compare and make a new plan"
        );
        let receipt = client
            .head(scope)
            .await?
            .ok_or_else(|| anyhow!("remote branch disappeared"))?;
        ensure!(
            Some(&receipt.receipt.head) == fresh.expected.as_ref(),
            "remote branch changed during retry"
        );
        track(client, journal, scope, receipt).await?;
        return Ok(
            json!({"head":fresh.expected,"already_applied":true,"local_branches_changed":false}),
        );
    }
    let mut permitted = BTreeMap::new();
    for signed in &approved.publish {
        let address = signed.verify()?;
        ensure!(
            signed.commit.project == repo.project() && permitted.insert(address, signed).is_none(),
            "invalid/duplicate approved commit"
        );
    }
    for signed in &fresh.publish {
        ensure!(
            permitted
                .get(&signed.verify()?)
                .is_some_and(|p| p.commit == signed.commit && p.signature == signed.signature),
            "new private dependency is absent from reviewed plan"
        );
    }
    for signed in &fresh.publish {
        transfer::upload(repo, client, signed).await?;
        client.post("staging/commits", json!(signed)).await?;
        client
            .post("history/commits", json!({"address":signed.verify()?}))
            .await?;
    }
    if !approved.update_branch {
        return Ok(json!({"candidate":approved.candidate,"published":true,"branch_changed":false}));
    }
    if approved
        .expected
        .as_ref()
        .is_some_and(|h| h.commit == approved.candidate)
    {
        let receipt = client
            .head(scope)
            .await?
            .ok_or_else(|| anyhow!("remote branch disappeared"))?;
        ensure!(
            Some(&receipt.receipt.head) == approved.expected.as_ref(),
            "remote branch changed during up-to-date check; fetch before tracking it"
        );
        track(client, journal, scope, receipt).await?;
        return Ok(
            json!({"head":approved.expected,"already_applied":true,"local_branches_changed":false}),
        );
    }
    let result = client.post("history/refs", json!({"branch":scope.branch,"candidate":approved.candidate,"expected":approved.expected})).await
        .context("candidate publication may have succeeded; retained candidates can be reviewed; fetch after any uncertain ref result")?;
    let receipt: SignedReceipt = serde_json::from_value(
        result
            .get("signed_receipt")
            .cloned()
            .ok_or_else(|| anyhow!("missing ref receipt"))?,
    )?;
    ensure!(
        receipt.receipt.head.commit == approved.candidate
            && receipt.receipt.head.generation
                == approved
                    .expected
                    .as_ref()
                    .map_or(1, |h| h.generation.saturating_add(1)),
        "unexpected accepted ref"
    );
    track(client, journal, scope, receipt.clone()).await?;
    Ok(json!({"head":receipt.receipt.head,"published":true,"local_branches_changed":false}))
}

pub async fn compare(
    client: &Client,
    from: &Address,
    to: &Address,
) -> anyhow::Result<ProjectDiffReport> {
    let mut all_changes = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    let mut totals: Option<DiffTotals> = None;
    let mut last_path: Option<String> = None;

    loop {
        let page = client
            .compare_page(from, to, None, cursor.as_deref())
            .await?;

        ensure!(
            page.project == client.project,
            "remote report project mismatch: expected {}, got {}",
            client.project,
            page.project
        );
        ensure!(
            &page.from == from,
            "remote report from-address mismatch: expected {}, got {}",
            from.as_str(),
            page.from.as_str()
        );
        ensure!(
            &page.to == to,
            "remote report to-address mismatch: expected {}, got {}",
            to.as_str(),
            page.to.as_str()
        );

        if let Some(expected_totals) = &totals {
            ensure!(
                expected_totals == &page.totals,
                "remote report totals changed across pages"
            );
        } else {
            totals = Some(page.totals.clone());
        }

        for change in page.changes {
            if let Some(last) = &last_path {
                ensure!(
                    change.path.as_str() > last.as_str(),
                    "remote report changes out of order"
                );
            }
            last_path = Some(change.path.clone());
            all_changes.push(change);
        }

        if !page.more {
            ensure!(
                page.next_cursor.is_none(),
                "terminal page must not include next_cursor"
            );
            break;
        }

        let next = page.next_cursor.ok_or_else(|| {
            anyhow!("remote report indicated more changes but omitted next_cursor")
        })?;
        ensure!(!next.is_empty(), "empty cursor");
        ensure!(seen_cursors.insert(next.clone()), "cursor loop detected");
        ensure!(seen_cursors.len() <= 10_000, "exceeded maximum page count");
        cursor = Some(next);
    }

    let totals = totals.unwrap_or(DiffTotals {
        added: 0,
        removed: 0,
        modified: 0,
        unchanged: 0,
        total_changes: 0,
    });
    ensure!(
        all_changes.len() == totals.total_changes,
        "retrieved changes count ({}) does not match report totals ({})",
        all_changes.len(),
        totals.total_changes
    );

    Ok(ProjectDiffReport {
        project: client.project,
        from: from.clone(),
        to: to.clone(),
        totals,
        changes: all_changes,
        next_cursor: None,
        more: false,
    })
}

pub fn format_compare_text(report: &ProjectDiffReport) -> String {
    let mut out = String::new();
    out.push_str("Server-produced metadata (unverified by receipt journal)\n");
    out.push_str(&format!("Project: {}\n", report.project));
    out.push_str(&format!("From:    {}\n", report.from.as_str()));
    out.push_str(&format!("To:      {}\n", report.to.as_str()));
    out.push_str(&format!(
        "Totals:  {} change(s) ({} added, {} removed, {} modified, {} unchanged)\n",
        report.totals.total_changes,
        report.totals.added,
        report.totals.removed,
        report.totals.modified,
        report.totals.unchanged,
    ));
    if !report.changes.is_empty() {
        out.push('\n');
        for change in &report.changes {
            let symbol = match change.kind {
                DiffKind::Added => "+",
                DiffKind::Removed => "-",
                DiffKind::Modified => "~",
                DiffKind::Unchanged => "=",
            };
            let doc_info = match (&change.from, &change.to) {
                (Some(from), Some(to)) if from.document != to.document => {
                    format!(" (document {} -> {})", from.document.0, to.document.0)
                }
                (_, Some(to)) => format!(" (document {})", to.document.0),
                (Some(from), None) => format!(" (document {})", from.document.0),
                (None, None) => String::new(),
            };
            out.push_str(&format!("  {} {}{}\n", symbol, change.path, doc_info));
        }
    }
    out.push_str(
        "\nNote: Server-produced metadata; does not independently verify document content.",
    );
    out
}

pub fn format_compare_json(report: &ProjectDiffReport) -> anyhow::Result<Value> {
    let mut value = serde_json::to_value(report)?;
    if let Value::Object(ref mut map) = value {
        map.insert("server_metadata".into(), Value::Bool(true));
        map.insert(
            "disclaimer".into(),
            Value::String(
                "Server-produced metadata; does not independently verify document content or cryptographic receipts.".into(),
            ),
        );
    }
    Ok(value)
}

pub async fn compare_file(
    client: &Client,
    from: &Address,
    to: &Address,
    path: &str,
) -> anyhow::Result<FileCompareReport> {
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    let mut initial_report: Option<FileCompareReport> = None;
    let mut all_node_changes = Vec::new();
    let mut last_node_id: Option<String> = None;

    loop {
        let page = client
            .compare_file_page(from, to, path, None, cursor.as_deref(), false)
            .await?;

        ensure!(
            page.project == client.project,
            "remote report project mismatch: expected {}, got {}",
            client.project,
            page.project
        );
        ensure!(
            &page.from == from,
            "remote report from-address mismatch: expected {}, got {}",
            from.as_str(),
            page.from.as_str()
        );
        ensure!(
            &page.to == to,
            "remote report to-address mismatch: expected {}, got {}",
            to.as_str(),
            page.to.as_str()
        );
        ensure!(
            page.path == path,
            "remote report path mismatch: expected {}, got {}",
            path,
            page.path
        );

        if let Some(initial) = &initial_report {
            ensure!(
                initial.kind == page.kind,
                "remote report diff kind changed across pages"
            );
            ensure!(
                initial.document_replaced == page.document_replaced,
                "remote report document_replaced flag changed across pages"
            );
            ensure!(
                initial.from_file == page.from_file,
                "remote report from_file changed across pages"
            );
            ensure!(
                initial.to_file == page.to_file,
                "remote report to_file changed across pages"
            );
            if let (Some(init_nd), Some(page_nd)) = (&initial.node_diff, &page.node_diff) {
                ensure!(
                    init_nd.document_id == page_nd.document_id,
                    "remote report document_id changed across pages"
                );
                ensure!(
                    init_nd.from_root == page_nd.from_root && init_nd.to_root == page_nd.to_root,
                    "remote report roots changed across pages"
                );
                ensure!(
                    init_nd.whole_state_identical == page_nd.whole_state_identical,
                    "remote report whole_state_identical changed across pages"
                );
                ensure!(
                    init_nd.totals == page_nd.totals,
                    "remote report totals changed across pages"
                );
                ensure!(
                    init_nd.components == page_nd.components,
                    "remote report components changed across pages"
                );
            }
        }

        if let Some(node_diff) = &page.node_diff {
            for change in &node_diff.changes {
                if let Some(last) = &last_node_id {
                    ensure!(
                        change.node_id.0.as_str() > last.as_str(),
                        "remote report node changes out of order"
                    );
                }
                last_node_id = Some(change.node_id.0.clone());
                all_node_changes.push(change.clone());
            }
        }

        let is_more = page.more;
        let next_cursor = page.next_cursor.clone();

        if initial_report.is_none() {
            initial_report = Some(page);
        }

        if !is_more {
            ensure!(
                next_cursor.is_none(),
                "terminal page must not include next_cursor"
            );
            break;
        }

        let next = next_cursor.ok_or_else(|| {
            anyhow!("remote report indicated more changes but omitted next_cursor")
        })?;
        ensure!(!next.is_empty(), "empty cursor");
        ensure!(seen_cursors.insert(next.clone()), "cursor loop detected");
        ensure!(seen_cursors.len() <= 10_000, "exceeded maximum page count");
        cursor = Some(next);
    }

    let mut final_report = initial_report.ok_or_else(|| anyhow!("empty response"))?;
    if let Some(ref mut nd) = final_report.node_diff {
        ensure!(
            all_node_changes.len() == nd.totals.total_changes,
            "retrieved node changes count ({}) does not match report totals ({})",
            all_node_changes.len(),
            nd.totals.total_changes
        );
        nd.changes = all_node_changes;
        nd.next_cursor = None;
        nd.more = false;
    }
    final_report.next_cursor = None;
    final_report.more = false;

    Ok(final_report)
}

pub fn format_file_compare_text(report: &FileCompareReport) -> String {
    let mut out = String::new();
    out.push_str("Server-produced metadata (unverified by receipt journal)\n");
    out.push_str(&format!("Project: {}\n", report.project));
    out.push_str(&format!("From:    {}\n", report.from.as_str()));
    out.push_str(&format!("To:      {}\n", report.to.as_str()));
    out.push_str(&format!("Path:    {}\n", report.path));

    let kind_str = match report.kind {
        DiffKind::Added => "added",
        DiffKind::Removed => "removed",
        DiffKind::Modified => {
            if report.document_replaced {
                "modified (document identity replaced)"
            } else {
                "modified"
            }
        }
        DiffKind::Unchanged => "unchanged",
    };
    out.push_str(&format!("Status:  {}\n", kind_str));

    if let (Some(from), Some(to)) = (&report.from_file, &report.to_file) {
        if from.document != to.document {
            out.push_str(&format!(
                "Document: replaced ({} -> {})\n",
                from.document.0, to.document.0
            ));
        } else {
            out.push_str(&format!("Document: {}\n", from.document.0));
            out.push_str(&format!(
                "Roots:    {} -> {}\n",
                from.state.as_str(),
                to.state.as_str()
            ));
        }
    } else if let Some(to) = &report.to_file {
        out.push_str(&format!(
            "Document: {} (root {})\n",
            to.document.0,
            to.state.as_str()
        ));
    } else if let Some(from) = &report.from_file {
        out.push_str(&format!(
            "Document: {} (root {})\n",
            from.document.0,
            from.state.as_str()
        ));
    }

    if let Some(nd) = &report.node_diff {
        out.push_str(&format!(
            "Node totals: {} change(s) ({} added, {} removed, {} modified, {} unchanged)\n",
            nd.totals.total_changes,
            nd.totals.added,
            nd.totals.removed,
            nd.totals.modified,
            nd.totals.unchanged,
        ));
        out.push_str(&format!(
            "Components: comments (from: {}, to: {}, changed: {}), suggestions (from: {}, to: {}, changed: {}), removed choices (from: {}, to: {}, changed: {})\n",
            nd.components.comments_from_count,
            nd.components.comments_to_count,
            nd.components.comments_changed,
            nd.components.suggestions_from_count,
            nd.components.suggestions_to_count,
            nd.components.suggestions_changed,
            nd.components.removed_choices_from_count,
            nd.components.removed_choices_to_count,
            nd.components.removed_choices_changed,
        ));

        if !nd.changes.is_empty() {
            out.push('\n');
            for change in &nd.changes {
                let symbol = match change.kind {
                    NodeDiffKind::Added => "+",
                    NodeDiffKind::Removed => "-",
                    NodeDiffKind::Modified => "~",
                    NodeDiffKind::Unchanged => "=",
                };
                let type_info = match (&change.from, &change.to) {
                    (Some(f), Some(t)) if f.node_type != t.node_type => {
                        format!(" ({}:{} -> {}:{})", f.node_type, f.pos, t.node_type, t.pos)
                    }
                    (Some(f), _) => format!(" ({}:{})", f.node_type, f.pos),
                    (_, Some(t)) => format!(" ({}:{})", t.node_type, t.pos),
                    (None, None) => String::new(),
                };
                out.push_str(&format!("  {} {}{}\n", symbol, change.node_id.0, type_info));

                for field in &change.field_changes {
                    out.push_str(&format!("    field {}: ", field.field));
                    match (&field.from, &field.to) {
                        (None, Some(to_val)) => {
                            out.push_str(&format!("added {}\n", format_bounded_val(to_val)))
                        }
                        (Some(from_val), None) => out
                            .push_str(&format!("removed (was {})\n", format_bounded_val(from_val))),
                        (Some(from_val), Some(to_val)) => out.push_str(&format!(
                            "{} -> {}\n",
                            format_bounded_val(from_val),
                            format_bounded_val(to_val)
                        )),
                        (None, None) => out.push_str("unchanged\n"),
                    }
                }
            }
        }
    }

    out.push_str(
        "\nNote: Server-produced metadata; does not independently verify document content or native formatting.",
    );
    out
}

fn format_bounded_val(v: &BoundedValue) -> String {
    match v {
        BoundedValue::Value(val) => val.to_string(),
        BoundedValue::Omitted(omitted) => {
            format!(
                "[omitted: {} bytes, sha256: {}]",
                omitted.bytes, omitted.sha256
            )
        }
    }
}

pub fn format_file_compare_json(report: &FileCompareReport) -> anyhow::Result<Value> {
    let mut value = serde_json::to_value(report)?;
    if let Value::Object(ref mut map) = value {
        map.insert("server_metadata".into(), Value::Bool(true));
        map.insert(
            "disclaimer".into(),
            Value::String(
                "Server-produced metadata; does not independently verify document content or cryptographic receipts.".into(),
            ),
        );
    }
    Ok(value)
}
