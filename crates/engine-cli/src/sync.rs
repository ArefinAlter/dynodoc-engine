//! Selected commit transfer. The separate receipt journal is remote tracking;
//! fetch/push never move local working branches or write a native document.
use anyhow::{anyhow, ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Subcommand};
use engine_core::{
    repository::{
        attestation::{Scope, SignedReceipt},
        authority_epoch::{Kind, Refusal, SignedTransition},
        local::{LocalRepository, ObjectKey, ObjectPacket},
        log::CommitLogEntry,
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
    Address::try_from(s.to_string()).map_err(|e| e.to_string())
}

#[derive(Subcommand)]
pub enum Action {
    /// Retrieve a bounded page or full chain of first-parent commit history.
    Log {
        /// Explicit starting commit address (required unless --cursor is supplied).
        #[arg(long, value_parser = parse_address)]
        head: Option<Address>,
        /// Page limit (1..=50, default 20).
        #[arg(long)]
        limit: Option<usize>,
        /// Continuation cursor for pagination.
        #[arg(long)]
        cursor: Option<String>,
        /// Retrieve all remaining first-parent commits across pages under budgets.
        #[arg(long)]
        all: bool,
        /// Format output as stable JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
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
pub enum SyncOutput {
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
            Action::Log {
                head,
                limit,
                cursor,
                all,
                json,
            } => {
                let log_res = log(&client, head.as_ref(), limit, cursor.as_deref(), all).await?;
                if json {
                    Ok(SyncOutput::Json(format_log_json(&log_res)?))
                } else {
                    Ok(SyncOutput::Text(format_log_text(&log_res)))
                }
            }
            Action::Plan { candidate, out, publish_only } => {
                let plan = plan(&repo, &client, &journal, &scope, Address::try_from(candidate)?, !publish_only).await?;
                let bytes = serde_json::to_vec_pretty(&plan)?;
                ensure!(bytes.len() <= MAX_PLAN_BYTES, "review plan byte limit");
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(out)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                Ok(SyncOutput::Json(json!({"commits_to_publish":plan.publish.len(),"candidate":plan.candidate,"update_branch":plan.update_branch,"expected":plan.expected,"instruction":"Review the complete plan, including parent and recovery commits, before sync push."})))
            }
            Action::Push { plan: input } => {
                let approved: Plan = serde_json::from_slice(&read(&input, MAX_PLAN_BYTES)?)?;
                push(&repo, &client, &journal, &scope, approved).await.map(SyncOutput::Json)
            }
            Action::Fetch => {
                let receipt = client.head(&scope).await?.ok_or_else(|| anyhow!("remote branch is absent; local tracking is retained"))?;
                proof(&client, &journal, &scope, &receipt).await?;
                let count = transfer::fetch(&repo, &client, &receipt.receipt.head.commit).await?;
                track(&client, &journal, &scope, receipt.clone()).await?;
                Ok(SyncOutput::Json(json!({"head":receipt.receipt.head,"new_commits":count,"local_branches_changed":false})))
            }
            Action::Pull { local_branch, expected, expected_generation } => {
                let expected = match (expected,expected_generation) {
                    (Some(address),Some(generation)) => Some(Head { commit:Address::try_from(address)?,generation }),
                    (None,None) => None,
                    _ => anyhow::bail!("expected local address and generation must be supplied together"),
                };
                pull(&repo,&client,&journal,&scope,&local_branch,expected.as_ref()).await.map(SyncOutput::Json)
            }
            Action::AuthorityProof { out } => authority_proof(&client, &journal, &scope, &out).await.map(SyncOutput::Json),
            Action::Tracking => unreachable!(),
        }
    }.await;
    journal.close().await;
    repo.close().await;
    match result? {
        SyncOutput::Json(val) => println!("{}", serde_json::to_string_pretty(&val)?),
        SyncOutput::Text(txt) => {
            if txt.ends_with('\n') {
                print!("{}", txt);
            } else {
                println!("{}", txt);
            }
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteLogResult {
    pub project: Uuid,
    pub head: Address,
    pub entries: Vec<CommitLogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub more: bool,
}

pub async fn log(
    client: &Client,
    head: Option<&Address>,
    limit: Option<usize>,
    cursor: Option<&str>,
    all: bool,
) -> anyhow::Result<RemoteLogResult> {
    ensure!(
        head.is_some() || cursor.is_some(),
        "--head is required when --cursor is not provided"
    );
    if let Some(l) = limit {
        ensure!(l > 0 && l <= 50, "limit must be between 1 and 50");
    }

    let mut current_cursor = cursor.map(|s| s.to_string());
    let mut seen_cursors = BTreeSet::new();
    let mut seen_addresses = BTreeSet::new();
    let mut initial_head = head.cloned();
    let mut all_entries = Vec::new();
    let mut pages_fetched = 0usize;

    loop {
        let page = client
            .log_page(initial_head.as_ref(), limit, current_cursor.as_deref())
            .await?;

        ensure!(
            page.project == client.project,
            "remote report project mismatch: expected {}, got {}",
            client.project,
            page.project
        );

        if let Some(ref expected_head) = initial_head {
            ensure!(
                &page.head == expected_head,
                "remote report head mismatch: expected {}, got {}",
                expected_head.as_str(),
                page.head.as_str()
            );
        } else {
            initial_head = Some(page.head.clone());
        }

        for entry in page.entries {
            ensure!(
                seen_addresses.insert(entry.address.clone()),
                "duplicate commit address encountered across pages: {}",
                entry.address.as_str()
            );
            all_entries.push(entry);
        }

        pages_fetched += 1;

        if !all {
            return Ok(RemoteLogResult {
                project: page.project,
                head: initial_head.unwrap_or(page.head),
                entries: all_entries,
                next_cursor: page.next_cursor,
                more: page.more,
            });
        }

        match page.next_cursor {
            Some(next_cursor) => {
                ensure!(
                    page.more,
                    "remote returned continuation cursor but marked more=false"
                );
                ensure!(
                    seen_cursors.insert(next_cursor.clone()),
                    "cursor loop detected in remote history log"
                );
                ensure!(
                    pages_fetched < 10_000,
                    "exceeded maximum pagination limit (10000 pages)"
                );
                current_cursor = Some(next_cursor);
            }
            None => {
                ensure!(
                    !page.more,
                    "remote indicated more commits exist but provided no continuation cursor"
                );
                return Ok(RemoteLogResult {
                    project: page.project,
                    head: initial_head.unwrap_or(page.head),
                    entries: all_entries,
                    next_cursor: None,
                    more: false,
                });
            }
        }
    }
}

pub fn format_log_text(result: &RemoteLogResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "First-parent history for project {} at commit {}:\n\n",
        result.project,
        result.head.as_str()
    ));

    if result.entries.is_empty() {
        out.push_str("No commits found.\n");
    } else {
        for (i, entry) in result.entries.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&format!("commit {}\n", entry.address.as_str()));
            if entry.parents.len() > 1 {
                let parents_str = entry
                    .parents
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push_str(&format!("Merge: {}\n", parents_str));
            } else if let Some(parent) = entry.parents.first() {
                out.push_str(&format!("Parent: {}\n", parent.as_str()));
            }
            out.push_str(&format!("Author: {}\n", entry.author_key));
            out.push_str(&format!("Date:   {}\n", entry.authored_at_ms));
            out.push('\n');
            match &entry.message {
                engine_core::repository::log::BoundedMessage::Value(msg) => {
                    for line in msg.lines() {
                        out.push_str(&format!("    {}\n", line));
                    }
                    if msg.is_empty() {
                        out.push('\n');
                    }
                }
                engine_core::repository::log::BoundedMessage::Omitted(omitted) => {
                    out.push_str(&format!(
                        "    [omitted: {} bytes, sha256: {}]\n",
                        omitted.bytes, omitted.sha256
                    ));
                }
            }
        }
    }

    if result.more {
        if let Some(ref cursor) = result.next_cursor {
            out.push_str(&format!(
                "\nMore commits available. Next cursor: {}\n",
                cursor
            ));
        }
    }

    out.push_str(
        "\nNote: First-parent history is not an exhaustive DAG traversal or independent proof of completeness.\n",
    );
    out
}

pub fn format_log_json(result: &RemoteLogResult) -> anyhow::Result<Value> {
    let mut value = serde_json::to_value(result)?;
    if let Value::Object(ref mut map) = value {
        map.insert("first_parent_history".into(), Value::Bool(true));
        map.insert(
            "disclaimer".into(),
            Value::String(
                "First-parent history is not an exhaustive DAG traversal or independent proof of completeness.".into(),
            ),
        );
    }
    Ok(value)
}
