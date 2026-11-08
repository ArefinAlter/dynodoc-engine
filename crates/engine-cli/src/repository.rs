//! Explicit local repository commands. These never contact a remote server or
//! apply content to a native editor. Signing keys are supplied by the operator.
use anyhow::{ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Subcommand, ValueEnum};
use engine_core::{
    merge_policy::{self, MergePolicy, Registry},
    repository::{
        convergence::FileExplain,
        horizon::{
            self as horizon_record, archive as horizon_archive,
            plan::PlanOptions,
            policy::{LoadOptions, Policy, MAX_POLICY_BYTES},
            Envelope, HorizonRecord, Role, Scope as HorizonScope, Signature, MAX_ENVELOPE_BYTES,
        },
        local::{
            CompactOptions, GcApplyOptions, GcPlanOptions, LocalRepository, ObjectKey,
            ObjectPacket, StorageLimits, SCHEMA_VERSION,
        },
        log::{CommitLogEntry, FirstParentLogOptions, DEFAULT_LOG_PAGE_LIMIT},
        project_merge::SameFile,
        recovery, relocation, Commit, FileEntry, Head, SignedCommit,
    },
    shared_checkpoint::Address,
};
use engine_shared::DocumentId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, ValueEnum)]
pub enum RecoveryKind {
    CherryPick,
    Revert,
}

impl From<RecoveryKind> for recovery::Kind {
    fn from(value: RecoveryKind) -> Self {
        match value {
            RecoveryKind::CherryPick => Self::CherryPick,
            RecoveryKind::Revert => Self::Revert,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PlanFormat {
    Json,
    Text,
}

/// Opt-in same-file convergence for `merge`; omit the flag for explicit-only.
#[derive(Clone, Copy, ValueEnum)]
pub enum SameFileMerge {
    /// Merge a path edited on both sides at node/field level when that merge is
    /// clean in both orientations.
    Clean,
}

#[derive(Subcommand)]
pub enum Action {
    /// Initialize or verify the local project database.
    Init,
    /// Inspect retained encoded bytes/object/commit/branch counts and limits.
    ///
    /// `bytes_used` and the limit are logical (canonical encoded bytes);
    /// `stored_bytes` is what the rows physically hold after compression at rest.
    Storage,
    /// Compress existing object rows in place (local schema 3). Safe to repeat.
    ///
    /// New objects are compressed when written; this one-time command re-encodes
    /// objects stored by earlier releases. Addresses, quotas and exported packets
    /// do not change. Each batch is a short verified transaction: an object must
    /// hash to its address and inflate back to the same bytes before its row is
    /// replaced, and the persistent counters are checked against the batch. An
    /// interrupted run keeps every committed batch; run it again to finish. It
    /// does not shrink the database file by itself: add --vacuum for that. Needs a
    /// writable repository.
    Compact {
        /// Rows examined per transaction (1-1024).
        #[arg(long, default_value_t = 256)]
        batch: usize,
        /// Stop after about this many rows (use the printed `next` to resume).
        #[arg(long)]
        max_objects: Option<u64>,
        #[arg(long, requires = "after_address")]
        after_document: Option<uuid::Uuid>,
        #[arg(long, requires = "after_document")]
        after_address: Option<String>,
        /// Return freed pages to the filesystem afterwards (checkpoint the
        /// write-ahead log, then VACUUM); needs free disk space about the size
        /// of the database file.
        #[arg(long)]
        vacuum: bool,
        /// JSON report, or a plain-text summary of the same facts.
        #[arg(long, value_enum, default_value_t = PlanFormat::Json)]
        format: PlanFormat,
    },
    /// Local private inventory; do not publish it as a shared remote listing.
    Objects {
        #[arg(long, requires = "after_address")]
        after_document: Option<uuid::Uuid>,
        #[arg(long, requires = "after_document")]
        after_address: Option<String>,
        #[arg(long, default_value_t = 64)]
        limit: usize,
    },
    /// Export one verified object as a base64 transfer packet.
    ExportObject {
        document: uuid::Uuid,
        address: String,
    },
    /// Export selected dependency closure and object graph as a history archive.
    ArchiveExport {
        /// Head commit address to export.
        head: String,
        /// Optional base commit address for incremental export.
        #[arg(long)]
        since: Option<String>,
        /// File path for the output archive (refuses overwrite).
        #[arg(long)]
        out: PathBuf,
    },
    /// Import a verified history archive without moving any branch.
    ArchiveImport {
        /// Archive file to import.
        file: PathBuf,
        /// Expected head commit address.
        #[arg(long)]
        expect_head: String,
    },
    /// Verify an offline history archive without modifying the repository.
    ArchiveVerify {
        /// Archive file to verify.
        file: PathBuf,
        /// Expected head commit address.
        #[arg(long)]
        expect_head: String,
    },
    /// Export a local historical file as a normalized-state JSON envelope.
    ExportFile {
        /// Commit address containing the file.
        #[arg(long)]
        commit: String,
        /// Path of the file within the commit.
        #[arg(long)]
        path: String,
        /// Output file path for the normalized state (refuses overwrite).
        #[arg(long)]
        out: PathBuf,
    },
    /// Import a private staging upload JSON batch, without moving any branch.
    ImportObjects { input: PathBuf },
    /// Read-only retention plan: what no branch head or recovery source reaches.
    ///
    /// Reports unreachable commits and objects (staged, orphaned, superseded)
    /// with encoded (logical) byte totals, the physical bytes stored after
    /// compression, and what stays pinned and why. Deletes nothing.
    /// Prints a deterministic `plan_hash` that `gc --plan-hash` requires. Opens
    /// the database read-only: it never creates, upgrades or writes it.
    GcPlan {
        /// Largest pinned reasons to include (1-100).
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Unreachable commits and staged objects to list as examples (0-1000).
        #[arg(long, default_value_t = 10)]
        list: usize,
        /// Deterministic JSON, or a plain-text summary of the same facts.
        #[arg(long, value_enum, default_value_t = PlanFormat::Json)]
        format: PlanFormat,
    },
    /// Read-only horizon plan: what a history horizon under a retention policy
    /// would release (docs/HORIZON-RECORD-V1.md). Deletes, signs and writes nothing.
    ///
    /// Heads, held and policy-pinned commits, merge bases, the recent window and the
    /// recovery (v2) and same-file merge (v3) provenance they need stay; under tier
    /// `history` every other commit would become a skeleton entry, under tier
    /// `content` every commit stays and only unneeded file states are released.
    /// Prints the canonical plan JSON on stdout and a short summary on stderr
    /// (`--format text` prints only the summary). The plan hash binds the policy,
    /// the branch heads and the three horizon roots, never the example count. Opens
    /// the database read-only: it never creates, upgrades or writes it.
    HorizonPlan {
        /// Retention policy JSON (`dynodoc.retention-policy.v1`).
        #[arg(long)]
        policy: PathBuf,
        /// Released and pinned commits to list as examples (0-1000).
        #[arg(long, default_value_t = 10)]
        list: usize,
        /// Instant, in milliseconds since the epoch, that `keep_within_days` counts
        /// back from. Defaults to the current time rounded down to a UTC day, so a
        /// plan repeated on the same day is the same plan. Echoed in the plan.
        #[arg(long)]
        as_of_ms: Option<i64>,
        /// Also write the canonical plan JSON to this new file (never overwrites).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Canonical JSON plus a stderr summary, or the plain-text summary alone.
        #[arg(long, value_enum, default_value_t = PlanFormat::Json)]
        format: PlanFormat,
    },
    /// Write the horizon record for a reviewed `horizon-plan` hash, for signers to
    /// sign offline (design section 6.2). With --archive, also writes the archive
    /// of exactly the history the horizon releases and records its hash, so the
    /// release can be undone with `horizon-rehydrate`. Reads the repository only.
    HorizonDraft {
        #[arg(long)]
        policy: PathBuf,
        /// The `plan_hash` of the plan you reviewed.
        #[arg(long)]
        plan_hash: String,
        /// Same meaning and default as for `horizon-plan`; must equal the plan's.
        #[arg(long)]
        as_of_ms: Option<i64>,
        /// Declared creation time; defaults to now. Signed, never verified.
        #[arg(long)]
        created_at_ms: Option<u64>,
        /// New archive file (`dynodoc.history-archive` v1); never overwrites.
        #[arg(long)]
        archive: Option<PathBuf>,
        /// New file for the canonical record JSON; never overwrites.
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a horizon record with a local Ed25519 key, offline. Prints the record
    /// address: compare it with what the other signers saw. Does not open the
    /// repository.
    HorizonSign {
        record: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, value_enum, default_value_t = HorizonRole::Owner)]
        role: HorizonRole,
        /// New file for the signature JSON; never overwrites.
        #[arg(long)]
        out: PathBuf,
    },
    /// Apply a signed horizon: release the commits and objects the plan selects.
    ///
    /// Recomputes the plan inside one write transaction and refuses unless its hash
    /// equals --plan-hash and the record describes exactly that plan; checks the
    /// signatures against the policy's `signatures.required` and the archive the
    /// record names; deletes the released bodies and objects; checks every horizon
    /// invariant before committing. A crash or any refusal changes nothing. The
    /// first apply upgrades the repository to local schema 4, which older
    /// binaries refuse to open. Back up the database file first.
    HorizonApply {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        plan_hash: String,
        /// The record from `horizon-draft`.
        #[arg(long)]
        record: PathBuf,
        /// Signature files from `horizon-sign` (repeatable).
        #[arg(long = "signature")]
        signatures: Vec<PathBuf>,
        /// Also sign now with this key (role from --role).
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = HorizonRole::Owner)]
        role: HorizonRole,
        #[arg(long)]
        as_of_ms: Option<i64>,
        /// The archive the record names.
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Release in resumable batches of at most N deletions per transaction instead
        /// of one transaction (very large releases). Run the same command again after
        /// an interruption to resume.
        #[arg(long)]
        batch: Option<u64>,
    },
    /// Every stored horizon with its record, signatures and policy.
    HorizonShow,
    /// Check every horizon invariant (H1 to H9) without changing anything; exits
    /// non-zero on the first violation. Never needs a released body.
    HorizonVerify,
    /// Restore what horizon --sequence released from its archive. The horizon stays
    /// in the chain, marked rehydrated.
    HorizonRehydrate {
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        archive: PathBuf,
    },
    /// Check an archive offline against its signed horizon envelope (the
    /// `horizon-show` record and signatures, or a server's envelope): header, every
    /// commit signature and address, every object hash, trailer, hash and counts.
    /// With --required, also checks that many distinct signatures. Does not open
    /// the repository.
    HorizonArchiveVerify {
        #[arg(long)]
        archive: PathBuf,
        /// Canonical envelope JSON `{"horizon":..., "signatures":[...]}`.
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long)]
        required: Option<u32>,
        /// Local (owner and device keys) or shared (owner and authority keys).
        #[arg(long)]
        shared: bool,
    },
    /// Delete the staged objects of a reviewed gc-plan; nothing else.
    ///
    /// Recomputes the plan inside one write transaction and refuses unless its
    /// hash equals --plan-hash (a branch moved or objects changed since the plan).
    /// Deletes only stored objects that no stored commit references. Never deletes
    /// commits, signatures, branch refs or any object a commit or recovery
    /// source reaches. Repeating an applied hash changes nothing. --vacuum then
    /// truncates the write-ahead log and runs VACUUM, which needs free disk space
    /// about the size of the database file.
    Gc {
        /// The `plan_hash` printed by `gc-plan` for the state you reviewed.
        #[arg(long)]
        plan_hash: String,
        /// Return freed pages to the filesystem after the deletion commits.
        #[arg(long)]
        vacuum: bool,
        /// JSON report, or a plain-text summary of the same facts.
        #[arg(long, value_enum, default_value_t = PlanFormat::Json)]
        format: PlanFormat,
    },
    /// Explicitly set persistent capacity; never deletes retained history.
    StorageLimits {
        #[arg(long)]
        bytes: i64,
        #[arg(long)]
        objects: i64,
        #[arg(long)]
        commits: i64,
        #[arg(long)]
        branches: i64,
    },
    /// Store a DocumentState JSON graph; returns its typed root without publishing.
    StoreState {
        document: uuid::Uuid,
        input: PathBuf,
    },
    /// Reconstruct an old or current state root as JSON.
    ReadState { document: uuid::Uuid, root: String },
    /// Sign and store a Commit JSON manifest with an existing Ed25519 PKCS#8 key.
    Commit { manifest: PathBuf, key: PathBuf },
    /// Verify/import a signed commit after its parents and objects are available.
    ImportCommit { input: PathBuf },
    /// Print a verified signed commit for review or transfer.
    Show { commit: String },
    /// Retrieve a bounded page or full chain of first-parent commit history from the local repository.
    Log {
        /// Starting commit address.
        commit: String,
        /// Page limit (1..=50, default 20).
        #[arg(long)]
        limit: Option<usize>,
        /// Continuation cursor (the next first-parent commit address to continue from).
        #[arg(long)]
        cursor: Option<String>,
        /// Retrieve all remaining first-parent commits across pages under limits.
        #[arg(long)]
        all: bool,
        /// Format output as stable JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Read one project branch. Missing branches print null.
    Head { branch: String },
    /// Publish a project commit using an exact expected address AND generation.
    SetHead {
        branch: String,
        commit: String,
        #[arg(long, requires = "expected_generation")]
        expected: Option<String>,
        #[arg(long, requires = "expected")]
        expected_generation: Option<i64>,
    },
    /// Return all best common ancestors of two commits.
    MergeBases { left: String, right: String },
    /// Compare three stored project commits without changing a branch or file.
    ///
    /// Paths edited on both sides stay whole-file conflicts. When both sides keep
    /// the same document, `same_file_convergence` also reports a dry-run
    /// node/field merge: clean or not, the address it would have, and conflicts.
    /// With --explain, `same_file_explain` also says, for each such path, which
    /// rule and strategy of the merge policy decided each field and why (JSON and
    /// readable text), and which invariants the merged state breaks. Nothing is
    /// stored or signed.
    Compare {
        base: String,
        left: String,
        right: String,
        /// Explain how the merge policy decides each same-document conflicting path.
        #[arg(long)]
        explain: bool,
        /// A `dynodoc.merge-policy.v1` JSON file to explain with, instead of the
        /// built-in `dynodoc.default.v1`. `merge --project-merge clean` records the
        /// policy it used in a v4 commit; `merge` without it uses the default.
        #[arg(long, requires = "explain")]
        merge_policy: Option<PathBuf>,
        /// Also plan by document identity (`plan_v2`): renames that follow edits,
        /// documents that need a node merge, project conflicts with their class and
        /// whether they can ever be automatic, and path portability warnings.
        #[arg(long)]
        project_constraints: bool,
    },
    /// Sign/store a two-parent merge of LEFT (first parent) and RIGHT.
    ///
    /// The base is the unique best common ancestor; criss-cross and disconnected
    /// histories are refused. Independent changes combine as in `compare`; every
    /// conflicting path needs an explicit choice in --resolutions (FileEntry, or
    /// null to delete). With --same-file-merge clean, a path edited on both sides
    /// that keeps one document identity is merged node by node and field by field
    /// when that is clean in both orientations: the merged state is stored first
    /// and recorded in the signed commit (format v3). Paths with node or field
    /// conflicts still need an explicit choice. Publish separately with set-head.
    /// With --explain, `explain` lists how the default merge policy decided each
    /// path merged this way, as `compare --explain` does; it is printed only when
    /// the merge succeeds.
    Merge {
        left: String,
        right: String,
        /// Merge clean same-file edits automatically (off when omitted).
        #[arg(long, value_enum)]
        same_file_merge: Option<SameFileMerge>,
        /// JSON object mapping each remaining conflict path to FileEntry or null.
        #[arg(long)]
        resolutions: Option<PathBuf>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        message: String,
        #[arg(long)]
        authored_at_ms: i64,
        /// Explain how each automatically merged path was decided.
        #[arg(long)]
        explain: bool,
        /// Merge by document identity (commit format v4): renames follow edits,
        /// edits follow moves, splits and joins, project constraints, and every
        /// automatic decision recorded with the merge policy. Conflicts need a
        /// choice in --choices (resolution file v2); a rejected merge stores nothing.
        #[arg(long, value_enum, conflicts_with_all = ["same_file_merge", "resolutions"])]
        project_merge: Option<SameFileMerge>,
        /// The `dynodoc.merge-policy.v1` file a project merge decides under
        /// (default `dynodoc.default.v1`); its canonical form is signed into the commit.
        #[arg(long, requires = "project_merge")]
        merge_policy: Option<PathBuf>,
        /// Resolution file v2: `{"version":2,"choices":[{"conflict":ID,"take":"left|right|delete"}]}`.
        #[arg(long, requires = "project_merge")]
        choices: Option<PathBuf>,
    },
    /// Move (or with --copy, copy) node subtrees from one document to another, as a
    /// signed one-parent v4 commit on ONTO with derived node ids. Publish with set-head.
    Relocate {
        /// DOCUMENT_UUID:NODE[,NODE...]
        #[arg(long)]
        from: String,
        /// DOCUMENT_UUID:PARENT_NODE:POSITION
        #[arg(long)]
        to: String,
        #[arg(long)]
        copy: bool,
        #[arg(long)]
        onto: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        message: String,
        #[arg(long)]
        authored_at_ms: i64,
    },
    /// Split node subtrees of DOCUMENT into a new document at NEW_PATH (v4 commit).
    Split {
        #[arg(long)]
        document: String,
        /// NODE[,NODE...]: subtree roots that move to the new document.
        #[arg(long)]
        nodes: String,
        #[arg(long)]
        new_path: String,
        /// The new document's UUID (a random one when omitted).
        #[arg(long)]
        new_document: Option<String>,
        #[arg(long, default_value = "a0")]
        position: String,
        #[arg(long)]
        onto: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        message: String,
        #[arg(long)]
        authored_at_ms: i64,
    },
    /// Join document FROM into INTO under PARENT; FROM leaves the project (v4 commit).
    Join {
        #[arg(long)]
        from: String,
        /// DOCUMENT_UUID:PARENT_NODE, or DOCUMENT_UUID:PARENT_NODE:POSITION
        #[arg(long)]
        into: String,
        #[arg(long)]
        onto: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        message: String,
        #[arg(long)]
        authored_at_ms: i64,
    },
    /// The relocation history of NODE in DOCUMENT, following first parents from HEAD.
    Lineage {
        head: String,
        document: String,
        node: String,
    },
    /// Re-run the recorded strategy of a stored merge commit's same-file records.
    /// With --explain, also print how the default merge policy decides each.
    VerifyMerge {
        commit: String,
        #[arg(long)]
        explain: bool,
    },
    /// Preview a source commit's changes (or inverse) on an exact current commit.
    RecoveryPlan {
        source: String,
        onto: String,
        #[arg(long, value_enum)]
        kind: RecoveryKind,
        /// Required for a merge source; must name one of its parents.
        #[arg(long)]
        mainline: Option<String>,
    },
    /// Sign/store a reviewed recovery commit. Publish separately with set-head.
    Recover {
        source: String,
        onto: String,
        #[arg(long, value_enum)]
        kind: RecoveryKind,
        #[arg(long)]
        mainline: Option<String>,
        /// JSON object mapping EVERY conflict path to FileEntry or null (delete).
        #[arg(long)]
        resolutions: Option<PathBuf>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        message: String,
        #[arg(long)]
        authored_at_ms: i64,
    },
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, limit: usize) -> anyhow::Result<T> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "input exceeds the local command's byte limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferBatch {
    document: uuid::Uuid,
    objects: Vec<TransferObject>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferObject {
    address: Address,
    bytes: String,
}

/// The merge policy to explain with: the file given, or the built-in default.
pub(crate) fn load_policy(path: Option<&Path>) -> anyhow::Result<MergePolicy> {
    let Some(path) = path else {
        return Ok(merge_policy::default::policy().clone());
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| {
            f.take(merge_policy::policy::MAX_INPUT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .with_context(|| format!("reading merge policy {}", path.display()))?;
    MergePolicy::from_json(&bytes, &Registry::builtin())
        .with_context(|| format!("merge policy {}", path.display()))
}

/// The `explain` report: the policy and the account of each path.
fn explain_value(
    policy: &MergePolicy,
    files: Vec<FileExplain>,
) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "policy": {"id": policy.id, "hash": policy.hash_hex()},
        "files": serde_json::to_value(files)?,
    }))
}

#[cfg(test)]
async fn compare_value(
    repo: &LocalRepository,
    base: Address,
    left: Address,
    right: Address,
) -> anyhow::Result<serde_json::Value> {
    compare_explained(repo, base, left, right, None).await
}

/// Project comparison: unique-base check, path-level plan and, only when a
/// conflicting path keeps one document identity, the report-only same-file merge.
/// With a policy, the same paths are also explained under it.
async fn compare_explained(
    repo: &LocalRepository,
    base: Address,
    left: Address,
    right: Address,
    explain: Option<&MergePolicy>,
) -> anyhow::Result<serde_json::Value> {
    let base = repo.commit(&base).await?;
    let left = repo.commit(&left).await?;
    let right = repo.commit(&right).await?;
    let bases = repo.merge_bases(&left.verify()?, &right.verify()?).await?;
    anyhow::ensure!(bases.len() == 1 && bases[0] == base.verify()?,
        "comparison requires the unique best common ancestor; resolve disconnected or criss-cross history explicitly");
    let plan = engine_core::repository::compare::plan(&base.commit, &left.commit, &right.commit)?;
    let mut output = serde_json::to_value(&plan)?;
    if let Some(report) = repo.same_file_convergence(&plan).await? {
        output["same_file_convergence"] = serde_json::to_value(report)?;
    }
    if let Some(policy) = explain {
        let files = repo.explain_same_file(&plan, policy).await?;
        output["same_file_explain"] = explain_value(policy, files)?;
    }
    Ok(output)
}

struct MergeArgs {
    left: Address,
    right: Address,
    same_file: SameFile,
    resolutions: BTreeMap<String, Option<FileEntry>>,
    message: String,
    authored_at_ms: i64,
    explain: bool,
}

/// Prepare, sign and store one merge. Nothing is stored while a conflict is open.
async fn merge_value(
    repo: &LocalRepository,
    args: MergeArgs,
    key: &dyn engine_core::repository::Signer,
) -> anyhow::Result<serde_json::Value> {
    let merge = repo
        .prepare_merge(
            &args.left,
            &args.right,
            args.same_file,
            &args.resolutions,
            args.authored_at_ms,
            args.message,
        )
        .await?;
    let Some(commit) = merge.commit else {
        let hint = if args.same_file == SameFile::Off {
            " (or use --same-file-merge clean for edits to one document that merge cleanly)"
        } else {
            ""
        };
        anyhow::bail!(
            "{} conflicting path(s) need an explicit resolution in --resolutions: {}{hint}",
            merge.unresolved.len(),
            merge.unresolved.join(", ")
        );
    };
    let explain = if args.explain {
        let policy = merge_policy::default::policy();
        Some(explain_value(
            policy,
            repo.explain_resolutions(&merge.applied, policy).await?,
        )?)
    } else {
        None
    };
    let signed = SignedCommit::sign(commit, key)?;
    let address = repo.import_commit(&signed).await?;
    let mut output = serde_json::json!({
        "commit": address,
        "version": signed.commit.version,
        "parents": signed.commit.parents,
        "base": merge.base,
        "same_file_resolutions": signed.commit.same_file_resolutions,
        "explicit_resolutions": merge.explicit,
    });
    if let Some(explain) = explain {
        output["explain"] = explain;
    }
    Ok(output)
}

fn document_id(text: &str) -> anyhow::Result<DocumentId> {
    Ok(DocumentId(
        uuid::Uuid::parse_str(text).context("a document is named by its UUID")?,
    ))
}

fn node_list(text: &str) -> anyhow::Result<Vec<engine_shared::NodeId>> {
    let nodes: Vec<_> = text
        .split(',')
        .filter(|n| !n.is_empty())
        .map(|n| engine_shared::NodeId(n.into()))
        .collect();
    anyhow::ensure!(!nodes.is_empty(), "name at least one node");
    Ok(nodes)
}

/// The single live root node of `document` in commit `onto`.
async fn root_of(
    repo: &LocalRepository,
    onto: &Address,
    document: DocumentId,
) -> anyhow::Result<engine_shared::NodeId> {
    let commit = repo.commit(onto).await?.commit;
    let entry = commit
        .files
        .values()
        .find(|f| f.document == document)
        .context("the document is not in ONTO")?;
    let state = repo.read_state(document, &entry.state).await?;
    let roots: Vec<_> = state
        .nodes
        .values()
        .filter(|n| !n.deleted && n.parent_id.is_none())
        .collect();
    match roots.as_slice() {
        [root] => Ok(root.id.clone()),
        _ => anyhow::bail!("the document must have exactly one root node"),
    }
}

/// Build, sign and store one relocation commit (v4, one parent).
async fn relocate_value(
    repo: &LocalRepository,
    onto: &Address,
    spec: relocation::Spec,
    new_path: Option<String>,
    (authored_at_ms, message): (i64, String),
    key: &dyn engine_core::repository::Signer,
) -> anyhow::Result<serde_json::Value> {
    let paths = new_path
        .map(|p| BTreeMap::from([(spec.to.document.0, p)]))
        .unwrap_or_default();
    let commit = repo
        .relocate(onto, &[spec], &paths, authored_at_ms, message)
        .await?;
    let signed = SignedCommit::sign(commit, key)?;
    let address = repo.import_commit(&signed).await?;
    Ok(serde_json::json!({
        "commit": address,
        "version": signed.commit.version,
        "parents": signed.commit.parents,
        "relocations": signed.commit.relocations,
    }))
}

/// Prepare, sign and store a v4 project merge; nothing is stored on a conflict.
async fn project_merge_value(
    repo: &LocalRepository,
    (left, right): (Address, Address),
    policy: &MergePolicy,
    choices: &engine_core::repository::project::ResolutionFile,
    (authored_at_ms, message): (i64, String),
    key: &dyn engine_core::repository::Signer,
) -> anyhow::Result<serde_json::Value> {
    let merge = repo
        .prepare_project_merge(&left, &right, policy, choices, authored_at_ms, message)
        .await?;
    let Some(commit) = merge.commit else {
        let list: Vec<String> = merge
            .report
            .conflicts
            .iter()
            .map(|c| format!("{} ({:?}: {})", c.id, c.auto, c.detail))
            .collect();
        anyhow::bail!(
            "{} project conflict(s) need a choice in --choices: {}",
            list.len(),
            list.join("; ")
        );
    };
    let signed = SignedCommit::sign(commit, key)?;
    let address = repo.import_commit(&signed).await?;
    Ok(serde_json::json!({
        "commit": address,
        "version": signed.commit.version,
        "parents": signed.commit.parents,
        "base": merge.base,
        "project_resolutions": signed.commit.project_resolutions,
        "report": merge.report,
    }))
}

/// A retention policy file, parsed and validated; every problem is listed in the error.
fn load_retention_policy(path: &Path) -> anyhow::Result<Policy> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(MAX_POLICY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Policy::load(&bytes, LoadOptions::default())
        .map_err(|errors| anyhow::anyhow!("invalid retention policy {}:\n{errors}", path.display()))
}

/// The text `horizon-plan` prints on stdout; the other rendering goes to stderr.
async fn horizon_plan(
    repo: &LocalRepository,
    policy: &Path,
    list: usize,
    as_of_ms: Option<i64>,
    out: Option<PathBuf>,
    format: PlanFormat,
) -> anyhow::Result<String> {
    let policy = load_retention_policy(policy)?;
    // A time rule needs an instant; the plan carries it, never an ambient clock.
    let as_of_ms = match (policy.window.keep_within_days, as_of_ms) {
        (Some(_), None) => Some(today_start_ms()?),
        (_, given) => given,
    };
    let plan = repo
        .horizon_plan(&policy, &PlanOptions { as_of_ms, list })
        .await?;
    let canonical = String::from_utf8(plan.canonical_bytes()?)?;
    if let Some(out) = out {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out)
            .with_context(|| format!("creating {}", out.display()))?
            .write_all(canonical.as_bytes())?;
    }
    Ok(match format {
        PlanFormat::Json => {
            eprint!("{}", plan.summary());
            format!(
                "{canonical}
"
            )
        }
        PlanFormat::Text => plan.summary(),
    })
}

/// The current time in milliseconds since the epoch, rounded down to a UTC day.
fn today_start_ms() -> anyhow::Result<i64> {
    const DAY_MS: i64 = 86_400_000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before 1970")?;
    Ok(now.as_millis() as i64 / DAY_MS * DAY_MS)
}

/// Who a local horizon signature stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum HorizonRole {
    Owner,
    Device,
}

impl From<HorizonRole> for Role {
    fn from(role: HorizonRole) -> Self {
        match role {
            HorizonRole::Owner => Role::Owner,
            HorizonRole::Device => Role::Device,
        }
    }
}

fn read_capped(path: &Path, cap: usize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= cap, "{} is too large", path.display());
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn horizon_as_of(policy: &Policy, given: Option<i64>) -> anyhow::Result<Option<i64>> {
    Ok(match (policy.window.keep_within_days, given) {
        (Some(_), None) => Some(today_start_ms()?),
        (_, given) => given,
    })
}

pub async fn run(path: PathBuf, project: uuid::Uuid, action: Action) -> anyhow::Result<()> {
    let address = |s: String| Address::try_from(s);
    let mut text = None;
    let mut vacuum_failure = None;

    let (output, repo) = match action {
        Action::HorizonSign {
            record,
            key,
            role,
            out,
        } => {
            let record = HorizonRecord::from_bytes(&read_capped(
                &record,
                horizon_record::MAX_RECORD_BYTES,
            )?)?;
            ensure!(
                record.project == project,
                "the record belongs to another project"
            );
            let signature =
                horizon_record::sign(&record, role.into(), &crate::signing::load(&key)?)?;
            write_new(&out, &serde_json::to_vec(&signature)?)?;
            (
                serde_json::json!({"record":record.address()?,"sequence":record.sequence,"role":signature.role,"key":signature.key,"out":out.display().to_string()}),
                None,
            )
        }
        Action::HorizonArchiveVerify {
            archive,
            envelope,
            required,
            shared,
        } => {
            let envelope = Envelope::from_bytes(&read_capped(&envelope, MAX_ENVELOPE_BYTES)?)?;
            ensure!(
                envelope.horizon.project == project,
                "the envelope belongs to another project"
            );
            let found = horizon_archive::verify(&archive, &envelope)?;
            if let Some(required) = required {
                let scope = if shared {
                    HorizonScope::Shared
                } else {
                    HorizonScope::Local
                };
                envelope.verify(scope, required)?;
            }
            (
                serde_json::json!({"record":envelope.horizon.address()?,"sequence":envelope.horizon.sequence,"archive":found,"signatures_checked":required.is_some()}),
                None,
            )
        }
        Action::ArchiveVerify { file, expect_head } => {
            let expect_head_addr = address(expect_head)?;
            anyhow::ensure!(
                file.is_file(),
                "archive file not found at {}",
                file.display()
            );

            let file_handle = std::fs::File::open(&file)
                .with_context(|| format!("failed to open archive at {}", file.display()))?;

            let summary = engine_core::repository::archive::verify_archive(
                file_handle,
                engine_core::repository::archive::ArchiveLimits::default(),
                Some(&expect_head_addr),
                Some(DocumentId(project)),
            )
            .await
            .map_err(|e| anyhow::anyhow!("archive verification failed: {e}"))?;

            let out = serde_json::json!({
                "file": file.display().to_string(),
                "head": summary.head,
                "project": summary.project.0,
                "objects": summary.objects,
                "commits": summary.commits,
                "bytes_before_footer": summary.bytes_before_footer,
                "total_bytes": summary.total_bytes,
                "sha256": summary.sha256,
            });
            (out, None)
        }
        Action::ArchiveImport { file, expect_head } => {
            let expect_head_addr = address(expect_head)?;
            anyhow::ensure!(
                file.is_file(),
                "archive file not found at {}",
                file.display()
            );

            let file_handle = std::fs::File::open(&file)
                .with_context(|| format!("failed to open archive at {}", file.display()))?;

            let staged = engine_core::repository::archive::validate_and_stage_archive(
                file_handle,
                engine_core::repository::archive::ArchiveLimits::default(),
                Some(&expect_head_addr),
                Some(DocumentId(project)),
            )
            .await
            .map_err(|e| anyhow::anyhow!("archive validation failed: {e}"))?;

            let repo = LocalRepository::open(&path, project).await?;

            let summary = engine_core::repository::archive::import_archive(&repo, &staged)
                .await
                .map_err(|e| anyhow::anyhow!("archive import failed: {e}"))?;

            let out = serde_json::json!({
                "file": file.display().to_string(),
                "head": summary.head,
                "objects_imported": summary.objects_imported,
                "commits_imported": summary.commits_imported,
                "total_objects": summary.total_objects,
                "total_commits": summary.total_commits,
            });
            (out, Some(repo))
        }
        other_action => {
            // The retention, horizon plans, archive export, export-file and log must not create, upgrade or write the database.
            let repo = if matches!(
                other_action,
                Action::GcPlan { .. }
                    | Action::HorizonPlan { .. }
                    | Action::HorizonDraft { .. }
                    | Action::HorizonShow
                    | Action::HorizonVerify
                    | Action::ArchiveExport { .. }
                    | Action::ExportFile { .. }
                    | Action::Log { .. }
            ) {
                LocalRepository::open_read_only(&path, project).await?
            } else {
                // A destructive command never creates the database it would collect.
                if matches!(
                    other_action,
                    Action::Gc { .. }
                        | Action::HorizonApply { .. }
                        | Action::HorizonRehydrate { .. }
                ) {
                    anyhow::ensure!(
                        path.is_file(),
                        "no repository database at {}",
                        path.display()
                    );
                }
                LocalRepository::open(&path, project).await?
            };
            let out = match other_action {
                Action::ArchiveVerify { .. }
                | Action::ArchiveImport { .. }
                | Action::HorizonSign { .. }
                | Action::HorizonArchiveVerify { .. } => unreachable!(),
                Action::HorizonDraft {
                    policy,
                    plan_hash,
                    as_of_ms,
                    created_at_ms,
                    archive,
                    out,
                } => {
                    let policy = load_retention_policy(&policy)?;
                    let as_of_ms = horizon_as_of(&policy, as_of_ms)?;
                    let created_at_ms = match created_at_ms {
                        Some(ms) => ms,
                        None => std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_millis() as u64,
                    };
                    let record = repo
                        .horizon_draft(
                            &policy,
                            &PlanOptions { as_of_ms, list: 0 },
                            &plan_hash,
                            created_at_ms,
                            archive.as_deref(),
                        )
                        .await?;
                    write_new(&out, &record.bytes()?)?;
                    serde_json::json!({"record":record.address()?,"sequence":record.sequence,"counts":record.counts,"archive":record.archive,"out":out.display().to_string(),"instruction":"Each signer runs horizon-sign on this file; then horizon-apply with every signature."})
                }
                Action::HorizonApply {
                    policy,
                    plan_hash,
                    record,
                    signatures,
                    key,
                    role,
                    as_of_ms,
                    archive,
                    batch,
                } => {
                    let policy = load_retention_policy(&policy)?;
                    let as_of_ms = horizon_as_of(&policy, as_of_ms)?;
                    let record = HorizonRecord::from_bytes(&read_capped(
                        &record,
                        horizon_record::MAX_RECORD_BYTES,
                    )?)?;
                    let mut collected = Vec::new();
                    for file in &signatures {
                        let signature: Signature =
                            serde_json::from_slice(&read_capped(file, 4096)?)
                                .with_context(|| format!("reading signature {}", file.display()))?;
                        collected.push(signature);
                    }
                    if let Some(key) = key {
                        collected.push(horizon_record::sign(
                            &record,
                            role.into(),
                            &crate::signing::load(&key)?,
                        )?);
                    }
                    let envelope = Envelope::assemble(record, collected)?;
                    let options = PlanOptions { as_of_ms, list: 0 };
                    let report = match batch {
                        None => {
                            repo.horizon_apply(
                                &envelope,
                                &policy,
                                &options,
                                &plan_hash,
                                archive.as_deref(),
                            )
                            .await?
                        }
                        Some(batch) => {
                            repo.horizon_apply_batched(
                                &envelope,
                                &policy,
                                &options,
                                &plan_hash,
                                archive.as_deref(),
                                batch,
                            )
                            .await?
                        }
                    };
                    serde_json::to_value(report)?
                }
                Action::HorizonShow => serde_json::to_value(repo.horizons().await?)?,
                Action::HorizonVerify => serde_json::to_value(repo.horizon_verify().await?)?,
                Action::HorizonRehydrate { sequence, archive } => {
                    serde_json::to_value(repo.horizon_rehydrate(sequence, &archive).await?)?
                }
                Action::Init => {
                    serde_json::json!({"project":project,"local_schema":SCHEMA_VERSION})
                }
                Action::Storage => serde_json::to_value(repo.storage_usage().await?)?,
                Action::Compact {
                    batch,
                    max_objects,
                    after_document,
                    after_address,
                    vacuum,
                    format,
                } => {
                    let after = match (after_document, after_address) {
                        (Some(document), Some(value)) => Some(ObjectKey {
                            document: DocumentId(document),
                            address: address(value)?,
                        }),
                        _ => None,
                    };
                    let report = repo
                        .compact(CompactOptions {
                            batch_objects: batch,
                            max_objects,
                            after,
                            vacuum,
                        })
                        .await?;
                    vacuum_failure = report
                        .vacuum
                        .as_ref()
                        .and_then(|v| v.error.clone())
                        .map(|e| format!("compaction committed but VACUUM failed: {e}"));
                    match format {
                        PlanFormat::Json => serde_json::to_value(&report)?,
                        PlanFormat::Text => {
                            text = Some(report.summary());
                            serde_json::Value::Null
                        }
                    }
                }
                Action::Objects {
                    after_document,
                    after_address,
                    limit,
                } => {
                    let after = match (after_document, after_address) {
                        (Some(document), Some(value)) => Some(ObjectKey {
                            document: DocumentId(document),
                            address: address(value)?,
                        }),
                        _ => None,
                    };
                    let keys = repo.inventory(after.as_ref(), limit).await?;
                    serde_json::json!({"objects":keys.iter().map(|k|serde_json::json!({"document":k.document,"address":k.address})).collect::<Vec<_>>()})
                }
                Action::ExportObject {
                    document,
                    address: value,
                } => {
                    let packet = repo
                        .object(&ObjectKey {
                            document: DocumentId(document),
                            address: address(value)?,
                        })
                        .await?;
                    serde_json::json!({"address":packet.key.address,"bytes":STANDARD.encode(packet.bytes)})
                }
                Action::ArchiveExport { head, since, out } => {
                    let head_addr = address(head)?;
                    let since_addr = since.map(address).transpose()?;
                    anyhow::ensure!(
                        !out.exists(),
                        "output file {} already exists; refusing overwrite",
                        out.display()
                    );

                    let mut file = engine_core::repository::private_fs::create_private_file(&out)
                        .with_context(|| {
                        format!("creating output archive at {}", out.display())
                    })?;

                    let guard =
                        engine_core::repository::private_fs::AutoRemoveFile::new(out.clone());

                    let summary = engine_core::repository::archive::export_archive_incremental(
                        &repo,
                        &head_addr,
                        since_addr.as_ref(),
                        std::io::BufWriter::new(&mut file),
                        engine_core::repository::archive::ArchiveLimits::default(),
                    )
                    .await
                    .context("archive export failed")?;
                    // Report success only once the complete archive is on disk.
                    file.sync_all()
                        .with_context(|| format!("syncing output archive {}", out.display()))?;
                    drop(file);

                    guard.commit();

                    let mut res = serde_json::json!({
                        "out": out.display().to_string(),
                        "head": summary.head,
                        "objects": summary.objects,
                        "commits": summary.commits,
                        "bytes": summary.total_bytes,
                        "bytes_before_footer": summary.bytes_before_footer,
                        "sha256": summary.sha256,
                    });
                    if let Some(since) = &summary.since {
                        res["since"] = serde_json::json!(since);
                    }
                    res
                }
                Action::ExportFile {
                    commit,
                    path: file_path,
                    out,
                } => {
                    let commit_addr = address(commit)?;
                    anyhow::ensure!(
                        !out.exists(),
                        "output file {} already exists; refusing overwrite",
                        out.display()
                    );

                    let signed = repo.commit(&commit_addr).await.with_context(|| {
                        format!("commit {} not found in repository", commit_addr.as_str())
                    })?;

                    let verified_addr = signed.verify().with_context(|| {
                        format!(
                            "commit {} signature verification failed",
                            commit_addr.as_str()
                        )
                    })?;
                    anyhow::ensure!(
                        verified_addr == commit_addr,
                        "commit address mismatch: expected {}, verified {}",
                        commit_addr.as_str(),
                        verified_addr.as_str()
                    );

                    anyhow::ensure!(
                        signed.commit.project == project,
                        "commit project {} does not match repository project {project}",
                        signed.commit.project
                    );

                    let file_entry =
                        signed
                            .commit
                            .files
                            .get(&file_path)
                            .cloned()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "path {file_path:?} not found in commit {}",
                                    commit_addr.as_str()
                                )
                            })?;

                    let state = repo
                        .read_state(file_entry.document, &file_entry.state)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to reconstruct state root {} for document {}",
                                file_entry.state.as_str(),
                                file_entry.document.0
                            )
                        })?;

                    let envelope = engine_core::repository::state_export::StateExportEnvelope::new(
                        file_path.clone(),
                        signed,
                        state,
                    );

                    envelope.write_to_path(&out)?;

                    serde_json::json!({
                        "out": out.display().to_string(),
                        "commit": commit_addr,
                        "path": file_path,
                        "document": file_entry.document.0,
                        "state_root": file_entry.state,
                        "format": engine_core::repository::state_export::STATE_EXPORT_FORMAT,
                        "version": engine_core::repository::state_export::STATE_EXPORT_VERSION,
                    })
                }
                Action::ImportObjects { input } => {
                    let batch: TransferBatch = read_json(&input, 1_500_000)?;
                    anyhow::ensure!(batch.objects.len() <= 64, "import at most 64 objects");
                    let mut bytes = 0usize;
                    let packets = batch
                        .objects
                        .into_iter()
                        .map(|object| {
                            let decoded = STANDARD.decode(object.bytes)?;
                            bytes += decoded.len();
                            anyhow::ensure!(bytes <= 1024 * 1024, "import at most 1 MiB");
                            Ok(ObjectPacket {
                                key: ObjectKey {
                                    document: DocumentId(batch.document),
                                    address: object.address,
                                },
                                bytes: decoded,
                            })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    serde_json::json!({"new_objects":repo.import_objects(&packets).await?,"published":false})
                }
                Action::GcPlan { top, list, format } => {
                    let plan = repo
                        .gc_plan(GcPlanOptions {
                            top_reasons: top,
                            list,
                        })
                        .await?;
                    match format {
                        PlanFormat::Json => serde_json::to_value(&plan)?,
                        PlanFormat::Text => {
                            text = Some(plan.summary());
                            serde_json::Value::Null
                        }
                    }
                }
                Action::HorizonPlan {
                    policy,
                    list,
                    as_of_ms,
                    out,
                    format,
                } => {
                    text = Some(horizon_plan(&repo, &policy, list, as_of_ms, out, format).await?);
                    serde_json::Value::Null
                }
                Action::Gc {
                    plan_hash,
                    vacuum,
                    format,
                } => {
                    let report = repo.gc_apply(&plan_hash, GcApplyOptions { vacuum }).await?;
                    // A failed shrink does not hide the deletion: print it, then fail.
                    vacuum_failure = report
                        .vacuum
                        .as_ref()
                        .and_then(|v| v.error.clone())
                        .map(|e| format!("deletion committed but VACUUM failed: {e}"));
                    match format {
                        PlanFormat::Json => serde_json::to_value(&report)?,
                        PlanFormat::Text => {
                            text = Some(report.summary());
                            serde_json::Value::Null
                        }
                    }
                }
                Action::StorageLimits {
                    bytes,
                    objects,
                    commits,
                    branches,
                } => serde_json::to_value(
                    repo.set_storage_limits(StorageLimits {
                        bytes,
                        objects,
                        commits,
                        branches,
                    })
                    .await?,
                )?,
                Action::StoreState { document, input } => {
                    let state = read_json(&input, 16 * 1024 * 1024)?;
                    let (root, stats) = repo.write_state(DocumentId(document), &state).await?;
                    serde_json::json!({"state":root,"new_objects":stats.new_objects,"new_bytes":stats.new_bytes})
                }
                Action::ReadState { document, root } => serde_json::to_value(
                    repo.read_state(DocumentId(document), &address(root)?)
                        .await?,
                )?,
                Action::Commit { manifest, key } => {
                    let commit: Commit =
                        read_json(&manifest, engine_core::repository::MAX_COMMIT_BYTES)?;
                    let key = crate::signing::load_signer(&key)?;
                    let signed = SignedCommit::sign(commit, &*key)?;
                    serde_json::json!({"commit":repo.import_commit(&signed).await?})
                }
                Action::ImportCommit { input } => {
                    serde_json::json!({"commit":repo.import_commit(&read_json(&input, engine_core::repository::MAX_COMMIT_BYTES + 1024)?).await?})
                }
                Action::Show { commit } => {
                    serde_json::to_value(repo.commit(&address(commit)?).await?)?
                }
                Action::Log {
                    commit,
                    limit,
                    cursor,
                    all,
                    json,
                } => {
                    let commit_addr = address(commit)?;
                    let cursor_addr = match cursor {
                        Some(c) => Some(address(c)?),
                        None => None,
                    };
                    let result = local_log(
                        &repo,
                        project,
                        &commit_addr,
                        limit,
                        cursor_addr.as_ref(),
                        all,
                    )
                    .await?;
                    if json {
                        serde_json::to_value(&format_local_log_json(&result)?)?
                    } else {
                        text = Some(format_local_log_text(&result));
                        serde_json::Value::Null
                    }
                }
                Action::Head { branch } => serde_json::to_value(repo.head(&branch).await?)?,
                Action::SetHead {
                    branch,
                    commit,
                    expected,
                    expected_generation,
                } => {
                    let expected = match (expected, expected_generation) {
                        (Some(commit), Some(generation)) => Some(Head {
                            commit: address(commit)?,
                            generation,
                        }),
                        (None, None) => None,
                        _ => anyhow::bail!(
                            "expected address and generation must be supplied together"
                        ),
                    };
                    serde_json::to_value(
                        repo.compare_and_swap(&branch, expected.as_ref(), &address(commit)?)
                            .await?,
                    )?
                }
                Action::MergeBases { left, right } => serde_json::to_value(
                    repo.merge_bases(&address(left)?, &address(right)?).await?,
                )?,
                Action::Compare {
                    base,
                    left,
                    right,
                    explain,
                    merge_policy,
                    project_constraints,
                } => {
                    let policy = explain
                        .then(|| load_policy(merge_policy.as_deref()))
                        .transpose()?;
                    let (b, l, r) = (address(base)?, address(left)?, address(right)?);
                    let mut output =
                        compare_explained(&repo, b.clone(), l.clone(), r.clone(), policy.as_ref())
                            .await?;
                    if project_constraints {
                        let plan = engine_core::repository::plan_v2::plan_v2(
                            &repo.commit(&b).await?.commit,
                            &repo.commit(&l).await?.commit,
                            &repo.commit(&r).await?.commit,
                        )?;
                        output["project_plan"] = serde_json::to_value(plan)?;
                    }
                    output
                }
                Action::Merge {
                    left,
                    right,
                    key,
                    message,
                    authored_at_ms,
                    project_merge: Some(SameFileMerge::Clean),
                    merge_policy,
                    choices,
                    ..
                } => {
                    let policy = load_policy(merge_policy.as_deref())?;
                    let choices: engine_core::repository::project::ResolutionFile = match choices {
                        Some(path) => read_json(&path, engine_core::repository::MAX_COMMIT_BYTES)?,
                        None => Default::default(),
                    };
                    let key = crate::signing::load_signer(&key)?;
                    project_merge_value(
                        &repo,
                        (address(left)?, address(right)?),
                        &policy,
                        &choices,
                        (authored_at_ms, message),
                        &*key,
                    )
                    .await?
                }
                Action::Merge {
                    left,
                    right,
                    same_file_merge,
                    resolutions,
                    key,
                    message,
                    authored_at_ms,
                    explain,
                    project_merge: None,
                    ..
                } => {
                    let resolutions = match resolutions {
                        Some(path) => read_json(&path, engine_core::repository::MAX_COMMIT_BYTES)?,
                        None => BTreeMap::new(),
                    };
                    // Load the key before anything is stored.
                    let key = crate::signing::load_signer(&key)?;
                    let args = MergeArgs {
                        left: address(left)?,
                        right: address(right)?,
                        same_file: match same_file_merge {
                            Some(SameFileMerge::Clean) => SameFile::Clean,
                            None => SameFile::Off,
                        },
                        resolutions,
                        message,
                        authored_at_ms,
                        explain,
                    };
                    merge_value(&repo, args, &*key).await?
                }
                Action::Relocate {
                    from,
                    to,
                    copy,
                    onto,
                    key,
                    message,
                    authored_at_ms,
                } => {
                    let (document, nodes) = from
                        .split_once(':')
                        .context("--from is DOCUMENT_UUID:NODE[,NODE...]")?;
                    let mut to_parts = to.splitn(3, ':');
                    let (Some(dest), Some(parent), Some(position)) =
                        (to_parts.next(), to_parts.next(), to_parts.next())
                    else {
                        anyhow::bail!("--to is DOCUMENT_UUID:PARENT_NODE:POSITION");
                    };
                    let spec = relocation::Spec {
                        kind: if copy {
                            relocation::Kind::Copy
                        } else {
                            relocation::Kind::Move
                        },
                        from: relocation::Source {
                            document: document_id(document)?,
                            roots: node_list(nodes)?,
                        },
                        to: relocation::Destination {
                            document: document_id(dest)?,
                            parent: engine_shared::NodeId(parent.into()),
                            position: position.into(),
                        },
                    };
                    let key = crate::signing::load_signer(&key)?;
                    relocate_value(
                        &repo,
                        &address(onto)?,
                        spec,
                        None,
                        (authored_at_ms, message),
                        &*key,
                    )
                    .await?
                }
                Action::Split {
                    document,
                    nodes,
                    new_path,
                    new_document,
                    position,
                    onto,
                    key,
                    message,
                    authored_at_ms,
                } => {
                    anyhow::ensure!(
                        engine_core::repository::valid_path(&new_path),
                        "--new-path is not a valid project path"
                    );
                    let onto = address(onto)?;
                    let source = document_id(&document)?;
                    let root = root_of(&repo, &onto, source).await?;
                    let new_document = match new_document {
                        Some(id) => document_id(&id)?,
                        None => DocumentId(uuid::Uuid::new_v4()),
                    };
                    let spec = relocation::Spec {
                        kind: relocation::Kind::Split,
                        from: relocation::Source {
                            document: source,
                            roots: node_list(&nodes)?,
                        },
                        to: relocation::Destination {
                            document: new_document,
                            parent: root,
                            position,
                        },
                    };
                    let key = crate::signing::load_signer(&key)?;
                    relocate_value(
                        &repo,
                        &onto,
                        spec,
                        Some(new_path),
                        (authored_at_ms, message),
                        &*key,
                    )
                    .await?
                }
                Action::Join {
                    from,
                    into,
                    onto,
                    key,
                    message,
                    authored_at_ms,
                } => {
                    let onto = address(onto)?;
                    let source = document_id(&from)?;
                    let mut parts = into.splitn(3, ':');
                    let (Some(dest), Some(parent)) = (parts.next(), parts.next()) else {
                        anyhow::bail!("--into is DOCUMENT_UUID:PARENT_NODE[:POSITION]");
                    };
                    let position = parts.next().unwrap_or("a0").to_string();
                    let root = root_of(&repo, &onto, source).await?;
                    let commit = repo.commit(&onto).await?.commit;
                    let entry = commit
                        .files
                        .values()
                        .find(|f| f.document == source)
                        .context("--from is not a document of ONTO")?;
                    let state = repo.read_state(source, &entry.state).await?;
                    let mut children: Vec<_> = state
                        .nodes
                        .values()
                        .filter(|n| !n.deleted && n.parent_id.as_ref() == Some(&root))
                        .map(|n| (n.pos.clone(), n.id.clone()))
                        .collect();
                    children.sort();
                    anyhow::ensure!(!children.is_empty(), "the document to join has no content");
                    let spec = relocation::Spec {
                        kind: relocation::Kind::Join,
                        from: relocation::Source {
                            document: source,
                            roots: children.into_iter().map(|(_, id)| id).collect(),
                        },
                        to: relocation::Destination {
                            document: document_id(dest)?,
                            parent: engine_shared::NodeId(parent.into()),
                            position,
                        },
                    };
                    let key = crate::signing::load_signer(&key)?;
                    relocate_value(&repo, &onto, spec, None, (authored_at_ms, message), &*key)
                        .await?
                }
                Action::Lineage {
                    head,
                    document,
                    node,
                } => serde_json::json!({
                    "steps": repo
                        .lineage(
                            &address(head)?,
                            document_id(&document)?,
                            &engine_shared::NodeId(node),
                        )
                        .await?
                }),
                Action::VerifyMerge { commit, explain } => {
                    let commit = address(commit)?;
                    let verified = repo.verify_same_file_resolutions(&commit).await?;
                    let project_verified = repo.verify_project_resolutions(&commit).await?;
                    let mut output = serde_json::json!({"commit":commit,"verified_same_file_resolutions":verified,"verified_project_resolutions":project_verified});
                    if explain {
                        let policy = merge_policy::default::policy();
                        let records = repo.commit(&commit).await?.commit.same_file_resolutions;
                        output["explain"] = explain_value(
                            policy,
                            repo.explain_resolutions(&records, policy).await?,
                        )?;
                    }
                    output
                }
                Action::RecoveryPlan {
                    source,
                    onto,
                    kind,
                    mainline,
                } => {
                    let mainline = mainline.map(address).transpose()?;
                    serde_json::to_value(
                        repo.plan_recovery(
                            kind.into(),
                            &address(source)?,
                            &address(onto)?,
                            mainline.as_ref(),
                        )
                        .await?,
                    )?
                }
                Action::Recover {
                    source,
                    onto,
                    kind,
                    mainline,
                    resolutions,
                    key,
                    message,
                    authored_at_ms,
                } => {
                    let mainline = mainline.map(address).transpose()?;
                    let plan = repo
                        .plan_recovery(
                            kind.into(),
                            &address(source)?,
                            &address(onto)?,
                            mainline.as_ref(),
                        )
                        .await?;
                    let resolutions = match resolutions {
                        Some(path) => read_json(&path, engine_core::repository::MAX_COMMIT_BYTES)?,
                        None => BTreeMap::new(),
                    };
                    let commit = plan.resolve(&resolutions, authored_at_ms, message)?;
                    let signed = SignedCommit::sign(commit, &*crate::signing::load_signer(&key)?)?;
                    serde_json::json!({"commit":repo.import_commit(&signed).await?,"recovery":signed.commit.recovery,"parents":signed.commit.parents})
                }
            };
            (out, Some(repo))
        }
    };
    if let Some(r) = repo {
        r.close().await;
    }
    match text {
        Some(text) => print!("{text}"),
        None => println!(
            "{}",
            serde_json::to_string_pretty(&output).context("encoding local repository result")?
        ),
    }
    match vacuum_failure {
        Some(message) => anyhow::bail!(message),
        None => Ok(()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalLogResult {
    pub project: uuid::Uuid,
    pub head: Address,
    pub entries: Vec<CommitLogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub more: bool,
}

pub async fn local_log(
    repo: &LocalRepository,
    project: uuid::Uuid,
    commit_addr: &Address,
    limit: Option<usize>,
    cursor: Option<&Address>,
    all: bool,
) -> anyhow::Result<LocalLogResult> {
    if let Some(l) = limit {
        ensure!(l > 0 && l <= 50, "limit must be between 1 and 50");
    }
    let effective_limit = limit.unwrap_or(DEFAULT_LOG_PAGE_LIMIT);

    if let Some(cursor_addr) = cursor {
        ensure!(
            cursor_addr != commit_addr,
            "cursor loop detected: continuation cursor cannot equal head"
        );
        // Validate that cursor_addr is reached from commit_addr along first parents
        let mut curr = commit_addr.clone();
        let mut found = false;
        let mut steps = 0usize;
        while steps < 65536 {
            let commit = repo.commit(&curr).await?;
            ensure!(commit.commit.project == project, "commit project mismatch");
            if let Some(first_parent) = commit.commit.parents.first() {
                if first_parent == cursor_addr {
                    found = true;
                    break;
                }
                curr = first_parent.clone();
                steps += 1;
            } else {
                break;
            }
        }
        ensure!(
            found,
            "continuation cursor is not on the first-parent chain of the specified commit"
        );
    }

    let start_addr = cursor.unwrap_or(commit_addr);

    if !all {
        let page = repo
            .first_parent_log(
                start_addr,
                FirstParentLogOptions {
                    limit: Some(effective_limit),
                },
            )
            .await?;
        return Ok(LocalLogResult {
            project,
            head: commit_addr.clone(),
            entries: page.entries,
            next_cursor: page.next_address.map(|a| a.as_str().to_string()),
            more: page.more,
        });
    }

    let mut current_addr = start_addr.clone();
    let mut all_entries = Vec::new();
    let mut seen_addresses = BTreeSet::new();
    let mut pages = 0usize;

    loop {
        let page = repo
            .first_parent_log(
                &current_addr,
                FirstParentLogOptions {
                    limit: Some(effective_limit),
                },
            )
            .await?;

        for entry in page.entries {
            ensure!(
                seen_addresses.insert(entry.address.clone()),
                "duplicate commit address encountered: {}",
                entry.address.as_str()
            );
            all_entries.push(entry);
        }
        pages += 1;

        match page.next_address {
            Some(next) => {
                ensure!(page.more, "more=false but next_address is present");
                ensure!(
                    pages < 10_000,
                    "exceeded maximum pagination limit (10000 pages)"
                );
                current_addr = next;
            }
            None => {
                ensure!(!page.more, "more=true but no next_address present");
                break;
            }
        }
    }

    Ok(LocalLogResult {
        project,
        head: commit_addr.clone(),
        entries: all_entries,
        next_cursor: None,
        more: false,
    })
}

pub fn format_local_log_text(result: &LocalLogResult) -> String {
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

pub fn format_local_log_json(result: &LocalLogResult) -> anyhow::Result<Value> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Command, FromArgMatches};
    use engine_core::{
        materializer::{DocumentState, MaterializedNode},
        repository::FileEntry,
    };
    use engine_shared::NodeId;
    use ring::signature::Ed25519KeyPair;

    fn paragraphs(edits: &[(usize, &str)]) -> DocumentState {
        let mut state = DocumentState::default();
        for i in 0..4 {
            let id = NodeId(format!("{i:026}"));
            let label = edits
                .iter()
                .find(|(index, _)| *index == i)
                .map_or(format!("paragraph {i}"), |(_, text)| (*text).to_string());
            state.nodes.insert(
                id.clone(),
                MaterializedNode {
                    id,
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: format!("p{i:06}"),
                    var_name: None,
                    deleted: false,
                    current_fields: serde_json::json!({"label": label}),
                },
            );
        }
        state
    }

    struct Fixture {
        path: PathBuf,
        project: uuid::Uuid,
        repo: LocalRepository,
    }

    async fn remove_test_database(path: &std::path::Path) -> std::io::Result<()> {
        // SQLite shutdown is awaited first. Windows scanners can briefly retain
        // a handle afterwards; retry only sharing/locking violations, boundedly.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut delay = std::time::Duration::from_millis(25);
        loop {
            match std::fs::remove_file(path) {
                Ok(()) => return Ok(()),
                Err(error)
                    if cfg!(windows)
                        && matches!(error.raw_os_error(), Some(32 | 33))
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(
                        delay.min(deadline.saturating_duration_since(tokio::time::Instant::now())),
                    )
                    .await;
                    delay = (delay * 2).min(std::time::Duration::from_millis(250));
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn database_cleanup_waits_for_a_windows_sharing_handle() {
        use std::os::windows::fs::OpenOptionsExt;
        let fixture = Fixture::new().await;
        let path = fixture.path.clone();
        fixture.repo.close().await;
        let handle = std::fs::OpenOptions::new()
            .read(true)
            // Permit readers/writers, but deliberately deny file deletion.
            .share_mode(3)
            .open(&path)
            .unwrap();
        assert_eq!(
            std::fs::remove_file(&path).unwrap_err().raw_os_error(),
            Some(32)
        );
        let release = std::thread::spawn(move || {
            // Hold it longer than the old 20 * 25 ms cleanup window.
            std::thread::sleep(std::time::Duration::from_millis(750));
            drop(handle);
        });
        let result = remove_test_database(&path).await;
        release.join().unwrap();
        result.expect("cleanup after sharing handle is released");
        assert!(!path.exists());
    }

    impl Fixture {
        async fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dynodoc-cli-repository-test-{}.sqlite",
                uuid::Uuid::new_v4()
            ));
            let project = uuid::Uuid::new_v4();
            let repo = LocalRepository::open(&path, project).await.unwrap();
            Self {
                path,
                project,
                repo,
            }
        }
        async fn with_project(project: uuid::Uuid) -> Self {
            let path = std::env::temp_dir().join(format!(
                "dynodoc-cli-repository-test-{}.sqlite",
                uuid::Uuid::new_v4()
            ));
            let repo = LocalRepository::open(&path, project).await.unwrap();
            Self {
                path,
                project,
                repo,
            }
        }
        async fn file(&self, document: DocumentId, edits: &[(usize, &str)]) -> FileEntry {
            let (state, _) = self
                .repo
                .write_state(document, &paragraphs(edits))
                .await
                .unwrap();
            FileEntry { document, state }
        }
        async fn commit(
            &self,
            parents: &[&Address],
            files: Vec<(&str, FileEntry)>,
            message: &str,
        ) -> Address {
            let commit = Commit {
                sealed: None,
                version: 1,
                project: self.project,
                parents: parents.iter().map(|a| (*a).clone()).collect(),
                files: files
                    .into_iter()
                    .map(|(path, file)| (path.to_string(), file))
                    .collect(),
                author_key: String::new(),
                authored_at_ms: 1_700_000_000_000,
                message: message.into(),
                recovery: None,
                project_resolutions: Vec::new(),
                relocations: Vec::new(),
                merge_policy: None,
                same_file_resolutions: Vec::new(),
            };
            let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
            self.repo
                .import_commit(&SignedCommit::sign(commit, &key).unwrap())
                .await
                .unwrap()
        }
        async fn finish(self) {
            self.repo.close().await;
            remove_test_database(&self.path)
                .await
                .expect("test database cleanup");
        }
    }

    #[tokio::test]
    async fn compare_output_is_unchanged_without_same_document_conflicts() {
        let f = Fixture::new().await;
        let (report, budget) = (
            DocumentId(uuid::Uuid::new_v4()),
            DocumentId(uuid::Uuid::new_v4()),
        );
        let base = f
            .commit(
                &[],
                vec![
                    ("Report.docx", f.file(report, &[]).await),
                    ("Budget.xlsx", f.file(budget, &[]).await),
                ],
                "base",
            )
            .await;
        let left = f
            .commit(
                &[&base],
                vec![
                    ("Report.docx", f.file(report, &[(0, "left")]).await),
                    ("Budget.xlsx", f.file(budget, &[]).await),
                ],
                "left",
            )
            .await;
        let right = f
            .commit(
                &[&base],
                vec![
                    ("Report.docx", f.file(report, &[]).await),
                    ("Budget.xlsx", f.file(budget, &[(1, "right")]).await),
                ],
                "right",
            )
            .await;
        let output = compare_value(&f.repo, base.clone(), left.clone(), right.clone())
            .await
            .unwrap();
        let plan = engine_core::repository::compare::plan(
            &f.repo.commit(&base).await.unwrap().commit,
            &f.repo.commit(&left).await.unwrap().commit,
            &f.repo.commit(&right).await.unwrap().commit,
        )
        .unwrap();
        // Exactly the pre-existing planner output: same bytes, no extra key.
        let expected = serde_json::to_value(&plan).unwrap();
        assert_eq!(
            serde_json::to_string_pretty(&output).unwrap(),
            serde_json::to_string_pretty(&expected).unwrap()
        );
        assert!(output.get("same_file_convergence").is_none());
        assert_eq!(output["conflicts"].as_array().unwrap().len(), 0);
        f.finish().await;
    }

    #[tokio::test]
    async fn compare_adds_a_same_file_report_without_changing_the_conflict_list() {
        let f = Fixture::new().await;
        let report = DocumentId(uuid::Uuid::new_v4());
        let base = f
            .commit(
                &[],
                vec![("Report.docx", f.file(report, &[]).await)],
                "base",
            )
            .await;
        let left = f
            .commit(
                &[&base],
                vec![("Report.docx", f.file(report, &[(0, "left")]).await)],
                "left",
            )
            .await;
        let right = f
            .commit(
                &[&base],
                vec![("Report.docx", f.file(report, &[(3, "right")]).await)],
                "right",
            )
            .await;
        let forward = compare_value(&f.repo, base.clone(), left.clone(), right.clone())
            .await
            .unwrap();
        let reverse = compare_value(&f.repo, base.clone(), right.clone(), left.clone())
            .await
            .unwrap();
        assert_eq!(forward["conflicts"].as_array().unwrap().len(), 1);
        assert!(forward["files"].as_object().unwrap().is_empty());
        let file = &forward["same_file_convergence"]["files"][0];
        assert_eq!(file["path"], "Report.docx");
        assert_eq!(file["clean"], true);
        assert!(file["merged_state"].is_string());
        assert_eq!(
            file["merged_state"],
            reverse["same_file_convergence"]["files"][0]["merged_state"]
        );
        assert_eq!(forward["same_file_convergence"]["not_examined"], 0);
        f.finish().await;
    }

    #[tokio::test]
    async fn compare_still_requires_a_unique_best_common_ancestor() {
        let f = Fixture::new().await;
        let a = f.commit(&[], vec![], "a").await;
        let b = f.commit(&[&a], vec![], "b").await;
        let c = f.commit(&[&a], vec![], "c").await;
        let d = f.commit(&[&b, &c], vec![], "d").await;
        let e = f.commit(&[&c, &b], vec![], "e").await;
        // Criss-cross: two best bases.
        let error = compare_value(&f.repo, b.clone(), d.clone(), e.clone())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unique best common ancestor"));
        // Disconnected histories have none.
        let unrelated = f.commit(&[], vec![], "unrelated").await;
        assert!(compare_value(&f.repo, a.clone(), b.clone(), unrelated)
            .await
            .is_err());
        // A unique base still compares.
        assert!(compare_value(&f.repo, a, b, c).await.is_ok());
        f.finish().await;
    }

    #[tokio::test]
    async fn gc_plan_is_read_only_and_never_creates_a_database() {
        let f = Fixture::new().await;
        let document = DocumentId(uuid::Uuid::new_v4());
        f.file(document, &[]).await;
        let (path, project) = (f.path.clone(), f.project);
        for format in [PlanFormat::Json, PlanFormat::Text] {
            run(
                path.clone(),
                project,
                Action::GcPlan {
                    top: 3,
                    list: 2,
                    format,
                },
            )
            .await
            .unwrap();
        }
        let missing = path.with_extension("missing");
        let result = run(
            missing.clone(),
            project,
            Action::GcPlan {
                top: 10,
                list: 10,
                format: PlanFormat::Json,
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!missing.exists());
        f.finish().await;
    }

    #[tokio::test]
    async fn gc_collects_only_the_reviewed_plan_and_refuses_a_stale_one() {
        let f = Fixture::new().await;
        let (kept, staged) = (
            DocumentId(uuid::Uuid::new_v4()),
            DocumentId(uuid::Uuid::new_v4()),
        );
        let file = f.file(kept, &[]).await;
        let head = f.commit(&[], vec![("Report.docx", file)], "base").await;
        f.repo.compare_and_swap("main", None, &head).await.unwrap();
        f.file(staged, &[(0, "never committed")]).await;
        let (path, project) = (f.path.clone(), f.project);
        let plan = f
            .repo
            .gc_plan(GcPlanOptions {
                top_reasons: 1,
                list: 0,
            })
            .await
            .unwrap();
        assert!(plan.unreachable.counts.objects > 0);
        let run_gc = |hash: String, vacuum: bool, format: PlanFormat| {
            run(
                path.clone(),
                project,
                Action::Gc {
                    plan_hash: hash,
                    vacuum,
                    format,
                },
            )
        };
        // A hash that is not the current plan changes nothing.
        assert!(run_gc("0".repeat(64), false, PlanFormat::Json)
            .await
            .is_err());
        // A missing database is an error and is never created by `gc`.
        let missing = path.with_extension("absent");
        assert!(run(
            missing.clone(),
            project,
            Action::Gc {
                plan_hash: plan.plan_hash.clone(),
                vacuum: false,
                format: PlanFormat::Json,
            },
        )
        .await
        .is_err());
        assert!(!missing.exists());
        let before = f.repo.storage_usage().await.unwrap();
        assert_eq!(before.objects_used as u64, plan.retained.objects);
        run_gc(plan.plan_hash.clone(), true, PlanFormat::Text)
            .await
            .unwrap();
        let after = f.repo.storage_usage().await.unwrap();
        assert_eq!(
            after.objects_used as u64,
            plan.retained.objects - plan.unreachable.counts.objects
        );
        // Replaying the same reviewed hash is a no-op, in either format.
        run_gc(plan.plan_hash.clone(), false, PlanFormat::Json)
            .await
            .unwrap();
        assert_eq!(f.repo.storage_usage().await.unwrap(), after);
        // The kept state and the branch are intact.
        let kept_file = &f.repo.commit(&head).await.unwrap().commit.files["Report.docx"];
        assert_eq!(
            f.repo
                .read_state(kept_file.document, &kept_file.state)
                .await
                .unwrap(),
            paragraphs(&[])
        );
        f.finish().await;
    }

    #[test]
    fn gc_arguments_require_a_plan_hash_and_parse_options() {
        let command = Action::augment_subcommands(Command::new("repository").no_binary_name(true));
        let parse = |args: &[&str]| {
            let matches = command.clone().try_get_matches_from(args).unwrap();
            Action::from_arg_matches(&matches).unwrap()
        };
        assert!(command.clone().try_get_matches_from(["gc"]).is_err());
        let hash = "ab".repeat(32);
        match parse(&["gc", "--plan-hash", &hash]) {
            Action::Gc {
                plan_hash,
                vacuum,
                format,
            } => {
                assert_eq!(plan_hash, hash);
                assert!(!vacuum);
                assert!(matches!(format, PlanFormat::Json));
            }
            _ => panic!("expected gc"),
        }
        assert!(matches!(
            parse(&["gc", "--plan-hash", &hash, "--vacuum", "--format", "text"]),
            Action::Gc {
                vacuum: true,
                format: PlanFormat::Text,
                ..
            }
        ));
    }

    async fn object_total(repo: &LocalRepository) -> usize {
        repo.storage_usage().await.unwrap().objects_used as usize
    }

    fn merge_args(
        left: &Address,
        right: &Address,
        same_file: SameFile,
        resolutions: BTreeMap<String, Option<FileEntry>>,
    ) -> MergeArgs {
        MergeArgs {
            left: left.clone(),
            right: right.clone(),
            same_file,
            resolutions,
            message: "merge".into(),
            authored_at_ms: 1_700_000_000_500,
            explain: false,
        }
    }

    #[tokio::test]
    async fn a_project_merge_follows_a_rename_with_the_other_side_s_edit_and_verifies() {
        let f = Fixture::new().await;
        let report = DocumentId(uuid::Uuid::new_v4());
        let base = f
            .commit(
                &[],
                vec![("Report.docx", f.file(report, &[]).await)],
                "base",
            )
            .await;
        let left = f
            .commit(
                &[&base],
                vec![("Archive/Report.docx", f.file(report, &[]).await)],
                "rename",
            )
            .await;
        let edited = f.file(report, &[(2, "edited")]).await;
        let right = f
            .commit(&[&base], vec![("Report.docx", edited.clone())], "edit")
            .await;
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let policy = merge_policy::default::policy();
        let output = project_merge_value(
            &f.repo,
            (left.clone(), right.clone()),
            policy,
            &Default::default(),
            (1_700_000_000_900, "merge".into()),
            &key,
        )
        .await
        .unwrap();
        assert_eq!(output["version"], 4);
        assert_eq!(
            output["project_resolutions"][0]["strategy"],
            "dynodoc.project.rename-follow.v1"
        );
        let commit = Address::try_from(output["commit"].as_str().unwrap().to_string()).unwrap();
        let stored = f.repo.commit(&commit).await.unwrap().commit;
        assert_eq!(stored.files["Archive/Report.docx"], edited);
        assert_eq!(stored.merge_policy.unwrap().hash, policy.hash_hex());
        assert_eq!(f.repo.verify_project_resolutions(&commit).await.unwrap(), 1);
        // The same-file merge of the old planner cannot do this.
        assert!(merge_value(
            &f.repo,
            merge_args(&left, &right, SameFile::Clean, BTreeMap::new()),
            &key,
        )
        .await
        .is_err());
        f.finish().await;
    }

    #[tokio::test]
    async fn merge_needs_the_flag_for_same_file_edits_and_records_the_resolution() {
        let f = Fixture::new().await;
        let report = DocumentId(uuid::Uuid::new_v4());
        let base = f
            .commit(
                &[],
                vec![("Report.docx", f.file(report, &[]).await)],
                "base",
            )
            .await;
        let left = f
            .commit(
                &[&base],
                vec![("Report.docx", f.file(report, &[(0, "left")]).await)],
                "left",
            )
            .await;
        let right = f
            .commit(
                &[&base],
                vec![("Report.docx", f.file(report, &[(3, "right")]).await)],
                "right",
            )
            .await;
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        // Without the flag the path is a conflict: an error and no new content.
        let stored = object_total(&f.repo).await;
        let error = merge_value(
            &f.repo,
            merge_args(&left, &right, SameFile::Off, BTreeMap::new()),
            &key,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Report.docx"));
        assert!(error.to_string().contains("--same-file-merge clean"));
        assert_eq!(object_total(&f.repo).await, stored);
        // With the flag: stored, signed as v3, recorded and independently verifiable.
        let output = merge_value(
            &f.repo,
            merge_args(&left, &right, SameFile::Clean, BTreeMap::new()),
            &key,
        )
        .await
        .unwrap();
        assert_eq!(output["version"], 3);
        assert_eq!(output["base"], serde_json::to_value(&base).unwrap());
        assert_eq!(output["parents"], serde_json::json!([left, right]));
        assert_eq!(output["explicit_resolutions"], serde_json::json!([]));
        let record = &output["same_file_resolutions"][0];
        assert_eq!(record["path"], "Report.docx");
        assert_eq!(record["strategy"], "dynodoc.same-file.node-field.v1");
        let commit: Address = serde_json::from_value(output["commit"].clone()).unwrap();
        let stored = f.repo.commit(&commit).await.unwrap();
        assert_eq!(stored.verify().unwrap(), commit);
        assert_eq!(
            stored.commit.files["Report.docx"].state,
            serde_json::from_value::<Address>(record["merged"].clone()).unwrap()
        );
        assert_eq!(
            f.repo.verify_same_file_resolutions(&commit).await.unwrap(),
            1
        );
        // The swapped merge produces the same merged state.
        let swapped = merge_value(
            &f.repo,
            merge_args(&right, &left, SameFile::Clean, BTreeMap::new()),
            &key,
        )
        .await
        .unwrap();
        assert_eq!(
            swapped["same_file_resolutions"][0]["merged"],
            record["merged"]
        );
        assert_ne!(swapped["commit"], output["commit"]);
        f.finish().await;
    }

    #[tokio::test]
    async fn merge_keeps_overlapping_edits_explicit_and_uses_given_resolutions() {
        let f = Fixture::new().await;
        let report = DocumentId(uuid::Uuid::new_v4());
        let base = f
            .commit(
                &[],
                vec![("Report.docx", f.file(report, &[]).await)],
                "base",
            )
            .await;
        let left_file = f.file(report, &[(1, "left wording")]).await;
        let left = f
            .commit(&[&base], vec![("Report.docx", left_file.clone())], "left")
            .await;
        let right = f
            .commit(
                &[&base],
                vec![("Report.docx", f.file(report, &[(1, "right wording")]).await)],
                "right",
            )
            .await;
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        for same_file in [SameFile::Off, SameFile::Clean] {
            assert!(merge_value(
                &f.repo,
                merge_args(&left, &right, same_file, BTreeMap::new()),
                &key
            )
            .await
            .is_err());
        }
        let output = merge_value(
            &f.repo,
            merge_args(
                &left,
                &right,
                SameFile::Clean,
                BTreeMap::from([("Report.docx".to_string(), Some(left_file.clone()))]),
            ),
            &key,
        )
        .await
        .unwrap();
        assert_eq!(output["version"], 1);
        assert_eq!(output["same_file_resolutions"], serde_json::json!([]));
        assert_eq!(
            output["explicit_resolutions"],
            serde_json::json!(["Report.docx"])
        );
        let commit: Address = serde_json::from_value(output["commit"].clone()).unwrap();
        assert_eq!(
            f.repo.commit(&commit).await.unwrap().commit.files["Report.docx"],
            left_file
        );
        f.finish().await;
    }

    #[tokio::test]
    async fn compare_explain_says_how_each_same_file_conflict_is_decided() {
        let f = Fixture::new().await;
        let report = DocumentId(uuid::Uuid::new_v4());
        let base = f
            .commit(
                &[],
                vec![("Report.docx", f.file(report, &[]).await)],
                "base",
            )
            .await;
        let left = f
            .commit(
                &[&base],
                vec![(
                    "Report.docx",
                    f.file(report, &[(0, "left"), (1, "same")]).await,
                )],
                "left",
            )
            .await;
        let right = f
            .commit(
                &[&base],
                vec![(
                    "Report.docx",
                    f.file(report, &[(0, "right"), (2, "other")]).await,
                )],
                "right",
            )
            .await;
        let plain = compare_value(&f.repo, base.clone(), left.clone(), right.clone())
            .await
            .unwrap();
        let policy = merge_policy::default::policy();
        let explained = compare_explained(
            &f.repo,
            base.clone(),
            left.clone(),
            right.clone(),
            Some(policy),
        )
        .await
        .unwrap();
        // Additive: every key of the plain report is unchanged.
        for (key, value) in plain.as_object().unwrap() {
            assert_eq!(&explained[key], value, "{key}");
        }
        let report = &explained["same_file_explain"];
        assert_eq!(report["policy"]["id"], "dynodoc.default.v1");
        assert_eq!(report["policy"]["hash"], policy.hash_hex());
        let file = &report["files"][0];
        assert_eq!(file["path"], "Report.docx");
        // Same verdict as the report that was already there.
        let known = &explained["same_file_convergence"]["files"][0];
        assert_eq!(file["clean"], known["clean"]);
        assert_eq!(file["clean"], false);
        assert_eq!(file["conflicts"], 1);
        let evidence = &file["convergence"]["evidence"];
        let decisions = evidence["decisions"].as_array().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["field"], "label");
        assert_eq!(decisions[0]["reason"], "both-changed");
        assert_eq!(decisions[0]["strategy"], "dynodoc.default.whole-value.v1");
        let text = file["text"].as_str().unwrap();
        assert!(text.contains(".label: conflict (both-changed)"), "{text}");
        assert!(text.contains("    left  \"left\""), "{text}");
        assert!(text.contains("    right \"right\""), "{text}");
        // Swapping the inputs swaps the labels, not the decisions.
        let swapped = compare_explained(&f.repo, base, right, left, Some(policy))
            .await
            .unwrap();
        let other = &swapped["same_file_explain"]["files"][0];
        assert_eq!(
            other["convergence"]["evidence"]["decisions"][0]["conflict_key"],
            decisions[0]["conflict_key"]
        );
        assert!(other["text"]
            .as_str()
            .unwrap()
            .contains("    left  \"right\""));
        f.finish().await;
    }

    #[tokio::test]
    async fn merge_explain_accounts_for_the_paths_it_merged() {
        let f = Fixture::new().await;
        let report = DocumentId(uuid::Uuid::new_v4());
        let base = f
            .commit(
                &[],
                vec![("Report.docx", f.file(report, &[]).await)],
                "base",
            )
            .await;
        let left = f
            .commit(
                &[&base],
                vec![("Report.docx", f.file(report, &[(0, "left")]).await)],
                "left",
            )
            .await;
        let right = f
            .commit(
                &[&base],
                vec![("Report.docx", f.file(report, &[(3, "right")]).await)],
                "right",
            )
            .await;
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let mut args = merge_args(&left, &right, SameFile::Clean, BTreeMap::new());
        args.explain = true;
        let output = merge_value(&f.repo, args, &key).await.unwrap();
        let file = &output["explain"]["files"][0];
        assert_eq!(output["explain"]["policy"]["id"], "dynodoc.default.v1");
        assert_eq!(file["path"], "Report.docx");
        assert_eq!(file["clean"], true);
        assert_eq!(
            file["merged_state"],
            output["same_file_resolutions"][0]["merged"]
        );
        assert_eq!(
            file["convergence"]["evidence"]["decisions"],
            serde_json::json!([])
        );
        assert!(
            file["convergence"]["evidence"]["shortcuts"]["draft_only"]
                .as_u64()
                .unwrap()
                + file["convergence"]["evidence"]["shortcuts"]["unchanged_or_team_only"]
                    .as_u64()
                    .unwrap()
                > 0
        );
        // Without the flag the output has no such key.
        let plain = merge_value(
            &f.repo,
            merge_args(&left, &right, SameFile::Clean, BTreeMap::new()),
            &key,
        )
        .await
        .unwrap();
        assert!(plain.get("explain").is_none());
        // A stored merge can be explained afterwards from its records.
        let commit: Address = serde_json::from_value(output["commit"].clone()).unwrap();
        let records = f
            .repo
            .commit(&commit)
            .await
            .unwrap()
            .commit
            .same_file_resolutions;
        let again = f
            .repo
            .explain_resolutions(&records, merge_policy::default::policy())
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(&again[0]).unwrap(), *file);
        f.finish().await;
    }

    #[test]
    fn a_merge_policy_file_is_loaded_strictly_and_named_in_errors() {
        let dir = std::env::temp_dir();
        let write = |name: &str, text: &str| {
            let path = dir.join(format!("{name}-{}.json", uuid::Uuid::new_v4()));
            std::fs::write(&path, text).unwrap();
            path
        };
        assert_eq!(
            load_policy(None).unwrap().hash_hex(),
            merge_policy::default::policy().hash_hex()
        );
        let good = write(
            "policy-good",
            r#"{"version":1,"id":"mine","rules":[{"id":"all","match":{},"strategy":"dynodoc.default.whole-value.v1","gate":"manual"}]}"#,
        );
        let policy = load_policy(Some(&good)).unwrap();
        assert_eq!(policy.id, "mine");
        let bad = write(
            "policy-bad",
            r#"{"version":1,"id":"mine","rules":[{"id":"all","match":{},"strategy":"nope.v1","gate":"manual"}]}"#,
        );
        let error = format!("{:#}", load_policy(Some(&bad)).unwrap_err());
        assert!(error.contains("policy-bad"), "{error}");
        assert!(error.contains("rules[0].strategy"), "{error}");
        let missing = format!(
            "{:#}",
            load_policy(Some(&dir.join("no-such-policy.json"))).unwrap_err()
        );
        assert!(missing.contains("no-such-policy.json"), "{missing}");
        for path in [good, bad] {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn merge_arguments_parse_and_the_flag_is_optional() {
        let command = Action::augment_subcommands(Command::new("repository").no_binary_name(true));
        let parse = |args: &[&str]| {
            let matches = command.clone().try_get_matches_from(args).unwrap();
            Action::from_arg_matches(&matches).unwrap()
        };
        let base = [
            "merge",
            "L",
            "R",
            "--key",
            "k.der",
            "--message",
            "m",
            "--authored-at-ms",
            "1",
        ];
        assert!(matches!(
            parse(&base),
            Action::Merge {
                same_file_merge: None,
                resolutions: None,
                ..
            }
        ));
        let mut with_flag = base.to_vec();
        with_flag.extend(["--same-file-merge", "clean", "--resolutions", "r.json"]);
        assert!(matches!(
            parse(&with_flag),
            Action::Merge {
                same_file_merge: Some(SameFileMerge::Clean),
                resolutions: Some(_),
                ..
            }
        ));
        let mut bad = base.to_vec();
        bad.extend(["--same-file-merge", "always"]);
        assert!(command.clone().try_get_matches_from(bad).is_err());
        assert!(command
            .clone()
            .try_get_matches_from(["merge", "L", "R"])
            .is_err());
        assert!(matches!(
            parse(&["verify-merge", "abc"]),
            Action::VerifyMerge { explain: false, .. }
        ));
        assert!(matches!(
            parse(&["verify-merge", "abc", "--explain"]),
            Action::VerifyMerge { explain: true, .. }
        ));
        assert!(matches!(
            parse(&["compare", "B", "L", "R"]),
            Action::Compare {
                explain: false,
                merge_policy: None,
                ..
            }
        ));
        assert!(matches!(
            parse(&[
                "compare",
                "B",
                "L",
                "R",
                "--explain",
                "--merge-policy",
                "p.json"
            ]),
            Action::Compare {
                explain: true,
                merge_policy: Some(_),
                ..
            }
        ));
        // A policy without --explain would be silently unused.
        assert!(command
            .clone()
            .try_get_matches_from(["compare", "B", "L", "R", "--merge-policy", "p.json"])
            .is_err());
        let mut explained = base.to_vec();
        explained.push("--explain");
        assert!(matches!(
            parse(&explained),
            Action::Merge { explain: true, .. }
        ));
        // The same-file merge takes no policy: a v3 commit records only the
        // default strategy. A project merge records its policy in a v4 commit.
        let mut with_policy = base.to_vec();
        with_policy.extend(["--merge-policy", "p.json"]);
        assert!(command
            .clone()
            .try_get_matches_from(with_policy.clone())
            .is_err());
        with_policy.extend(["--project-merge", "clean", "--choices", "c.json"]);
        assert!(matches!(
            parse(&with_policy),
            Action::Merge {
                project_merge: Some(SameFileMerge::Clean),
                merge_policy: Some(_),
                choices: Some(_),
                ..
            }
        ));
        // A project merge takes choices, never the v1 path map or the v3 flag.
        let mut mixed = base.to_vec();
        mixed.extend(["--project-merge", "clean", "--same-file-merge", "clean"]);
        assert!(command.clone().try_get_matches_from(mixed).is_err());
        assert!(matches!(
            parse(&[
                "relocate",
                "--from",
                "d:n",
                "--to",
                "e:p:a0",
                "--copy",
                "--onto",
                "c",
                "--key",
                "k",
                "--message",
                "m",
                "--authored-at-ms",
                "1"
            ]),
            Action::Relocate { copy: true, .. }
        ));
        assert!(matches!(
            parse(&["compare", "B", "L", "R", "--project-constraints"]),
            Action::Compare {
                project_constraints: true,
                ..
            }
        ));
    }

    #[test]
    fn horizon_plan_arguments_require_a_policy_and_parse_options() {
        let command = Action::augment_subcommands(Command::new("repository").no_binary_name(true));
        let parse = |args: &[&str]| {
            let matches = command.clone().try_get_matches_from(args).unwrap();
            Action::from_arg_matches(&matches).unwrap()
        };
        assert!(command
            .clone()
            .try_get_matches_from(["horizon-plan"])
            .is_err());
        assert!(matches!(
            parse(&["horizon-plan", "--policy", "p.json"]),
            Action::HorizonPlan {
                list: 10,
                as_of_ms: None,
                out: None,
                format: PlanFormat::Json,
                ..
            }
        ));
        assert!(matches!(
            parse(&[
                "horizon-plan",
                "--policy",
                "p.json",
                "--list",
                "0",
                "--as-of-ms",
                "5",
                "--out",
                "plan.json",
                "--format",
                "text",
            ]),
            Action::HorizonPlan {
                list: 0,
                as_of_ms: Some(5),
                out: Some(_),
                format: PlanFormat::Text,
                ..
            }
        ));
        assert!(command
            .clone()
            .try_get_matches_from(["horizon-plan", "--policy", "p", "--format", "xml"])
            .is_err());
    }

    #[tokio::test]
    async fn horizon_verbs_draft_sign_apply_verify_and_refuse_a_second_key_role() {
        let f = Fixture::new().await;
        let document = DocumentId(uuid::Uuid::new_v4());
        let mut head = f
            .commit(&[], vec![("a", f.file(document, &[]).await)], "c0")
            .await;
        for i in 1..5 {
            let file = f.file(document, &[(0, &format!("edit {i}"))]).await;
            head = f
                .commit(&[&head], vec![("a", file)], &format!("c{i}"))
                .await;
        }
        f.repo.compare_and_swap("main", None, &head).await.unwrap();
        let (path, project) = (f.path.clone(), f.project);
        let dir =
            std::env::temp_dir().join(format!("dynodoc-horizon-verbs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            r#"{"version":1,"id":"cli","tier":"history","window":{"keep_last_commits":2},"protect":{"branch_heads":true},"signatures":{"required":2},"archive":{"required":true,"destination":"file:///a/{project}/{sequence}.dynarc"}}"#,
        )
        .unwrap();
        let key = |name: &str| {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let file = dir.join(name);
            crate::private_file::write_private_test(&file, pkcs8.as_ref()).unwrap();
            file
        };
        let (owner, device) = (key("owner.der"), key("device.der"));
        let plan = f
            .repo
            .horizon_plan(
                &Policy::load(&std::fs::read(&policy).unwrap(), LoadOptions::default()).unwrap(),
                &PlanOptions {
                    as_of_ms: None,
                    list: 0,
                },
            )
            .await
            .unwrap();
        let (record, archive) = (dir.join("record.json"), dir.join("1.dynarc"));
        run(
            path.clone(),
            project,
            Action::HorizonDraft {
                policy: policy.clone(),
                plan_hash: plan.plan_hash.clone(),
                as_of_ms: None,
                created_at_ms: Some(1_791_000_000_000),
                archive: Some(archive.clone()),
                out: record.clone(),
            },
        )
        .await
        .unwrap();
        let signature = dir.join("owner.sig");
        run(
            path.clone(),
            project,
            Action::HorizonSign {
                record: record.clone(),
                key: owner.clone(),
                role: HorizonRole::Owner,
                out: signature.clone(),
            },
        )
        .await
        .unwrap();
        let apply = |key: PathBuf, signatures: Vec<PathBuf>| Action::HorizonApply {
            policy: policy.clone(),
            plan_hash: plan.plan_hash.clone(),
            record: record.clone(),
            signatures,
            key: Some(key),
            role: HorizonRole::Device,
            as_of_ms: None,
            archive: Some(archive.clone()),
            batch: None,
        };
        // The same key twice is one signer: below the two the policy requires.
        assert!(run(
            path.clone(),
            project,
            apply(owner.clone(), vec![signature.clone()])
        )
        .await
        .is_err());
        assert!(f.repo.commit(&plan.sets.released[0]).await.is_ok());
        run(
            path.clone(),
            project,
            apply(device.clone(), vec![signature.clone()]),
        )
        .await
        .unwrap();
        assert!(matches!(
            f.repo.commit(&plan.sets.released[0]).await,
            Err(engine_core::repository::Error::HistoryPruned { .. })
        ));
        run(path.clone(), project, Action::HorizonVerify)
            .await
            .unwrap();
        run(path.clone(), project, Action::HorizonShow)
            .await
            .unwrap();
        let shown = f.repo.horizons().await.unwrap();
        let envelope = dir.join("envelope.json");
        std::fs::write(
            &envelope,
            Envelope::assemble(shown[0].record.clone(), shown[0].signatures.clone())
                .unwrap()
                .bytes()
                .unwrap(),
        )
        .unwrap();
        run(
            path.clone(),
            project,
            Action::HorizonArchiveVerify {
                archive: archive.clone(),
                envelope,
                required: Some(2),
                shared: false,
            },
        )
        .await
        .unwrap();
        run(
            path.clone(),
            project,
            Action::HorizonRehydrate {
                sequence: 1,
                archive,
            },
        )
        .await
        .unwrap();
        assert!(f.repo.commit(&plan.sets.released[0]).await.is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
        f.finish().await;
    }

    #[tokio::test]
    async fn horizon_plan_is_read_only_lists_every_policy_problem_and_never_overwrites() {
        let f = Fixture::new().await;
        let document = DocumentId(uuid::Uuid::new_v4());
        let first = f.file(document, &[]).await;
        let mut head = f.commit(&[], vec![("a", first)], "c0").await;
        for i in 1..5 {
            let file = f.file(document, &[(0, &format!("edit {i}"))]).await;
            head = f
                .commit(&[&head], vec![("a", file)], &format!("c{i}"))
                .await;
        }
        f.repo.compare_and_swap("main", None, &head).await.unwrap();
        let (path, project) = (f.path.clone(), f.project);
        let dir =
            std::env::temp_dir().join(format!("dynodoc-horizon-cli-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("policy.json");
        std::fs::write(
            &policy,
            r#"{"version":1,"id":"cli","tier":"history","window":{"keep_last_commits":2},"protect":{"branch_heads":true}}"#,
        )
        .unwrap();
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let snapshot = || {
            (
                std::fs::read(&path).unwrap(),
                std::fs::read(&wal).unwrap_or_default(),
            )
        };
        let before = snapshot();
        let plan_args = |out: Option<PathBuf>, format| Action::HorizonPlan {
            policy: policy.clone(),
            list: 2,
            as_of_ms: None,
            out,
            format,
        };
        run(path.clone(), project, plan_args(None, PlanFormat::Text))
            .await
            .unwrap();
        let out = dir.join("plan.json");
        run(
            path.clone(),
            project,
            plan_args(Some(out.clone()), PlanFormat::Json),
        )
        .await
        .unwrap();
        assert!(snapshot() == before, "planning wrote to the database");
        // The file is the library's canonical plan for the same inputs.
        let expected = f
            .repo
            .horizon_plan(
                &Policy::load(&std::fs::read(&policy).unwrap(), LoadOptions::default()).unwrap(),
                &PlanOptions {
                    as_of_ms: None,
                    list: 2,
                },
            )
            .await
            .unwrap();
        let written = std::fs::read(&out).unwrap();
        assert_eq!(written, expected.canonical_bytes().unwrap());
        let value: serde_json::Value = serde_json::from_slice(&written).unwrap();
        assert_eq!(value["commits"]["released"], 3);
        assert_eq!(value["read_only"], true);
        // A second run to the same file refuses and leaves it untouched.
        assert!(run(
            path.clone(),
            project,
            plan_args(Some(out.clone()), PlanFormat::Json)
        )
        .await
        .is_err());
        assert_eq!(std::fs::read(&out).unwrap(), written);
        // An invalid policy lists every problem; a missing one is an error too.
        std::fs::write(
            &policy,
            r#"{"version":1,"id":"cli","tier":"history","window":{},"protect":{"branch_heads":false},"x":1}"#,
        )
        .unwrap();
        let error = run(path.clone(), project, plan_args(None, PlanFormat::Json))
            .await
            .unwrap_err()
            .to_string();
        for code in [
            "policy.window_empty",
            "policy.heads_unprotected",
            "policy.unknown_field",
        ] {
            assert!(error.contains(code), "{error}");
        }
        std::fs::remove_file(&policy).unwrap();
        assert!(
            run(path.clone(), project, plan_args(None, PlanFormat::Json))
                .await
                .is_err()
        );
        // A missing database is an error and is never created.
        let missing = path.with_extension("absent");
        assert!(
            run(missing.clone(), project, plan_args(None, PlanFormat::Json))
                .await
                .is_err()
        );
        assert!(!missing.exists());
        // A time rule takes the instant from the flag, not from a clock.
        std::fs::write(
            &policy,
            r#"{"version":1,"id":"days","tier":"content","window":{"keep_within_days":1}}"#,
        )
        .unwrap();
        let timed_out = dir.join("timed.json");
        run(
            path.clone(),
            project,
            Action::HorizonPlan {
                policy: policy.clone(),
                list: 0,
                as_of_ms: Some(1_700_000_000_000),
                out: Some(timed_out.clone()),
                format: PlanFormat::Text,
            },
        )
        .await
        .unwrap();
        let timed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&timed_out).unwrap()).unwrap();
        assert_eq!(timed["as_of_ms"], 1_700_000_000_000i64);
        std::fs::remove_dir_all(&dir).unwrap();
        f.finish().await;
    }

    #[test]
    fn gc_plan_arguments_parse_with_documented_defaults() {
        let command = Action::augment_subcommands(Command::new("repository").no_binary_name(true));
        let parse = |args: &[&str]| {
            let matches = command.clone().try_get_matches_from(args).unwrap();
            Action::from_arg_matches(&matches).unwrap()
        };
        assert!(matches!(
            parse(&["gc-plan"]),
            Action::GcPlan {
                top: 10,
                list: 10,
                format: PlanFormat::Json
            }
        ));
        assert!(matches!(
            parse(&["gc-plan", "--top", "3", "--list", "0", "--format", "text"]),
            Action::GcPlan {
                top: 3,
                list: 0,
                format: PlanFormat::Text
            }
        ));
        assert!(command
            .clone()
            .try_get_matches_from(["gc-plan", "--format", "xml"])
            .is_err());
    }

    #[tokio::test]
    async fn archive_export_selected_closure_excludes_unrelated_private_branch() {
        use engine_core::repository::archive::{
            verify_archive_stream, ArchiveEntry, ArchiveLimits, ArchiveReader,
        };

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1_v1 = f.file(doc1, &[(0, "File 1 v1")]).await;
        let c1 = f.commit(&[], vec![("doc1.docx", f1_v1)], "Genesis").await;

        let f1_v2 = f.file(doc1, &[(0, "File 1 v2")]).await;
        let c2 = f
            .commit(&[&c1], vec![("doc1.docx", f1_v2)], "Mainline edit")
            .await;

        // Unrelated private branch
        let doc2 = DocumentId(uuid::Uuid::new_v4());
        let f2 = f.file(doc2, &[(0, "Private file")]).await;
        let _c3 = f
            .commit(&[&c1], vec![("private.docx", f2.clone())], "Private branch")
            .await;

        let archive_path =
            std::env::temp_dir().join(format!("test-archive-{}.dynoarc", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c2.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        assert!(archive_path.is_file());

        // Verify stream with verify_archive_stream
        let file = std::fs::File::open(&archive_path).unwrap();
        let summary = verify_archive_stream(
            file,
            ArchiveLimits::default(),
            Some(&c2),
            Some(DocumentId(f.project)),
        )
        .unwrap();
        assert_eq!(summary.head, c2);
        assert_eq!(summary.commits, 2); // c1 and c2 only, NOT c3

        // Inspect frame by frame
        let file = std::fs::File::open(&archive_path).unwrap();
        let mut reader = ArchiveReader::new(file, ArchiveLimits::default());
        let mut seen_commits = Vec::new();
        let mut seen_documents = std::collections::HashSet::new();

        while let Some(entry) = reader.next_entry().unwrap() {
            match entry {
                ArchiveEntry::Object { document, .. } => {
                    seen_documents.insert(document);
                }
                ArchiveEntry::Commit { address, .. } => {
                    seen_commits.push(address);
                }
                _ => {}
            }
        }

        assert_eq!(seen_commits, vec![c1, c2]);
        assert!(seen_documents.contains(&doc1));
        assert!(
            !seen_documents.contains(&doc2),
            "unrelated private document must NOT be in archive"
        );

        let _ = std::fs::remove_file(&archive_path);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_export_refuses_overwrite() {
        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Text")]).await;
        let c1 = f.commit(&[], vec![("doc.docx", f1)], "Genesis").await;

        let archive_path =
            std::env::temp_dir().join(format!("test-overwrite-{}.dynoarc", uuid::Uuid::new_v4()));
        std::fs::write(&archive_path, b"existing content").unwrap();

        let err = run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("already exists; refusing overwrite"));
        assert_eq!(std::fs::read(&archive_path).unwrap(), b"existing content");

        let _ = std::fs::remove_file(&archive_path);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_export_tampered_storage_fails_closed_and_removes_incomplete_output() {
        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Text")]).await;
        let c1 = f
            .commit(&[], vec![("doc.docx", f1.clone())], "Genesis")
            .await;

        // Tamper object in database (drop immutable trigger first to simulate disk corruption)
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", f.path.display()))
            .await
            .unwrap();
        sqlx::query("drop trigger if exists objects_no_update")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("update objects set bytes = x'deadbeef' where document = ? and address = ?")
            .bind(doc1.0.to_string())
            .bind(f1.state.as_str())
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let archive_path =
            std::env::temp_dir().join(format!("test-tamper-{}.dynoarc", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&archive_path);

        let err = run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("archive export failed"));
        assert!(
            !archive_path.exists(),
            "incomplete archive output must be removed on failure"
        );

        f.finish().await;
    }

    #[tokio::test]
    async fn archive_export_merge_and_recovery_history() {
        use engine_core::repository::archive::{verify_archive_stream, ArchiveLimits};

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());

        // Base commit c1
        let f1 = f.file(doc1, &[(0, "Base")]).await;
        let c1 = f.commit(&[], vec![("doc1.docx", f1)], "Base").await;

        // Left branch c2
        let f2 = f.file(doc1, &[(0, "Left branch")]).await;
        let c2 = f
            .commit(&[&c1], vec![("doc1.docx", f2)], "Left branch")
            .await;

        // Right branch c3
        let f3 = f.file(doc1, &[(0, "Right branch")]).await;
        let c3 = f
            .commit(&[&c1], vec![("doc1.docx", f3.clone())], "Right branch")
            .await;

        // Merge commit c4
        let c4 = f
            .commit(&[&c2, &c3], vec![("doc1.docx", f3)], "Merge left and right")
            .await;

        let archive_path =
            std::env::temp_dir().join(format!("test-merge-{}.dynoarc", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c4.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        assert!(archive_path.is_file());

        let file = std::fs::File::open(&archive_path).unwrap();
        let summary = verify_archive_stream(
            file,
            ArchiveLimits::default(),
            Some(&c4),
            Some(DocumentId(f.project)),
        )
        .unwrap();
        assert_eq!(summary.head, c4);
        assert_eq!(summary.commits, 4); // c1, c2, c3, c4

        let _ = std::fs::remove_file(&archive_path);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_import_success_leaves_refs_and_pins_unchanged() {
        let f1 = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1_v1 = f1.file(doc1, &[(0, "Genesis content")]).await;
        let c1 = f1
            .commit(&[], vec![("doc.docx", f1_v1.clone())], "Genesis")
            .await;

        let f1_v2 = f1.file(doc1, &[(0, "Updated content")]).await;
        let c2 = f1
            .commit(&[&c1], vec![("doc.docx", f1_v2.clone())], "Edit")
            .await;

        let archive_path = std::env::temp_dir().join(format!(
            "test-import-success-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f1.path.clone(),
            f1.project,
            Action::ArchiveExport {
                head: c2.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        // Target repository with same project
        let f2 = Fixture::with_project(f1.project).await;
        assert_eq!(f2.repo.head("main").await.unwrap(), None);

        run(
            f2.path.clone(),
            f2.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: c2.as_str().to_string(),
            },
        )
        .await
        .unwrap();

        // Verify commits are in f2
        let read_c1 = f2.repo.commit(&c1).await.unwrap();
        assert_eq!(read_c1.commit.message, "Genesis");
        let read_c2 = f2.repo.commit(&c2).await.unwrap();
        assert_eq!(read_c2.commit.message, "Edit");

        // Verify files' content is readable in f2
        let state1 = f2.repo.read_state(doc1, &f1_v1.state).await.unwrap();
        assert_eq!(state1, paragraphs(&[(0, "Genesis content")]));
        let state2 = f2.repo.read_state(doc1, &f1_v2.state).await.unwrap();
        assert_eq!(state2, paragraphs(&[(0, "Updated content")]));

        // Verify refs and pins were NOT moved or created
        assert_eq!(f2.repo.head("main").await.unwrap(), None);

        let _ = std::fs::remove_file(&archive_path);
        f1.finish().await;
        f2.finish().await;
    }

    #[tokio::test]
    async fn archive_import_truncated_footer_leaves_target_untouched() {
        let f1 = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1_v1 = f1.file(doc1, &[(0, "Some content")]).await;
        let c1 = f1.commit(&[], vec![("doc.docx", f1_v1)], "Genesis").await;

        let archive_path = std::env::temp_dir().join(format!(
            "test-import-trunc-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f1.path.clone(),
            f1.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        // Truncate archive (remove last 30 bytes to chop footer)
        let bytes = std::fs::read(&archive_path).unwrap();
        assert!(bytes.len() > 30);
        let truncated = &bytes[..bytes.len() - 30];
        std::fs::write(&archive_path, truncated).unwrap();

        let f2 = Fixture::with_project(f1.project).await;
        let err = run(
            f2.path.clone(),
            f2.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: c1.as_str().to_string(),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("archive validation failed"));
        // Target repository has 0 objects and 0 commits
        assert!(f2.repo.inventory(None, 10).await.unwrap().is_empty());
        assert!(f2.repo.commit(&c1).await.is_err());

        let _ = std::fs::remove_file(&archive_path);
        f1.finish().await;
        f2.finish().await;
    }

    #[tokio::test]
    async fn archive_import_capacity_exhaustion_mid_copy_and_retry() {
        use engine_core::repository::local::StorageLimits;

        let f1 = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1_v1 = f1.file(doc1, &[(0, "Content 1")]).await;
        let c1 = f1.commit(&[], vec![("doc.docx", f1_v1)], "Genesis").await;

        let f1_v2 = f1.file(doc1, &[(0, "Content 2")]).await;
        let c2 = f1.commit(&[&c1], vec![("doc.docx", f1_v2)], "Edit").await;

        let archive_path =
            std::env::temp_dir().join(format!("test-import-cap-{}.dynoarc", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f1.path.clone(),
            f1.project,
            Action::ArchiveExport {
                head: c2.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        let f2 = Fixture::with_project(f1.project).await;
        // Limit f2 to 1 object so import cannot complete all objects
        f2.repo
            .set_storage_limits(StorageLimits {
                objects: 1,
                bytes: 10_000_000,
                commits: 100,
                branches: 10,
            })
            .await
            .unwrap();

        let err = run(
            f2.path.clone(),
            f2.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: c2.as_str().to_string(),
            },
        )
        .await
        .unwrap_err();

        let err_msg = err.to_string();
        assert!(err_msg.contains("archive import failed"));
        assert!(
            err_msg.contains("target copy failed after importing")
                || err_msg.contains("capacity exceeded")
        );

        // Refs and pins unchanged
        assert_eq!(f2.repo.head("main").await.unwrap(), None);

        // Raise storage limits and retry with the exact same archive
        f2.repo
            .set_storage_limits(StorageLimits {
                objects: 100,
                bytes: 10_000_000,
                commits: 100,
                branches: 10,
            })
            .await
            .unwrap();

        run(
            f2.path.clone(),
            f2.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: c2.as_str().to_string(),
            },
        )
        .await
        .unwrap();

        assert!(f2.repo.commit(&c2).await.is_ok());

        let _ = std::fs::remove_file(&archive_path);
        f1.finish().await;
        f2.finish().await;
    }

    #[tokio::test]
    async fn archive_import_existing_object_corruption_fails() {
        let f1 = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1_v1 = f1.file(doc1, &[(0, "Genesis content")]).await;
        let c1 = f1
            .commit(&[], vec![("doc.docx", f1_v1.clone())], "Genesis")
            .await;

        let archive_path = std::env::temp_dir().join(format!(
            "test-import-corrupt-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f1.path.clone(),
            f1.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        let f2 = Fixture::with_project(f1.project).await;
        // Pre-insert the object into f2, but with corrupted bytes in sqlite
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", f2.path.display()))
            .await
            .unwrap();
        sqlx::query(
            "insert into objects(document, address, bytes, codec, size) values(?, ?, x'deadbeef', 0, 4)",
        )
        .bind(doc1.0.to_string())
        .bind(f1_v1.state.as_str())
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let err = run(
            f2.path.clone(),
            f2.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: c1.as_str().to_string(),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("archive import failed"));

        let _ = std::fs::remove_file(&archive_path);
        f1.finish().await;
        f2.finish().await;
    }

    #[tokio::test]
    async fn archive_import_rejects_head_or_project_mismatch() {
        let f1 = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1_v1 = f1.file(doc1, &[(0, "Genesis")]).await;
        let c1 = f1
            .commit(&[], vec![("doc.docx", f1_v1.clone())], "Genesis")
            .await;

        let f1_v2 = f1.file(doc1, &[(0, "Edit")]).await;
        let c2 = f1.commit(&[&c1], vec![("doc.docx", f1_v2)], "Edit").await;

        let archive_path = std::env::temp_dir().join(format!(
            "test-import-mismatch-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f1.path.clone(),
            f1.project,
            Action::ArchiveExport {
                head: c2.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        let f2 = Fixture::with_project(f1.project).await;
        // Head mismatch
        let err = run(
            f2.path.clone(),
            f2.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: c1.as_str().to_string(), // wrong head
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("archive validation failed"));
        assert!(err.to_string().contains("head mismatch"));

        // Project mismatch (f3 has different project)
        let f3 = Fixture::new().await;
        let err2 = run(
            f3.path.clone(),
            f3.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: c2.as_str().to_string(),
            },
        )
        .await
        .unwrap_err();
        assert!(err2.to_string().contains("archive validation failed"));
        assert!(err2.to_string().contains("project mismatch"));

        let _ = std::fs::remove_file(&archive_path);
        f1.finish().await;
        f2.finish().await;
        f3.finish().await;
    }

    #[tokio::test]
    async fn archive_import_rejects_extra_unrelated_payloads() {
        use engine_core::repository::archive::ArchiveWriter;

        let f1 = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1_v1 = f1.file(doc1, &[(0, "Genesis")]).await;
        let c1 = f1
            .commit(&[], vec![("doc.docx", f1_v1.clone())], "Genesis")
            .await;

        let doc_extra = DocumentId(uuid::Uuid::new_v4());
        let f_extra = f1.file(doc_extra, &[(0, "Unrelated object")]).await;

        let archive_path = std::env::temp_dir().join(format!(
            "test-extra-payload-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut writer = ArchiveWriter::new(file).unwrap();
        writer
            .write_header(1, DocumentId(f1.project), c1.clone())
            .unwrap();

        // Write all objects for doc1 (Genesis)
        let keys = f1.repo.inventory(None, 100).await.unwrap();
        for key in &keys {
            if key.document == doc1 {
                let p = f1.repo.object(key).await.unwrap();
                writer
                    .write_object(doc1, key.address.clone(), &p.bytes)
                    .unwrap();
            }
        }

        // Write Extra unrelated object
        let p_extra = f1
            .repo
            .object(&ObjectKey {
                document: doc_extra,
                address: f_extra.state.clone(),
            })
            .await
            .unwrap();
        writer
            .write_object(doc_extra, f_extra.state.clone(), &p_extra.bytes)
            .unwrap();

        // Write commit c1
        let signed_c1 = f1.repo.commit(&c1).await.unwrap();
        writer.write_commit(&signed_c1).unwrap();
        writer.finish().unwrap();

        let f2 = Fixture::with_project(f1.project).await;
        let err = run(
            f2.path.clone(),
            f2.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: c1.as_str().to_string(),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("archive validation failed"));
        assert!(err
            .to_string()
            .contains("extra objects outside the selected object closure"));
        assert!(f2.repo.inventory(None, 10).await.unwrap().is_empty());

        let _ = std::fs::remove_file(&archive_path);
        f1.finish().await;
        f2.finish().await;
    }

    #[tokio::test]
    async fn archive_verify_valid_multi_parent_and_recovery_archive() {
        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());

        // Base commit c1
        let f1 = f.file(doc1, &[(0, "Base")]).await;
        let c1 = f.commit(&[], vec![("doc1.docx", f1)], "Base").await;

        // Left branch c2
        let f2 = f.file(doc1, &[(0, "Left branch")]).await;
        let c2 = f
            .commit(&[&c1], vec![("doc1.docx", f2)], "Left branch")
            .await;

        // Right branch c3
        let f3 = f.file(doc1, &[(0, "Right branch")]).await;
        let c3 = f
            .commit(&[&c1], vec![("doc1.docx", f3.clone())], "Right branch")
            .await;

        // Merge commit c4
        let c4 = f
            .commit(&[&c2, &c3], vec![("doc1.docx", f3)], "Merge left and right")
            .await;

        let archive_path = std::env::temp_dir().join(format!(
            "test-verify-merge-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c4.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        // 1. Verify via repository action
        run(
            f.path.clone(),
            f.project,
            Action::ArchiveVerify {
                file: archive_path.clone(),
                expect_head: c4.as_str().to_string(),
            },
        )
        .await
        .unwrap();

        // 2. Verify via top-level archive_verify without repository
        super::super::archive_verify(archive_path.clone(), f.project, c4.as_str().to_string())
            .await
            .unwrap();

        let _ = std::fs::remove_file(&archive_path);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_verify_substituted_heads_and_scope_swaps_fail() {
        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Genesis")]).await;
        let c1 = f.commit(&[], vec![("doc.docx", f1)], "Genesis").await;

        let archive_path = std::env::temp_dir().join(format!(
            "test-verify-subst-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        // Substituted head
        let fake_head = Address::try_from(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        )
        .unwrap();
        let err = super::super::archive_verify(
            archive_path.clone(),
            f.project,
            fake_head.as_str().to_string(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("archive verification failed"));
        assert!(err.to_string().contains("head mismatch"));

        // Scope swap (wrong project UUID)
        let other_project = uuid::Uuid::new_v4();
        let err_proj = super::super::archive_verify(
            archive_path.clone(),
            other_project,
            c1.as_str().to_string(),
        )
        .await
        .unwrap_err();
        assert!(err_proj.to_string().contains("archive verification failed"));
        assert!(err_proj.to_string().contains("project mismatch"));

        let _ = std::fs::remove_file(&archive_path);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_verify_altered_envelopes_and_missing_objects_fail() {
        use engine_core::repository::archive::ArchiveWriter;

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Genesis")]).await;
        let c1 = f
            .commit(&[], vec![("doc.docx", f1.clone())], "Genesis")
            .await;

        // 1. Missing objects in archive
        let archive_missing = std::env::temp_dir().join(format!(
            "test-verify-missing-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let file = std::fs::File::create(&archive_missing).unwrap();
        let mut writer = ArchiveWriter::new(file).unwrap();
        writer
            .write_header(1, DocumentId(f.project), c1.clone())
            .unwrap();
        // Do NOT write the object frame for f1!
        let signed_c1 = f.repo.commit(&c1).await.unwrap();
        writer.write_commit(&signed_c1).unwrap();
        writer.finish().unwrap();

        let err = super::super::archive_verify(
            archive_missing.clone(),
            f.project,
            c1.as_str().to_string(),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("object referenced in file graph is missing from archive"));
        let _ = std::fs::remove_file(&archive_missing);

        // 2. Altered envelope: export valid archive then alter envelope bytes
        let archive_altered = std::env::temp_dir().join(format!(
            "test-verify-altered-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_altered.clone(),
            },
        )
        .await
        .unwrap();

        let mut bytes = std::fs::read(&archive_altered).unwrap();
        // Locate "envelope":" and alter a base64 character in the middle
        let pos = bytes
            .windows(12)
            .position(|w| w == b"\"envelope\":\"")
            .unwrap();
        bytes[pos + 15] ^= 0x01;
        std::fs::write(&archive_altered, bytes).unwrap();

        let err2 = super::super::archive_verify(
            archive_altered.clone(),
            f.project,
            c1.as_str().to_string(),
        )
        .await
        .unwrap_err();
        assert!(err2.to_string().contains("archive verification failed"));

        let _ = std::fs::remove_file(&archive_altered);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_verify_repeated_frames_appended_data_and_truncation_fail() {
        use engine_core::repository::archive::ArchiveWriter;

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Genesis")]).await;
        let c1 = f
            .commit(&[], vec![("doc.docx", f1.clone())], "Genesis")
            .await;

        // 1. Repeated frame (duplicate object)
        let archive_dup =
            std::env::temp_dir().join(format!("test-verify-dup-{}.dynoarc", uuid::Uuid::new_v4()));
        let file = std::fs::File::create(&archive_dup).unwrap();
        let mut writer = ArchiveWriter::new(file).unwrap();
        writer
            .write_header(1, DocumentId(f.project), c1.clone())
            .unwrap();
        let keys = f.repo.inventory(None, 100).await.unwrap();
        for key in &keys {
            let p = f.repo.object(key).await.unwrap();
            writer
                .write_object(key.document, key.address.clone(), &p.bytes)
                .unwrap();
        }
        // Write a duplicate object frame
        let first_key = &keys[0];
        let p_dup = f.repo.object(first_key).await.unwrap();
        assert!(writer
            .write_object(first_key.document, first_key.address.clone(), &p_dup.bytes)
            .is_err());
        let _ = std::fs::remove_file(&archive_dup);

        // 2. Appended data after footer
        let archive_appended = std::env::temp_dir().join(format!(
            "test-verify-appended-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_appended.clone(),
            },
        )
        .await
        .unwrap();

        let mut bytes = std::fs::read(&archive_appended).unwrap();
        bytes.extend_from_slice(b"trailing extra garbage bytes");
        std::fs::write(&archive_appended, bytes).unwrap();

        let err = super::super::archive_verify(
            archive_appended.clone(),
            f.project,
            c1.as_str().to_string(),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("unexpected trailing data after footer"));
        let _ = std::fs::remove_file(&archive_appended);

        // 3. Truncation
        let archive_trunc = std::env::temp_dir().join(format!(
            "test-verify-trunc-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_trunc.clone(),
            },
        )
        .await
        .unwrap();

        let bytes = std::fs::read(&archive_trunc).unwrap();
        std::fs::write(&archive_trunc, &bytes[..bytes.len() - 25]).unwrap();

        let err2 =
            super::super::archive_verify(archive_trunc.clone(), f.project, c1.as_str().to_string())
                .await
                .unwrap_err();
        assert!(err2.to_string().contains("archive verification failed"));
        let _ = std::fs::remove_file(&archive_trunc);

        f.finish().await;
    }

    #[tokio::test]
    async fn export_file_retained_old_commit_after_later_edits_and_deletion() {
        use engine_core::repository::state_export::StateExportEnvelope;

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());

        // c1: Report.docx v1
        let f1 = f.file(doc1, &[(0, "Report v1")]).await;
        let c1 = f.commit(&[], vec![("Report.docx", f1)], "Genesis").await;

        // c2: Report.docx v2
        let f2 = f.file(doc1, &[(0, "Report v2")]).await;
        let c2 = f
            .commit(&[&c1], vec![("Report.docx", f2)], "Edit report")
            .await;

        // c3: Delete Report.docx and add Report-Renamed.docx
        let f3 = f.file(doc1, &[(0, "Report Renamed")]).await;
        let c3 = f
            .commit(&[&c2], vec![("Report-Renamed.docx", f3)], "Rename report")
            .await;

        let export_out =
            std::env::temp_dir().join(format!("test-export-v1-{}.json", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&export_out);

        // Export Report.docx from retained old commit c1
        run(
            f.path.clone(),
            f.project,
            Action::ExportFile {
                commit: c1.as_str().to_string(),
                path: "Report.docx".to_string(),
                out: export_out.clone(),
            },
        )
        .await
        .unwrap();

        assert!(export_out.is_file());

        // Verify exported envelope JSON
        let envelope_bytes = std::fs::read(&export_out).unwrap();
        let envelope: StateExportEnvelope = serde_json::from_slice(&envelope_bytes).unwrap();
        assert_eq!(envelope.format, "dynodoc.state-export");
        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.path, "Report.docx");
        assert_eq!(envelope.commit.verify().unwrap(), c1);
        assert_eq!(envelope.state, paragraphs(&[(0, "Report v1")]));

        // Attempting to export Report.docx at c3 must fail (file was deleted)
        let export_fail_deleted = std::env::temp_dir().join(format!(
            "test-export-fail-del-{}.json",
            uuid::Uuid::new_v4()
        ));
        let err_del = run(
            f.path.clone(),
            f.project,
            Action::ExportFile {
                commit: c3.as_str().to_string(),
                path: "Report.docx".to_string(),
                out: export_fail_deleted.clone(),
            },
        )
        .await
        .unwrap_err();
        assert!(err_del.to_string().contains("not found in commit"));
        assert!(!export_fail_deleted.exists());

        // Attempting to export Report-Renamed.docx at c1 must fail (never guess a rename)
        let export_fail_rename = std::env::temp_dir().join(format!(
            "test-export-fail-ren-{}.json",
            uuid::Uuid::new_v4()
        ));
        let err_ren = run(
            f.path.clone(),
            f.project,
            Action::ExportFile {
                commit: c1.as_str().to_string(),
                path: "Report-Renamed.docx".to_string(),
                out: export_fail_rename.clone(),
            },
        )
        .await
        .unwrap_err();
        assert!(err_ren.to_string().contains("not found in commit"));
        assert!(!export_fail_rename.exists());

        // Repository refs/pins remain untouched
        assert_eq!(f.repo.head("main").await.unwrap(), None);

        let _ = std::fs::remove_file(&export_out);
        f.finish().await;
    }

    #[tokio::test]
    async fn export_file_refuses_overwrite_and_sets_private_permissions() {
        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Content")]).await;
        let c1 = f.commit(&[], vec![("doc.docx", f1)], "Genesis").await;

        let export_out =
            std::env::temp_dir().join(format!("test-export-perm-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&export_out, b"pre-existing content").unwrap();

        // Refuses overwrite
        let err = run(
            f.path.clone(),
            f.project,
            Action::ExportFile {
                commit: c1.as_str().to_string(),
                path: "doc.docx".to_string(),
                out: export_out.clone(),
            },
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("already exists; refusing overwrite"));
        assert_eq!(std::fs::read(&export_out).unwrap(), b"pre-existing content");

        let _ = std::fs::remove_file(&export_out);

        // Successful export sets 0600 permissions on Unix
        run(
            f.path.clone(),
            f.project,
            Action::ExportFile {
                commit: c1.as_str().to_string(),
                path: "doc.docx".to_string(),
                out: export_out.clone(),
            },
        )
        .await
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&export_out).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let _ = std::fs::remove_file(&export_out);
        f.finish().await;
    }

    #[tokio::test]
    async fn export_file_corrupt_object_cleans_up_incomplete_output() {
        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Content")]).await;
        let c1 = f
            .commit(&[], vec![("doc.docx", f1.clone())], "Genesis")
            .await;

        // Tamper object in SQLite
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", f.path.display()))
            .await
            .unwrap();
        sqlx::query("drop trigger if exists objects_no_update")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("update objects set bytes = x'deadbeef' where document = ? and address = ?")
            .bind(doc1.0.to_string())
            .bind(f1.state.as_str())
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let export_out =
            std::env::temp_dir().join(format!("test-export-corrupt-{}.json", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&export_out);

        let err = run(
            f.path.clone(),
            f.project,
            Action::ExportFile {
                commit: c1.as_str().to_string(),
                path: "doc.docx".to_string(),
                out: export_out.clone(),
            },
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("failed to reconstruct")
                || err.to_string().contains("HashMismatch")
        );
        assert!(
            !export_out.exists(),
            "incomplete export file must be removed on failure"
        );

        f.finish().await;
    }

    #[tokio::test]
    async fn state_export_verify_cli_workflow() {
        use crate::{Cli, Command};
        use clap::Parser;

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Report initial content")]).await;
        let c1 = f
            .commit(&[], vec![("Report.docx", f1)], "Genesis commit")
            .await;

        let export_out =
            std::env::temp_dir().join(format!("test-verify-cli-{}.json", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&export_out);

        // Export Report.docx from c1
        run(
            f.path.clone(),
            f.project,
            Action::ExportFile {
                commit: c1.as_str().to_string(),
                path: "Report.docx".to_string(),
                out: export_out.clone(),
            },
        )
        .await
        .unwrap();

        // 1. Verify clap parsing and dispatch
        let parsed = Cli::try_parse_from([
            "engine-cli",
            "state-export-verify",
            export_out.to_str().unwrap(),
            "--project",
            &f.project.to_string(),
            "--expect-commit",
            c1.as_str(),
            "--path",
            "Report.docx",
        ])
        .expect("clap parsing state-export-verify");

        match parsed.command {
            Command::StateExportVerify {
                file,
                project,
                expect_commit,
                path,
            } => {
                assert_eq!(file, export_out);
                assert_eq!(project, f.project);
                assert_eq!(expect_commit, c1.as_str());
                assert_eq!(path, "Report.docx");
            }
            _ => panic!("expected Command::StateExportVerify"),
        }

        // 1b. Verify clap parsing with --expect-path alias
        let parsed_alias = Cli::try_parse_from([
            "engine-cli",
            "state-export-verify",
            export_out.to_str().unwrap(),
            "--project",
            &f.project.to_string(),
            "--expect-commit",
            c1.as_str(),
            "--expect-path",
            "Report.docx",
        ])
        .expect("clap parsing state-export-verify with alias");
        assert!(matches!(
            parsed_alias.command,
            Command::StateExportVerify { .. }
        ));

        // 1c. Missing required flags fails clap parsing
        assert!(Cli::try_parse_from([
            "engine-cli",
            "state-export-verify",
            export_out.to_str().unwrap(),
            "--expect-commit",
            c1.as_str(),
            "--path",
            "Report.docx",
        ])
        .is_err());

        assert!(Cli::try_parse_from([
            "engine-cli",
            "state-export-verify",
            export_out.to_str().unwrap(),
            "--project",
            &f.project.to_string(),
            "--path",
            "Report.docx",
        ])
        .is_err());

        assert!(Cli::try_parse_from([
            "engine-cli",
            "state-export-verify",
            export_out.to_str().unwrap(),
            "--project",
            &f.project.to_string(),
            "--expect-commit",
            c1.as_str(),
        ])
        .is_err());

        // 2. Successful verification via CLI entrypoint
        super::super::state_export_verify(
            export_out.clone(),
            f.project,
            c1.as_str().to_string(),
            "Report.docx".to_string(),
        )
        .await
        .expect("state_export_verify should succeed");

        // 3. Wrong project expectation fails
        let wrong_proj = uuid::Uuid::new_v4();
        let err_proj = super::super::state_export_verify(
            export_out.clone(),
            wrong_proj,
            c1.as_str().to_string(),
            "Report.docx".to_string(),
        )
        .await
        .unwrap_err();
        assert!(err_proj
            .to_string()
            .contains("does not match expected project"));

        // 4. Wrong commit expectation fails
        let wrong_commit = "00".repeat(32);
        let err_commit = super::super::state_export_verify(
            export_out.clone(),
            f.project,
            wrong_commit,
            "Report.docx".to_string(),
        )
        .await
        .unwrap_err();
        assert!(err_commit
            .to_string()
            .contains("does not match expected commit"));

        // 5. Wrong path expectation fails
        let err_path = super::super::state_export_verify(
            export_out.clone(),
            f.project,
            c1.as_str().to_string(),
            "Other.docx".to_string(),
        )
        .await
        .unwrap_err();
        assert!(err_path
            .to_string()
            .contains("does not match expected path"));

        // 6. Corrupted input file fails
        let corrupt_path =
            std::env::temp_dir().join(format!("test-verify-corrupt-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&corrupt_path, b"not valid json").unwrap();
        let err_corrupt = super::super::state_export_verify(
            corrupt_path.clone(),
            f.project,
            c1.as_str().to_string(),
            "Report.docx".to_string(),
        )
        .await
        .unwrap_err();
        assert!(err_corrupt.to_string().contains("verification failed"));
        let _ = std::fs::remove_file(&corrupt_path);

        // 7. Missing input file fails
        let missing_path =
            std::env::temp_dir().join(format!("nonexistent-{}.json", uuid::Uuid::new_v4()));
        let err_missing = super::super::state_export_verify(
            missing_path.clone(),
            f.project,
            c1.as_str().to_string(),
            "Report.docx".to_string(),
        )
        .await
        .unwrap_err();
        assert!(err_missing
            .to_string()
            .contains("state export file not found"));

        // 8. Confirm no new files or repository alterations were made
        assert_eq!(f.repo.head("main").await.unwrap(), None);

        let _ = std::fs::remove_file(&export_out);
        f.finish().await;
    }

    #[tokio::test]
    async fn export_file_project_mismatch_fails() {
        let f1 = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1_v1 = f1.file(doc1, &[(0, "Content")]).await;
        let c1 = f1.commit(&[], vec![("doc.docx", f1_v1)], "Genesis").await;

        let export_out = std::env::temp_dir().join(format!(
            "test-export-mismatch-{}.json",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&export_out);

        let f2 = Fixture::new().await; // different project UUID
        let err = run(
            f1.path.clone(),
            f2.project, // pass wrong project to run()
            Action::ExportFile {
                commit: c1.as_str().to_string(),
                path: "doc.docx".to_string(),
                out: export_out.clone(),
            },
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match repository project")
                || err.to_string().contains("local schema/project")
        );
        assert!(!export_out.exists());

        f1.finish().await;
        f2.finish().await;
    }

    #[tokio::test]
    async fn archive_export_deep_history_iterative_topological_sort() {
        use engine_core::repository::archive::{
            verify_archive_stream, ArchiveEntry, ArchiveLimits, ArchiveReader,
        };

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());

        // Build a 25-deep commit chain
        let f1_v0 = f.file(doc1, &[(0, "Initial content")]).await;
        let mut prev = f.commit(&[], vec![("doc.docx", f1_v0)], "Commit 0").await;
        let mut all_commits = vec![prev.clone()];

        for i in 1..25 {
            let fi = f.file(doc1, &[(0, &format!("Content version {i}"))]).await;
            let c = f
                .commit(&[&prev], vec![("doc.docx", fi)], &format!("Commit {i}"))
                .await;
            all_commits.push(c.clone());
            prev = c;
        }

        let head = prev;
        let archive_path = std::env::temp_dir().join(format!(
            "test-archive-deep-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: head.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        assert!(archive_path.is_file());

        // Stream verification
        let file = std::fs::File::open(&archive_path).unwrap();
        let summary = verify_archive_stream(
            file,
            ArchiveLimits::default(),
            Some(&head),
            Some(DocumentId(f.project)),
        )
        .unwrap();
        assert_eq!(summary.head, head);
        assert_eq!(summary.commits, 25);

        // Frame order inspection: commits must appear in dependency-first order
        let file2 = std::fs::File::open(&archive_path).unwrap();
        let mut reader = ArchiveReader::new(file2, ArchiveLimits::default());
        let mut seen_commits = Vec::new();
        while let Some(entry) = reader.next_entry().unwrap() {
            if let ArchiveEntry::Commit { address, .. } = entry {
                seen_commits.push(address);
            }
        }
        assert_eq!(seen_commits, all_commits);

        let _ = std::fs::remove_file(&archive_path);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_export_shared_subgraphs_deduplicate_by_document_and_address() {
        use engine_core::repository::archive::{ArchiveEntry, ArchiveLimits, ArchiveReader};

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let doc2 = DocumentId(uuid::Uuid::new_v4());

        let f1 = f.file(doc1, &[(0, "Shared Doc1 content")]).await;
        let c1 = f
            .commit(&[], vec![("doc1.docx", f1.clone())], "Genesis")
            .await;

        let f2 = f.file(doc2, &[(0, "Doc2 content")]).await;
        let c2 = f
            .commit(
                &[&c1],
                vec![("doc1.docx", f1.clone()), ("doc2.docx", f2.clone())],
                "Add doc2 while doc1 unchanged",
            )
            .await;

        let c3 = f
            .commit(
                &[&c1, &c2],
                vec![("doc1.docx", f1.clone()), ("doc2.docx", f2.clone())],
                "Merge branch",
            )
            .await;

        let archive_path = std::env::temp_dir().join(format!(
            "test-archive-shared-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_path);

        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c3.as_str().to_string(),
                since: None,
                out: archive_path.clone(),
            },
        )
        .await
        .unwrap();

        let file = std::fs::File::open(&archive_path).unwrap();
        let mut reader = ArchiveReader::new(file, ArchiveLimits::default());
        let mut object_keys = Vec::new();
        while let Some(entry) = reader.next_entry().unwrap() {
            if let ArchiveEntry::Object {
                document, address, ..
            } = entry
            {
                object_keys.push((document, address));
            }
        }

        // Each distinct (document, address) must appear exactly once
        let mut set = std::collections::HashSet::new();
        for key in &object_keys {
            assert!(
                set.insert(key.clone()),
                "duplicate object in export: {:?}",
                key
            );
        }

        let _ = std::fs::remove_file(&archive_path);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_export_corrupt_or_missing_rows_removes_incomplete_output() {
        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "File 1")]).await;
        let c1 = f
            .commit(&[], vec![("doc1.docx", f1.clone())], "Genesis")
            .await;
        let f2 = f.file(doc1, &[(0, "File 2")]).await;
        let c2 = f
            .commit(&[&c1], vec![("doc1.docx", f2.clone())], "Child")
            .await;

        // 1. Missing dependency commit
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", f.path.display()))
            .await
            .unwrap();
        sqlx::query("drop trigger if exists commits_no_delete")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from commits where address = ?")
            .bind(c1.as_str())
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let archive_fail_commit = std::env::temp_dir().join(format!(
            "test-archive-fail-c-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_fail_commit);

        let err1 = run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c2.as_str().to_string(),
                since: None,
                out: archive_fail_commit.clone(),
            },
        )
        .await
        .unwrap_err();

        assert!(
            err1.to_string().contains("dependency closure missing")
                || err1.to_string().contains("archive export failed")
        );
        assert!(
            !archive_fail_commit.exists(),
            "incomplete archive must be removed"
        );

        // 2. Corrupt object
        let f_b = Fixture::new().await;
        let doc_b = DocumentId(uuid::Uuid::new_v4());
        let fb1 = f_b.file(doc_b, &[(0, "Object content")]).await;
        let cb1 = f_b
            .commit(&[], vec![("doc.docx", fb1.clone())], "Genesis")
            .await;

        let pool_b = sqlx::SqlitePool::connect(&format!("sqlite://{}", f_b.path.display()))
            .await
            .unwrap();
        sqlx::query("drop trigger if exists objects_no_update")
            .execute(&pool_b)
            .await
            .unwrap();
        sqlx::query("update objects set bytes = x'cafebabe' where document = ? and address = ?")
            .bind(doc_b.0.to_string())
            .bind(fb1.state.as_str())
            .execute(&pool_b)
            .await
            .unwrap();
        pool_b.close().await;

        let archive_fail_obj = std::env::temp_dir().join(format!(
            "test-archive-fail-o-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_fail_obj);

        let err2 = run(
            f_b.path.clone(),
            f_b.project,
            Action::ArchiveExport {
                head: cb1.as_str().to_string(),
                since: None,
                out: archive_fail_obj.clone(),
            },
        )
        .await
        .unwrap_err();

        assert!(
            err2.to_string().contains("hash mismatch")
                || err2.to_string().contains("archive export failed")
        );
        assert!(
            !archive_fail_obj.exists(),
            "incomplete archive must be removed"
        );

        f.finish().await;
        f_b.finish().await;
    }

    #[tokio::test]
    async fn archive_export_large_synthetic_payload_set_streamed() {
        use engine_core::repository::archive::{verify_archive_stream, ArchiveLimits};

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());

        // Create multiple large paragraphs (synthetic payloads)
        let large_text = "Dynodoc streaming archive export test string. ".repeat(500); // ~23 KB per entry
        let f1 = f
            .file(
                doc1,
                &[
                    (0, &large_text),
                    (1, &large_text),
                    (2, &large_text),
                    (3, &large_text),
                ],
            )
            .await;
        let c1 = f
            .commit(&[], vec![("large.docx", f1)], "Commit with large payload")
            .await;

        let archive_out = std::env::temp_dir().join(format!(
            "test-archive-large-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&archive_out);

        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: None,
                out: archive_out.clone(),
            },
        )
        .await
        .unwrap();

        assert!(archive_out.is_file());
        let meta = std::fs::metadata(&archive_out).unwrap();
        assert!(meta.len() > 30_000, "archive should be sizable");

        // Verify the entire streamed archive
        let file = std::fs::File::open(&archive_out).unwrap();
        let summary = verify_archive_stream(
            file,
            ArchiveLimits::default(),
            Some(&c1),
            Some(DocumentId(f.project)),
        )
        .unwrap();
        assert_eq!(summary.head, c1);
        assert_eq!(summary.commits, 1);
        assert!(summary.objects >= 1);

        let _ = std::fs::remove_file(&archive_out);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_export_incremental_size_reduction_and_omitted_objects() {
        use engine_core::repository::archive::{
            verify_archive_stream, ArchiveEntry, ArchiveLimits, ArchiveReader,
        };

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let doc2 = DocumentId(uuid::Uuid::new_v4());

        // c1: Genesis with doc1 and doc2 (sizable payloads)
        let large_doc2 = "Large doc2 content for archive base. ".repeat(200);
        let f1_v1 = f.file(doc1, &[(0, "Doc 1 Genesis content")]).await;
        let f2_v1 = f.file(doc2, &[(0, &large_doc2)]).await;
        let c1 = f
            .commit(
                &[],
                vec![("doc1.docx", f1_v1.clone()), ("doc2.docx", f2_v1.clone())],
                "Genesis c1",
            )
            .await;

        // c2: Edit doc1, keep doc2 untouched
        let f1_v2 = f.file(doc1, &[(0, "Doc 1 Second version")]).await;
        let c2 = f
            .commit(
                &[&c1],
                vec![("doc1.docx", f1_v2.clone()), ("doc2.docx", f2_v1.clone())],
                "Edit doc1 c2",
            )
            .await;

        // c3: Edit doc1 again, keep doc2 untouched
        let f1_v3 = f.file(doc1, &[(0, "Doc 1 Third version")]).await;
        let c3 = f
            .commit(
                &[&c2],
                vec![("doc1.docx", f1_v3.clone()), ("doc2.docx", f2_v1.clone())],
                "Edit doc1 c3",
            )
            .await;

        // 1. Full export of c3
        let full_out = std::env::temp_dir().join(format!(
            "test-archive-full-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&full_out);
        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c3.as_str().to_string(),
                since: None,
                out: full_out.clone(),
            },
        )
        .await
        .unwrap();

        let full_summary = verify_archive_stream(
            std::fs::File::open(&full_out).unwrap(),
            ArchiveLimits::default(),
            Some(&c3),
            Some(DocumentId(f.project)),
        )
        .unwrap();
        assert_eq!(full_summary.commits, 3);
        assert_eq!(full_summary.since, None);

        // 2. Incremental export of c3 since c1
        let incr_out = std::env::temp_dir().join(format!(
            "test-archive-incr-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&incr_out);
        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c3.as_str().to_string(),
                since: Some(c1.as_str().to_string()),
                out: incr_out.clone(),
            },
        )
        .await
        .unwrap();

        let incr_summary = verify_archive_stream(
            std::fs::File::open(&incr_out).unwrap(),
            ArchiveLimits::default(),
            Some(&c3),
            Some(DocumentId(f.project)),
        )
        .unwrap();
        assert_eq!(incr_summary.commits, 2); // c2 and c3 only
        assert_eq!(incr_summary.since, Some(c1.clone()));
        // Review patch: the CLI's offline verifier fails closed on a delta, so it is never
        // reported as a verified complete history (audit F-05).
        let err =
            super::super::archive_verify(incr_out.clone(), f.project, c3.as_str().to_string())
                .await
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("incremental archive requires target repository"),
            "{err}"
        );

        // Assert size reduction
        let full_len = std::fs::metadata(&full_out).unwrap().len();
        let incr_len = std::fs::metadata(&incr_out).unwrap().len();
        assert!(
            incr_len < full_len,
            "incremental export ({incr_len} bytes) should be smaller than full export ({full_len} bytes)"
        );

        // Verify stream of incremental archive
        let file = std::fs::File::open(&incr_out).unwrap();
        let summary = verify_archive_stream(
            file,
            ArchiveLimits::default(),
            Some(&c3),
            Some(DocumentId(f.project)),
        )
        .unwrap();
        assert_eq!(summary.head, c3);
        assert_eq!(summary.since, Some(c1.clone()));
        assert_eq!(summary.commits, 2);

        // Inspect frame-by-frame: doc2 objects must NOT appear in incremental archive
        let file2 = std::fs::File::open(&incr_out).unwrap();
        let mut reader = ArchiveReader::new(file2, ArchiveLimits::default());
        let mut seen_commits = Vec::new();
        let mut seen_docs = std::collections::HashSet::new();

        while let Some(entry) = reader.next_entry().unwrap() {
            match entry {
                ArchiveEntry::Header { since, .. } => {
                    assert_eq!(since, Some(c1.clone()));
                }
                ArchiveEntry::Object { document, .. } => {
                    seen_docs.insert(document);
                }
                ArchiveEntry::Commit { address, .. } => {
                    seen_commits.push(address);
                }
                ArchiveEntry::Footer(s) => {
                    assert_eq!(s.since, Some(c1.clone()));
                }
            }
        }

        assert_eq!(seen_commits, vec![c2, c3]);
        assert!(
            !seen_docs.contains(&doc2),
            "doc2 objects are completely in base closure and must NOT be emitted"
        );

        let _ = std::fs::remove_file(&full_out);
        let _ = std::fs::remove_file(&incr_out);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_export_incremental_empty_delta() {
        use engine_core::repository::archive::{verify_archive_stream, ArchiveLimits};

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Genesis")]).await;
        let c1 = f.commit(&[], vec![("doc.docx", f1)], "Genesis").await;

        let empty_out = std::env::temp_dir().join(format!(
            "test-archive-empty-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&empty_out);

        run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: Some(c1.as_str().to_string()),
                out: empty_out.clone(),
            },
        )
        .await
        .unwrap();

        // Verify stream
        let file = std::fs::File::open(&empty_out).unwrap();
        let summary = verify_archive_stream(
            file,
            ArchiveLimits::default(),
            Some(&c1),
            Some(DocumentId(f.project)),
        )
        .unwrap();
        assert_eq!(summary.commits, 0);
        assert_eq!(summary.objects, 0);
        assert_eq!(summary.head, c1);
        assert_eq!(summary.since, Some(c1));

        let _ = std::fs::remove_file(&empty_out);
        f.finish().await;
    }

    #[tokio::test]
    async fn archive_export_incremental_disjoint_and_missing_since_fail_closed() {
        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());

        // Forking branches: c1 -> c2_a (branch A) and c1 -> c2_b (branch B)
        let f1 = f.file(doc1, &[(0, "Base")]).await;
        let c1 = f.commit(&[], vec![("doc.docx", f1)], "Genesis").await;

        let f2_a = f.file(doc1, &[(0, "Branch A")]).await;
        let c2_a = f.commit(&[&c1], vec![("doc.docx", f2_a)], "Branch A").await;

        let f2_b = f.file(doc1, &[(0, "Branch B")]).await;
        let c2_b = f.commit(&[&c1], vec![("doc.docx", f2_b)], "Branch B").await;

        // 1. Disjoint ancestry: c2_b is NOT a descendant of c2_a
        let disjoint_out = std::env::temp_dir().join(format!(
            "test-archive-disjoint-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&disjoint_out);

        let err1 = run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c2_b.as_str().to_string(),
                since: Some(c2_a.as_str().to_string()),
                out: disjoint_out.clone(),
            },
        )
        .await
        .unwrap_err();

        let err1_msg = format!("{err1:#}");
        assert!(
            err1_msg.contains("head is not a descendant of since"),
            "unexpected error message: {err1_msg}"
        );
        assert!(
            !disjoint_out.exists(),
            "incomplete output file must be removed on failure"
        );

        // 2. Missing since commit
        let missing_out = std::env::temp_dir().join(format!(
            "test-archive-missing-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&missing_out);

        let fake_since = "9999999999999999999999999999999999999999999999999999999999999999";
        let err2 = run(
            f.path.clone(),
            f.project,
            Action::ArchiveExport {
                head: c1.as_str().to_string(),
                since: Some(fake_since.to_string()),
                out: missing_out.clone(),
            },
        )
        .await
        .unwrap_err();

        let err2_msg = format!("{err2:#}");
        assert!(
            err2_msg.contains("since commit missing"),
            "unexpected error message: {err2_msg}"
        );
        assert!(
            !missing_out.exists(),
            "incomplete output file must be removed on failure"
        );

        f.finish().await;
    }

    #[tokio::test]
    async fn archive_preflight_rejects_invalid_typed_root_and_leaves_target_untouched() {
        use engine_core::repository::archive::ArchiveWriter;

        let project_id = uuid::Uuid::new_v4();
        let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let doc1 = DocumentId(uuid::Uuid::new_v4());

        // Create a real file to obtain a valid typed child node (which is a valid stored object
        // that passes validate_stored and references, but is NOT an Object::State root).
        let f_init = Fixture::with_project(project_id).await;
        let f1 = f_init.file(doc1, &[(0, "Hello world")]).await;
        let p_root = f_init
            .repo
            .object(&ObjectKey {
                document: doc1,
                address: f1.state.clone(),
            })
            .await
            .unwrap();
        let children =
            engine_core::shared_checkpoint::references(&f1.state, &p_root.bytes).unwrap();
        let child_addr = children[0].clone();
        let p_child = f_init
            .repo
            .object(&ObjectKey {
                document: doc1,
                address: child_addr.clone(),
            })
            .await
            .unwrap();
        f_init.finish().await;

        // Sign a commit referencing this child node (not a State root) as the file's state
        let mut files = BTreeMap::new();
        files.insert(
            "doc.docx".to_string(),
            engine_core::repository::FileEntry {
                document: doc1,
                state: child_addr.clone(),
            },
        );
        let commit = engine_core::repository::Commit {
            sealed: None,
            version: 1,
            project: project_id,
            parents: vec![],
            authored_at_ms: 1700000000000,
            author_key: String::new(),
            files,
            project_resolutions: Vec::new(),
            relocations: Vec::new(),
            merge_policy: None,
            same_file_resolutions: Vec::new(),
            recovery: None,
            message: "Commit with non-state typed root".into(),
        };
        let signed = SignedCommit::sign(commit, &key).unwrap();
        let head = signed.verify().unwrap();

        // Write a complete DYNOARC archive with valid footer
        let archive_path = std::env::temp_dir().join(format!(
            "test-preflight-invalid-typed-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut writer = ArchiveWriter::new(file).unwrap();
        writer
            .write_header(1, DocumentId(project_id), head.clone())
            .unwrap();
        writer
            .write_object(doc1, child_addr.clone(), &p_child.bytes)
            .unwrap();
        writer.write_commit(&signed).unwrap();
        writer.finish().unwrap();

        // 1. Standalone archive-verify MUST reject during semantic preflight
        let err_verify = super::super::archive_verify(
            archive_path.clone(),
            project_id,
            head.as_str().to_string(),
        )
        .await
        .unwrap_err();
        assert!(
            err_verify.to_string().contains("semantic preflight")
                || err_verify
                    .to_string()
                    .contains("archive verification failed")
        );

        // 2. Archive-import into an absent destination MUST fail AND leave absent target absent
        let absent_target =
            std::env::temp_dir().join(format!("test-absent-target-{}.db", uuid::Uuid::new_v4()));
        assert!(!absent_target.exists());

        let err_import = run(
            absent_target.clone(),
            project_id,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: head.as_str().to_string(),
            },
        )
        .await
        .unwrap_err();
        assert!(err_import.to_string().contains("archive validation failed"));
        assert!(
            !absent_target.exists(),
            "absent target must remain absent after preflight rejection"
        );

        // 3. Archive-import into an existing destination MUST leave existing target unchanged
        let f_existing = Fixture::with_project(project_id).await;
        let existing_inv_before = f_existing.repo.inventory(None, 10).await.unwrap();

        let err_import2 = run(
            f_existing.path.clone(),
            f_existing.project,
            Action::ArchiveImport {
                file: archive_path.clone(),
                expect_head: head.as_str().to_string(),
            },
        )
        .await
        .unwrap_err();
        assert!(err_import2
            .to_string()
            .contains("archive validation failed"));

        let existing_inv_after = f_existing.repo.inventory(None, 10).await.unwrap();
        assert_eq!(
            existing_inv_before, existing_inv_after,
            "existing target repository must remain completely unchanged"
        );

        let _ = std::fs::remove_file(&archive_path);
        f_existing.finish().await;
    }

    #[tokio::test]
    async fn archive_preflight_rejects_false_recovery_evidence() {
        use engine_core::repository::archive::ArchiveWriter;

        let f = Fixture::new().await;
        let doc1 = DocumentId(uuid::Uuid::new_v4());
        let f1 = f.file(doc1, &[(0, "Base")]).await;
        let c1 = f.commit(&[], vec![("doc.docx", f1.clone())], "Base").await;

        let f2 = f.file(doc1, &[(0, "Modified")]).await;
        let c2 = f
            .commit(&[&c1], vec![("doc.docx", f2.clone())], "Modified")
            .await;

        let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();

        // Sign a commit claiming to revert c2, but providing false/falsified file content
        let f_fake = f.file(doc1, &[(0, "False content")]).await;
        let commit = engine_core::repository::Commit {
            sealed: None,
            version: 2,
            project: f.project,
            parents: vec![c2.clone()],
            authored_at_ms: 1700000000000,
            author_key: String::new(),
            files: {
                let mut map = BTreeMap::new();
                map.insert("doc.docx".to_string(), f_fake.clone());
                map
            },
            project_resolutions: Vec::new(),
            relocations: Vec::new(),
            merge_policy: None,
            same_file_resolutions: Vec::new(),
            recovery: Some(engine_core::repository::recovery::Source {
                kind: engine_core::repository::recovery::Kind::Revert,
                commit: c2.clone(),
                mainline: None,
            }),
            message: "Commit with false recovery".into(),
        };
        let signed = SignedCommit::sign(commit, &key).unwrap();
        let head = signed.verify().unwrap();

        let archive_path = std::env::temp_dir().join(format!(
            "test-preflight-false-recovery-{}.dynoarc",
            uuid::Uuid::new_v4()
        ));
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut writer = ArchiveWriter::new(file).unwrap();
        writer
            .write_header(1, DocumentId(f.project), head.clone())
            .unwrap();

        // Write objects for f1, f2, and f_fake
        let p1 = f
            .repo
            .object(&ObjectKey {
                document: doc1,
                address: f1.state.clone(),
            })
            .await
            .unwrap();
        writer
            .write_object(doc1, f1.state.clone(), &p1.bytes)
            .unwrap();

        let p2 = f
            .repo
            .object(&ObjectKey {
                document: doc1,
                address: f2.state.clone(),
            })
            .await
            .unwrap();
        writer
            .write_object(doc1, f2.state.clone(), &p2.bytes)
            .unwrap();

        let p_fake = f
            .repo
            .object(&ObjectKey {
                document: doc1,
                address: f_fake.state.clone(),
            })
            .await
            .unwrap();
        writer
            .write_object(doc1, f_fake.state.clone(), &p_fake.bytes)
            .unwrap();

        let signed_c1 = f.repo.commit(&c1).await.unwrap();
        writer.write_commit(&signed_c1).unwrap();
        let signed_c2 = f.repo.commit(&c2).await.unwrap();
        writer.write_commit(&signed_c2).unwrap();
        writer.write_commit(&signed).unwrap();
        writer.finish().unwrap();

        let err = super::super::archive_verify(
            archive_path.clone(),
            f.project,
            head.as_str().to_string(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("semantic preflight")
                || err.to_string().contains("archive verification failed")
        );

        let _ = std::fs::remove_file(&archive_path);
        f.finish().await;
    }

    #[test]
    fn log_arguments_parse_and_validate() {
        let command = Action::augment_subcommands(Command::new("repository").no_binary_name(true));
        let parse = |args: &[&str]| {
            let matches = command.clone().try_get_matches_from(args).unwrap();
            Action::from_arg_matches(&matches).unwrap()
        };
        assert!(command.clone().try_get_matches_from(["log"]).is_err());
        assert!(matches!(
            parse(&["log", "abc"]),
            Action::Log {
                commit,
                limit: None,
                cursor: None,
                all: false,
                json: false
            } if commit == "abc"
        ));
        assert!(matches!(
            parse(&[
                "log",
                "abc",
                "--limit",
                "25",
                "--cursor",
                "def",
                "--all",
                "--json"
            ]),
            Action::Log {
                commit,
                limit: Some(25),
                cursor: Some(cur),
                all: true,
                json: true
            } if commit == "abc" && cur == "def"
        ));
    }

    #[tokio::test]
    async fn local_history_log_read_only_filesystem() {
        let f = Fixture::new().await;
        let doc = DocumentId(uuid::Uuid::new_v4());
        let f0 = f.file(doc, &[]).await;
        let c0 = f.commit(&[], vec![("a", f0)], "genesis").await;
        let f1 = f.file(doc, &[(0, "edit")]).await;
        let c1 = f.commit(&[&c0], vec![("a", f1)], "second").await;
        f.repo.close().await;

        let path = f.path.clone();
        let project = f.project;

        // Set file permissions to read-only (0o444)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }

        // Run log on read-only database
        run(
            path.clone(),
            project,
            Action::Log {
                commit: c1.as_str().to_string(),
                limit: None,
                cursor: None,
                all: false,
                json: true,
            },
        )
        .await
        .unwrap();

        // Restore write permissions before cleanup
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        remove_test_database(&path).await.unwrap();
    }

    #[tokio::test]
    async fn local_history_log_missing_database() {
        let missing =
            std::env::temp_dir().join(format!("dynodoc-missing-{}.sqlite", uuid::Uuid::new_v4()));
        let project = uuid::Uuid::new_v4();
        let err = run(
            missing.clone(),
            project,
            Action::Log {
                commit: "1".repeat(64),
                limit: None,
                cursor: None,
                all: false,
                json: true,
            },
        )
        .await;
        assert!(err.is_err());
        assert!(!missing.exists(), "missing database must never be created");
    }

    #[tokio::test]
    async fn local_history_log_schemas_1_2_3_fixtures() {
        let f = Fixture::new().await;
        let doc = DocumentId(uuid::Uuid::new_v4());
        let f0 = f.file(doc, &[]).await;
        let c0 = f.commit(&[], vec![("a", f0)], "c0").await;
        let path = f.path.clone();
        let project = f.project;
        f.repo.close().await;

        for schema_ver in [1i64, 2i64, 3i64] {
            // Update version in local_meta
            {
                let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
                    .await
                    .unwrap();
                sqlx::query("update local_meta set version=?")
                    .bind(schema_ver)
                    .execute(&pool)
                    .await
                    .unwrap();
                pool.close().await;
            }

            // Run Action::Log
            run(
                path.clone(),
                project,
                Action::Log {
                    commit: c0.as_str().to_string(),
                    limit: None,
                    cursor: None,
                    all: false,
                    json: true,
                },
            )
            .await
            .unwrap();

            // Verify version is unchanged (never auto-upgraded by read_only)
            {
                let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
                    .await
                    .unwrap();
                let ver: i64 = sqlx::query_scalar("select version from local_meta")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
                assert_eq!(ver, schema_ver, "schema version must not be upgraded");
                pool.close().await;
            }
        }

        // Schema 5 (unsupported; 4 is the horizon schema) must fail rather than proceed
        {
            let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
                .await
                .unwrap();
            sqlx::query("update local_meta set version=5")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }

        let err = run(
            path.clone(),
            project,
            Action::Log {
                commit: c0.as_str().to_string(),
                limit: None,
                cursor: None,
                all: false,
                json: true,
            },
        )
        .await;
        assert!(err.is_err(), "unsupported schema version must fail");

        remove_test_database(&path).await.unwrap();
    }

    #[tokio::test]
    async fn local_history_log_merge_recovery_and_cursor_validation() {
        let f = Fixture::new().await;
        let doc = DocumentId(uuid::Uuid::new_v4());
        let f0 = f.file(doc, &[]).await;
        let c0 = f.commit(&[], vec![("a", f0)], "c0 genesis").await;

        let f1a = f.file(doc, &[(0, "branch a")]).await;
        let c1a = f.commit(&[&c0], vec![("a", f1a)], "c1a mainline").await;

        let f1b = f.file(doc, &[(1, "branch b")]).await;
        let c1b = f.commit(&[&c0], vec![("a", f1b)], "c1b side branch").await;

        let f2 = f.file(doc, &[(0, "branch a"), (1, "branch b")]).await;
        let c2 = f
            .commit(&[&c1a, &c1b], vec![("a", f2.clone())], "c2 merge")
            .await;

        // Commit 3: recovery commit onto c2
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let plan = f
            .repo
            .plan_recovery(
                engine_core::repository::recovery::Kind::Revert,
                &c1b,
                &c2,
                None,
            )
            .await
            .unwrap();
        let resolutions: BTreeMap<String, Option<FileEntry>> = plan
            .changes
            .conflicts
            .iter()
            .map(|c| (c.path.clone(), Some(f2.clone())))
            .collect();
        let c3_commit = plan
            .resolve(&resolutions, 1_700_000_003_000, "c3 recovery".to_string())
            .unwrap();
        let c3 = f
            .repo
            .import_commit(&SignedCommit::sign(c3_commit, &key).unwrap())
            .await
            .unwrap();

        // 1. Full chain traversal follows first-parent spine: c3 -> c2 -> c1a -> c0
        let full = local_log(&f.repo, f.project, &c3, None, None, true)
            .await
            .unwrap();
        assert_eq!(full.head, c3);
        assert_eq!(full.entries.len(), 4);
        assert_eq!(full.entries[0].address, c3);
        assert_eq!(full.entries[1].address, c2);
        assert_eq!(full.entries[2].address, c1a);
        assert_eq!(full.entries[3].address, c0);
        // c1b is never visited on first-parent traversal
        assert!(!full.entries.iter().any(|e| e.address == c1b));

        // Format checks: c2 has 2 parents -> Merge: c1a c1b
        let text = format_local_log_text(&full);
        assert!(text.contains(&format!("Merge: {} {}", c1a.as_str(), c1b.as_str())));
        assert!(text.contains("Note: First-parent history is not an exhaustive DAG traversal or independent proof of completeness."));

        let json_val = format_local_log_json(&full).unwrap();
        assert_eq!(json_val["first_parent_history"], true);
        assert_eq!(json_val["entries"].as_array().unwrap().len(), 4);

        // 2. Single bounded page
        let page1 = local_log(&f.repo, f.project, &c3, Some(2), None, false)
            .await
            .unwrap();
        assert_eq!(page1.entries.len(), 2);
        assert_eq!(page1.entries[0].address, c3);
        assert_eq!(page1.entries[1].address, c2);
        assert!(page1.more);
        assert_eq!(page1.next_cursor.as_deref(), Some(c1a.as_str()));

        // 3. Continuation from valid cursor c1a
        let cont = local_log(&f.repo, f.project, &c3, Some(2), Some(&c1a), false)
            .await
            .unwrap();
        assert_eq!(cont.head, c3); // Head is the original commit requested
        assert_eq!(cont.entries.len(), 2);
        assert_eq!(cont.entries[0].address, c1a);
        assert_eq!(cont.entries[1].address, c0);
        assert!(!cont.more);
        assert_eq!(cont.next_cursor, None);

        // 4. Bad cursors:
        // a) Cursor equals head (loop)
        let err_loop = local_log(&f.repo, f.project, &c3, None, Some(&c3), false)
            .await
            .unwrap_err();
        assert!(err_loop.to_string().contains("cursor loop detected"));

        // b) Cursor on secondary branch c1b (not on first-parent chain)
        let err_side = local_log(&f.repo, f.project, &c3, None, Some(&c1b), false)
            .await
            .unwrap_err();
        assert!(err_side
            .to_string()
            .contains("continuation cursor is not on the first-parent chain"));

        // c) Nonexistent cursor
        let non_existent = Address::try_from("f".repeat(64)).unwrap();
        let err_none = local_log(&f.repo, f.project, &c3, None, Some(&non_existent), false)
            .await
            .unwrap_err();
        assert!(err_none
            .to_string()
            .contains("continuation cursor is not on the first-parent chain"));

        // 5. Database immutability: record snapshot, run action, verify unchanged
        let (path, project) = (f.path.clone(), f.project);
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let snapshot = || {
            (
                std::fs::read(&path).unwrap(),
                std::fs::read(&wal).unwrap_or_default(),
            )
        };
        let before = snapshot();
        run(
            path.clone(),
            project,
            Action::Log {
                commit: c3.as_str().to_string(),
                limit: Some(2),
                cursor: None,
                all: false,
                json: true,
            },
        )
        .await
        .unwrap();
        assert!(
            snapshot() == before,
            "log action must not mutate the database or WAL"
        );

        f.finish().await;
    }
}
