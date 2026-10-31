//! Explicit local repository commands. These never contact a remote server or
//! apply content to a native editor. Signing keys are supplied by the operator.
use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Subcommand, ValueEnum};
use engine_core::{
    merge_policy::{self, MergePolicy, Registry},
    repository::{
        convergence::FileExplain,
        horizon::{
            plan::PlanOptions,
            policy::{LoadOptions, Policy, MAX_POLICY_BYTES},
        },
        local::{
            CompactOptions, GcApplyOptions, GcPlanOptions, LocalRepository, ObjectKey,
            ObjectPacket, StorageLimits, SCHEMA_VERSION,
        },
        project_merge::SameFile,
        recovery, Commit, FileEntry, Head, SignedCommit,
    },
    shared_checkpoint::Address,
};
use engine_shared::DocumentId;
use ring::signature::Ed25519KeyPair;
use std::{
    collections::BTreeMap,
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
        /// built-in `dynodoc.default.v1`. A preview only: `merge` always uses the
        /// default policy, because a signed commit cannot yet record another.
        #[arg(long, requires = "explain")]
        merge_policy: Option<PathBuf>,
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
fn load_policy(path: Option<&Path>) -> anyhow::Result<MergePolicy> {
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
    key: &Ed25519KeyPair,
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

pub async fn run(path: PathBuf, project: uuid::Uuid, action: Action) -> anyhow::Result<()> {
    // The retention, horizon plans, archive export/verify, and export-file must not create, upgrade or write the database.
    let repo = if matches!(
        action,
        Action::GcPlan { .. }
            | Action::HorizonPlan { .. }
            | Action::ArchiveExport { .. }
            | Action::ArchiveVerify { .. }
            | Action::ExportFile { .. }
    ) {
        LocalRepository::open_read_only(&path, project).await?
    } else {
        // A destructive command never creates the database it would collect.
        if matches!(action, Action::Gc { .. }) {
            anyhow::ensure!(
                path.is_file(),
                "no repository database at {}",
                path.display()
            );
        }
        LocalRepository::open(&path, project).await?
    };
    let address = |s: String| Address::try_from(s);
    let mut text = None;
    let mut vacuum_failure = None;
    let output = match action {
        Action::Init => serde_json::json!({"project":project,"local_schema":SCHEMA_VERSION}),
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
        Action::ArchiveExport { head, out } => {
            let head_addr = address(head)?;
            anyhow::ensure!(
                !out.exists(),
                "output file {} already exists; refusing overwrite",
                out.display()
            );

            let file = engine_core::repository::private_fs::create_private_file(&out)
                .with_context(|| format!("creating output archive at {}", out.display()))?;

            let guard = engine_core::repository::private_fs::AutoRemoveFile::new(out.clone());

            let summary = engine_core::repository::archive::export_archive(
                &repo,
                &head_addr,
                file,
                engine_core::repository::archive::ArchiveLimits::default(),
            )
            .await
            .context("archive export failed")?;

            guard.commit();

            serde_json::json!({
                "out": out.display().to_string(),
                "head": summary.head,
                "objects": summary.objects,
                "commits": summary.commits,
                "bytes": summary.total_bytes,
                "bytes_before_footer": summary.bytes_before_footer,
                "sha256": summary.sha256,
            })
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
            .map_err(|e| anyhow::anyhow!("archive validation failed: {e}"))?;

            let summary = engine_core::repository::archive::import_archive(&repo, &staged)
                .await
                .map_err(|e| anyhow::anyhow!("archive import failed: {e}"))?;

            serde_json::json!({
                "file": file.display().to_string(),
                "head": summary.head,
                "objects_imported": summary.objects_imported,
                "commits_imported": summary.commits_imported,
                "total_objects": summary.total_objects,
                "total_commits": summary.total_commits,
            })
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
            .map_err(|e| anyhow::anyhow!("archive verification failed: {e}"))?;

            serde_json::json!({
                "file": file.display().to_string(),
                "head": summary.head,
                "project": summary.project.0,
                "objects": summary.objects,
                "commits": summary.commits,
                "bytes_before_footer": summary.bytes_before_footer,
                "total_bytes": summary.total_bytes,
                "sha256": summary.sha256,
            })
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

            let file_entry = signed
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
            let commit: Commit = read_json(&manifest, engine_core::repository::MAX_COMMIT_BYTES)?;
            let key = crate::signing::load(&key)?;
            let signed = SignedCommit::sign(commit, &key)?;
            serde_json::json!({"commit":repo.import_commit(&signed).await?})
        }
        Action::ImportCommit { input } => {
            serde_json::json!({"commit":repo.import_commit(&read_json(&input, engine_core::repository::MAX_COMMIT_BYTES + 1024)?).await?})
        }
        Action::Show { commit } => serde_json::to_value(repo.commit(&address(commit)?).await?)?,
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
                _ => anyhow::bail!("expected address and generation must be supplied together"),
            };
            serde_json::to_value(
                repo.compare_and_swap(&branch, expected.as_ref(), &address(commit)?)
                    .await?,
            )?
        }
        Action::MergeBases { left, right } => {
            serde_json::to_value(repo.merge_bases(&address(left)?, &address(right)?).await?)?
        }
        Action::Compare {
            base,
            left,
            right,
            explain,
            merge_policy,
        } => {
            let policy = explain
                .then(|| load_policy(merge_policy.as_deref()))
                .transpose()?;
            compare_explained(
                &repo,
                address(base)?,
                address(left)?,
                address(right)?,
                policy.as_ref(),
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
        } => {
            let resolutions = match resolutions {
                Some(path) => read_json(&path, engine_core::repository::MAX_COMMIT_BYTES)?,
                None => BTreeMap::new(),
            };
            // Load the key before anything is stored.
            let key = crate::signing::load(&key)?;
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
            merge_value(&repo, args, &key).await?
        }
        Action::VerifyMerge { commit, explain } => {
            let commit = address(commit)?;
            let verified = repo.verify_same_file_resolutions(&commit).await?;
            let mut output =
                serde_json::json!({"commit":commit,"verified_same_file_resolutions":verified});
            if explain {
                let policy = merge_policy::default::policy();
                let records = repo.commit(&commit).await?.commit.same_file_resolutions;
                output["explain"] =
                    explain_value(policy, repo.explain_resolutions(&records, policy).await?)?;
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
            let signed = SignedCommit::sign(commit, &crate::signing::load(&key)?)?;
            serde_json::json!({"commit":repo.import_commit(&signed).await?,"recovery":signed.commit.recovery,"parents":signed.commit.parents})
        }
    };
    repo.close().await;
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
        // The commit-producing merge takes no policy: a v3 commit records only the
        // default strategy.
        let mut with_policy = base.to_vec();
        with_policy.extend(["--merge-policy", "p.json"]);
        assert!(command.clone().try_get_matches_from(with_policy).is_err());
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
}
