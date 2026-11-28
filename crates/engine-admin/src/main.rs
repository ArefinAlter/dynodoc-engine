//! Dynodoc server and database operator CLI.
//!
//! - `migrate`, `grant-runtime`, `check-runtime`, `check-ordering` — PostgreSQL schema & role tools.
//! - `auth`, `kms`, `install-ref-authority`, `transparency`, `shared-object-gc`, `history-metrics` — operator services.
//! - `verify` (stage 14), `replay` (stage 15), `snapshot` (stage 15), `openapi` (stage 18).

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use engine_api::ApiDoc;
use engine_core::log;
use engine_core::materializer::Materializer;
use engine_core::merge_policy::{self, MergePolicy, Registry};
use engine_core::snapshot::{SnapshotEngine, SnapshotReason};
use engine_shared::DocumentId;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::io::Read;
use std::path::Path;
use utoipa::OpenApi;
use uuid::Uuid;

mod auth;
mod authority;
mod key_read;
mod kms;
mod transparency;

#[derive(Parser)]
#[command(
    name = "engine-admin",
    version,
    about = "Dynodoc server and database operator tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Customer-managed at-rest data keys (Phase 0; not end-to-end): create, rewrap after a
    /// KEK rotation, rotate, crypto-erase. Operator command (MIGRATION_DATABASE_URL).
    Kms(kms::Options),
    /// Operator-issued sign-in links, for an installation with no mail or with email sign-in off
    /// (owner credential: MIGRATION_DATABASE_URL). The link is a credential; see the subcommands.
    Auth {
        #[command(subcommand)]
        action: auth::Action,
    },
    /// Apply migrations using MIGRATION_DATABASE_URL in a separate operator process.
    Migrate,
    /// Give an existing restricted login the explicit runtime allowlist (operator only).
    GrantRuntime { role: String },
    /// Install the public receipt key using operator credentials; never replaces a key.
    InstallRefAuthority { public_key: String },
    /// Offline: dual-sign a receipt-authority rotation (or, with --recovery, sign a
    /// recorded break with the new key). Writes a new statement file; never overwrites.
    RotateRefAuthority(authority::Rotate),
    /// Append a dual-signed rotation using operator credentials. An exact retry is a no-op.
    InstallRefAuthorityRotation { statement: std::path::PathBuf },
    /// Append a recovery statement (operator credentials). Records a break that every
    /// client must re-pin explicitly; requires --confirm-break.
    InstallRefAuthorityRecovery {
        statement: std::path::PathBuf,
        #[arg(long)]
        confirm_break: bool,
    },
    /// Print the receipt-authority epochs, seal and revocation state. --out saves the
    /// state file `rotate-ref-authority` signs (created exclusively).
    ShowRefAuthority {
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Record a revocation marker for the active epoch (or --epoch). It stops receipt
    /// issuance at once and cannot be edited; recover with a new epoch.
    RevokeRefAuthority {
        #[arg(long)]
        reason: String,
        /// Best-known time of compromise or loss, RFC 3339 with a zone. Defaults to now.
        #[arg(long)]
        effective_at: Option<String>,
        #[arg(long)]
        epoch: Option<u32>,
        /// Required confirmation: repeat the epoch number being revoked.
        #[arg(long)]
        confirm_revoke_epoch: Option<u32>,
        /// Preview which epoch would be revoked without modifying the database.
        #[arg(long)]
        dry_run: bool,
    },
    /// Transparency log: log worker, log-key rotation and anchor export (owner credential).
    Transparency {
        #[command(subcommand)]
        action: transparency::Action,
    },
    /// Merge benchmark (decision 042): merge a generated, synthetic, deterministic corpus
    /// under a policy and print the timings as JSON. Numbers depend on the machine.
    MergeBench {
        #[arg(long, default_value_t = 1000)]
        cases: u64,
        /// Nodes per document.
        #[arg(long, default_value_t = 200)]
        nodes: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// A `dynodoc.merge-policy.v1` file; the default policy without one.
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
    },
    /// Serve Prometheus text metrics of the transparency log and history pruning on a
    /// loopback address (owner credential; nothing leaves the host).
    HistoryMetrics {
        #[arg(long, default_value = "127.0.0.1:9464")]
        listen: std::net::SocketAddr,
    },
    /// Physically delete one document's checkpoint objects that only released history
    /// reached (owner credential). Without --apply prints the plan and changes nothing;
    /// --apply PLAN_HASH deletes exactly that reviewed plan. Back up the database first.
    SharedObjectGc {
        document: Uuid,
        #[arg(long)]
        apply: Option<String>,
    },
    /// Check schema and runtime privileges using DATABASE_URL; makes no changes.
    CheckRuntime,
    /// Inspect database column collations and test SQL ordering parity with Rust byte order (read-only).
    ///
    /// Exit status:
    ///   0: all relational ID/position columns and synthetic string tests match Rust byte order
    ///   2: incompatible column collation or ordering mismatch detected
    ///   1: connection or database query error
    #[command(name = "check-ordering", alias = "ordering-audit")]
    CheckOrdering {
        /// Emit structured JSON report to standard output.
        #[arg(long)]
        json: bool,
    },
    /// Independently verify the event chain and all legacy snapshots.
    Verify {
        /// Document id (UUID).
        document_id: String,
        /// Also fail unless the verified chain passes through this head (hex), such as
        /// one recorded at an earlier check.
        #[arg(long)]
        expect_head: Option<String>,
    },
    /// Backfill legacy snapshot receipts by verified replay (schema 28). Atomic per document.
    VerifySnapshots {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        document_id: Option<String>,
        /// Visit every document in keyset order; stop at the first integrity error.
        #[arg(long)]
        all: bool,
    },
    /// Compare the node table with a verified replay (read-only); exits non-zero on an
    /// unexplained difference.
    VerifyProjection {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        document_id: Option<String>,
        /// Visit every document in keyset order and report every failing one.
        #[arg(long)]
        all: bool,
    },
    /// Replay a document's event log and print the materialized state.
    Replay {
        /// Document id (UUID).
        document_id: String,
    },
    /// Take a snapshot of a document's current state.
    Snapshot {
        /// Document id (UUID).
        document_id: String,
    },
    /// Publish an opt-in shared checkpoint at an exact event revision (schema 25).
    SharedSnapshot {
        document_id: String,
        #[arg(long)]
        through_seq: i64,
        /// Use typed chunked state objects (requires schema 30).
        #[arg(long)]
        typed: bool,
        /// Reuses unchanged components from an eligible earlier typed checkpoint (requires --typed).
        #[arg(long)]
        incremental: bool,
        /// Explicit codec selection (e.g. 'compact-v3').
        #[arg(long)]
        codec: Option<String>,
    },
    /// Read-only: check that a published shared checkpoint re-encodes as compact v3 and
    /// report the sizes. Checkpoints are immutable, so nothing is written.
    SharedReencodeCheck {
        document_id: String,
        #[arg(long)]
        through_seq: i64,
    },
    /// Emit the generated OpenAPI document. With `--out`, write it there; otherwise
    /// print to stdout. CI compares the committed `openapi.yaml` against `--out -` to
    /// fail on drift (see SETUP.md).
    Openapi {
        /// File to write the spec to (defaults to stdout).
        #[arg(long)]
        out: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match cli.command {
        Command::Kms(options) => kms::run(options, connect_migration().await?).await,
        Command::Auth { action } => auth::run(action).await,
        Command::Migrate => {
            let pool = connect_migration().await?;
            engine_core::database::MIGRATOR.run(&pool).await?;
            println!("Database migrations complete; provision/check the runtime role before starting the API.");
            Ok(())
        }
        Command::GrantRuntime { role } => {
            engine_core::database::grant_runtime(&connect_migration().await?, &role).await?;
            println!("Runtime grants verified for {role}; connect directly using its separate credentials.");
            Ok(())
        }
        Command::InstallRefAuthority { public_key } => {
            let id = engine_core::repository::server_authority::install(
                &connect_migration().await?,
                &public_key,
            )
            .await?;
            println!("Installed receipt authority {id}; distribute this identity and public key through a trusted channel.");
            Ok(())
        }
        Command::RotateRefAuthority(args) => authority::rotate(args),
        Command::InstallRefAuthorityRotation { statement } => {
            authority::install_rotation(&connect_migration().await?, &statement).await
        }
        Command::InstallRefAuthorityRecovery {
            statement,
            confirm_break,
        } => {
            authority::install_recovery(&connect_migration().await?, &statement, confirm_break)
                .await
        }
        Command::ShowRefAuthority { out } => {
            authority::show(&connect_migration().await?, out.as_deref()).await
        }
        Command::RevokeRefAuthority {
            reason,
            effective_at,
            epoch,
            confirm_revoke_epoch,
            dry_run,
        } => {
            authority::revoke(
                &connect_migration().await?,
                &reason,
                effective_at.as_deref(),
                epoch,
                confirm_revoke_epoch,
                dry_run,
            )
            .await
        }
        Command::Transparency { action } => transparency::run(action).await,
        Command::MergeBench {
            cases,
            nodes,
            seed,
            policy,
        } => {
            let policy = load_policy(policy.as_deref())?;
            let report = engine_core::merge_bench::run(seed, cases, nodes, &policy);
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::HistoryMetrics { listen } => {
            engine_api::metrics::serve(connect_migration().await?, listen).await
        }
        Command::SharedObjectGc { document, apply } => {
            let pool = connect_migration().await?;
            let plan = match apply {
                None => engine_api::object_collector::plan(&pool, document).await?,
                Some(hash) => engine_api::object_collector::apply(&pool, document, &hash).await?,
            };
            println!(
                "{}",
                serde_json::json!({"document":plan.document,"plan_hash":plan.plan_hash,"marked":plan.marked,"candidates":plan.candidates,"sweep_objects":plan.sweep_objects,"sweep_bytes":plan.sweep_bytes,"applied":plan.applied})
            );
            Ok(())
        }
        Command::CheckRuntime => {
            engine_core::database::check_runtime(&connect().await?).await?;
            println!("Runtime schema and database privileges verified.");
            Ok(())
        }
        Command::CheckOrdering { json } => check_ordering(json).await,
        Command::Verify {
            document_id,
            expect_head,
        } => verify(document_id, expect_head).await,
        Command::VerifySnapshots { document_id, all } => verify_snapshots(document_id, all).await,
        Command::VerifyProjection { document_id, all } => verify_projection(document_id, all).await,
        Command::Replay { document_id } => replay(document_id).await,
        Command::Snapshot { document_id } => snapshot(document_id).await,
        Command::SharedSnapshot {
            document_id,
            through_seq,
            typed,
            incremental,
            codec,
        } => shared_snapshot(document_id, through_seq, typed, incremental, codec).await,
        Command::SharedReencodeCheck {
            document_id,
            through_seq,
        } => shared_reencode_check(document_id, through_seq).await,
        Command::Openapi { out } => openapi(out),
    }
}

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

/// Emit the OpenAPI document generated from the annotated handlers. No DB needed.
fn openapi(out: Option<String>) -> anyhow::Result<()> {
    let yaml = ApiDoc::openapi()
        .to_yaml()
        .context("serializing the OpenAPI document to YAML failed")?;
    match out {
        Some(path) => {
            std::fs::write(&path, yaml).with_context(|| format!("writing {path} failed"))?;
            eprintln!("wrote OpenAPI spec to {path}");
        }
        None => print!("{yaml}"),
    }
    Ok(())
}

/// Parse the UUID argument into a `DocumentId`.
fn parse_document_id(document_id: &str) -> anyhow::Result<DocumentId> {
    Uuid::parse_str(document_id)
        .map(DocumentId)
        .with_context(|| format!("invalid document id (expected a UUID): {document_id}"))
}

/// Connect to Postgres from `DATABASE_URL`.
async fn connect() -> anyhow::Result<PgPool> {
    let database_url = std::env::var("DATABASE_URL").context(
        "DATABASE_URL is not set; binaries do not read .env files — run via Task (e.g. 'task db:check') or export DATABASE_URL (see docs/LOCAL-DEVELOPMENT.md)",
    )?;
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .context("could not connect to Postgres")
}

async fn connect_migration() -> anyhow::Result<PgPool> {
    let url = std::env::var("MIGRATION_DATABASE_URL").context(
        "MIGRATION_DATABASE_URL is required for this operator command (never pass it to engine-api); binaries do not read .env.migrate — run via Task (e.g. 'task migrate') or export MIGRATION_DATABASE_URL",
    )?;
    PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .context("could not connect for database administration")
}

async fn verify(document_id: String, expect_head: Option<String>) -> anyhow::Result<()> {
    let doc = parse_document_id(&document_id)?;
    let pool = connect().await?;

    let report = engine_core::snapshot_verification::verify_document(&pool, doc, false)
        .await
        .context("event/snapshot verification failed")?;
    // Event rows are immutable, so the verified head can be read after the check.
    let head: Vec<u8> =
        sqlx::query_scalar("select chain_hash from event where document_id=$1 and seq=$2")
            .bind(doc.0)
            .bind(report.through_seq)
            .fetch_optional(&pool)
            .await?
            .unwrap_or_else(|| log::ZERO_HASH.to_vec());
    println!("OK: event chain and {} legacy snapshots verified through seq {} for document {document_id}; head {}", report.snapshots, report.through_seq, to_hex(&head));
    if report.attributions > 0 {
        println!(
            "OK: {} sealed AI-agent authorship record(s) name every event of their merge",
            report.attributions
        );
    }
    if let Some(expected) = expect_head {
        let seq: Option<i64> = sqlx::query_scalar(
            "select seq from event where document_id=$1 and encode(chain_hash,'hex')=lower($2) and seq<=$3",
        )
        .bind(doc.0)
        .bind(expected.trim())
        .bind(report.through_seq)
        .fetch_optional(&pool)
        .await?;
        let Some(seq) = seq else {
            anyhow::bail!(
                "expected head {expected} is not in the verified chain; its head is {}",
                to_hex(&head)
            );
        };
        println!("OK: expected head is the chain hash at seq {seq}");
    }
    Ok(())
}

async fn verify_snapshots(document_id: Option<String>, all: bool) -> anyhow::Result<()> {
    let pool = connect().await?;
    let mut cursor: Option<Uuid> = None;
    loop {
        let document = if all {
            sqlx::query_scalar::<_, Uuid>(
                "select id from document where ($1::uuid is null or id>$1) order by id limit 1",
            )
            .bind(cursor)
            .fetch_optional(&pool)
            .await?
        } else {
            Some(parse_document_id(document_id.as_deref().context("document id required")?)?.0)
        };
        let Some(id) = document else {
            break;
        };
        let report =
            engine_core::snapshot_verification::verify_document(&pool, DocumentId(id), true)
                .await
                .with_context(|| {
                    format!(
                        "snapshot backfill failed for document {id}; its receipts were rolled back"
                    )
                })?;
        println!(
            "OK: document {id}; {} snapshots; {} replayed events; through seq {}",
            report.snapshots, report.replayed_events, report.through_seq
        );
        if !all {
            break;
        }
        cursor = Some(id);
    }
    Ok(())
}

async fn verify_projection(document_id: Option<String>, all: bool) -> anyhow::Result<()> {
    let pool = connect().await?;
    let mut cursor: Option<Uuid> = None;
    let mut failed = 0usize;
    loop {
        let document = if all {
            sqlx::query_scalar::<_, Uuid>(
                "select id from document where ($1::uuid is null or id>$1) order by id limit 1",
            )
            .bind(cursor)
            .fetch_optional(&pool)
            .await?
        } else {
            Some(parse_document_id(document_id.as_deref().context("document id required")?)?.0)
        };
        let Some(id) = document else {
            break;
        };
        match engine_core::projection::verify_projection(&pool, DocumentId(id)).await {
            Err(err) => {
                failed += 1;
                println!("FAIL: document {id}: {err}");
            }
            Ok(report) => {
                for d in &report.differences {
                    let status = d
                        .known
                        .map_or("DIFF".to_string(), |why| format!("KNOWN ({why})"));
                    println!(
                        "{status}: document {id} node {} {}: replay={} table={}",
                        d.node_id.0, d.field, d.replayed, d.stored
                    );
                }
                let unexplained = report.unexplained().count();
                let known = report.differences.len() - unexplained;
                let verdict = if unexplained > 0 { "FAIL" } else { "OK" };
                failed += usize::from(unexplained > 0);
                println!(
                    "{verdict}: document {id}; {} rows; {unexplained} unexplained, {known} known difference(s); through seq {}",
                    report.stored_rows, report.through_seq
                );
            }
        }
        if !all {
            break;
        }
        cursor = Some(id);
    }
    if failed > 0 {
        anyhow::bail!("{failed} document(s) failed the projection check");
    }
    Ok(())
}

async fn replay(document_id: String) -> anyhow::Result<()> {
    let doc = parse_document_id(&document_id)?;
    let pool = connect().await?;

    // A true replay folds the whole log from genesis (snapshot_seq 0 = no snapshot).
    let events = log::read_since_snapshot(&pool, doc, 0)
        .await
        .context("reading the event log failed")?;
    let state = Materializer::fold(&events).context("folding the event log failed")?;

    println!(
        "replayed {} event(s) for document {document_id}",
        events.len()
    );
    println!("{}", serde_json::to_string_pretty(&state)?);
    Ok(())
}

async fn snapshot(document_id: String) -> anyhow::Result<()> {
    let doc = parse_document_id(&document_id)?;
    let pool = connect().await?;

    let snapshot = SnapshotEngine::new(pool)
        .take(doc, SnapshotReason::Periodic)
        .await
        .context("taking a snapshot failed")?;

    println!(
        "snapshot {} taken for document {document_id}",
        snapshot.id.0
    );
    println!("  through_seq:  {}", snapshot.through_seq);
    println!("  merkle_root:  {}", to_hex(&snapshot.merkle_root));
    println!("  chain_hash:   {}", to_hex(&snapshot.event_chain_hash));
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

async fn shared_snapshot(
    document_id: String,
    through_seq: i64,
    typed: bool,
    incremental: bool,
    codec_arg: Option<String>,
) -> anyhow::Result<()> {
    if let Some(ref c) = codec_arg {
        if c != "compact-v3" {
            anyhow::bail!("unsupported codec '{c}', expected 'compact-v3'");
        }
        if typed {
            anyhow::bail!("--codec {c} cannot be combined with --typed");
        }
    } else if incremental && !typed {
        anyhow::bail!("--incremental requires --typed");
    }

    if through_seq < 0 {
        anyhow::bail!("through_seq must be non-negative");
    }

    let doc = parse_document_id(&document_id)?;
    let pool = connect().await?;

    if incremental {
        let is_v3 = matches!(codec_arg.as_deref(), Some("compact-v3"));
        let result = if is_v3 {
            engine_core::shared_checkpoint::postgres::take_incremental_v3(
                &pool,
                doc,
                through_seq,
                engine_core::shared_checkpoint::Limits::default(),
            )
            .await
            .context("publishing shared checkpoint failed")?
        } else {
            engine_core::shared_checkpoint::postgres::take_incremental(
                &pool,
                doc,
                through_seq,
                engine_core::shared_checkpoint::Limits::default(),
            )
            .await
            .context("publishing shared checkpoint failed")?
        };

        let codec_name = if is_v3 { "V3" } else { "V2" };
        println!(
            "shared checkpoint {codec_name} (incremental) at revision {}: {}",
            result.through_seq,
            result.root.as_str()
        );
        match result.base_seq {
            Some(base) => println!("selected base: revision {base}"),
            None => println!("selected base: none"),
        }
        println!("fallback ran: {}", result.fallback_ran);
        println!(
            "encoded objects: {}; encoded bytes: {}",
            result.stats.visited_objects, result.stats.encoded_bytes
        );
        println!(
            "new objects: {}; new canonical bytes: {}",
            result.stats.new_objects, result.stats.new_bytes
        );
        println!(
            "read queries: {}; write queries: {}",
            result.object_read_queries, result.object_write_queries
        );
        return Ok(());
    }

    use engine_core::shared_checkpoint::postgres::Codec;
    let codec = match codec_arg.as_deref() {
        Some("compact-v3") => Codec::V3,
        _ if typed => Codec::V2,
        _ => Codec::V1,
    };
    let result = engine_core::shared_checkpoint::postgres::take_with_codec(
        &pool,
        doc,
        through_seq,
        engine_core::shared_checkpoint::Limits::default(),
        codec,
    )
    .await
    .context("publishing shared checkpoint failed")?;
    println!(
        "shared checkpoint {codec:?} at revision {}: {}",
        result.through_seq,
        result.root.as_str()
    );
    println!(
        "encoded objects: {}; encoded bytes: {}",
        result.stats.visited_objects, result.stats.encoded_bytes
    );
    println!(
        "new objects: {}; new canonical bytes: {}",
        result.stats.new_objects, result.stats.new_bytes
    );
    Ok(())
}

async fn shared_reencode_check(document_id: String, through_seq: i64) -> anyhow::Result<()> {
    let doc = parse_document_id(&document_id)?;
    let pool = connect().await?;
    let check = engine_core::shared_checkpoint::postgres::reencode_check(
        &pool,
        doc,
        through_seq,
        engine_core::shared_checkpoint::Limits::default(),
    )
    .await
    .context("compact v3 re-encode check failed")?;
    println!(
        "shared checkpoint at revision {through_seq}: codec {}, root {}",
        check.codec_version,
        check.source_root.as_str()
    );
    println!("compact v3 root: {}", check.v3_root.as_str());
    println!(
        "compact v3: {} objects, {} encoded bytes; typed v2: {} objects, {} encoded bytes",
        check.v3.visited_objects,
        check.v3.encoded_bytes,
        check.v2.visited_objects,
        check.v2.encoded_bytes
    );
    println!("state matches event replay and decodes identical; nothing was written");
    Ok(())
}

async fn check_ordering(json: bool) -> anyhow::Result<()> {
    let pool = connect().await?;
    let report = engine_core::database::ordering::audit_ordering(&pool).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_ordering_report(&report);
    }
    if !report.compatible {
        std::process::exit(2);
    }
    Ok(())
}

fn print_ordering_report(report: &engine_core::database::ordering::OrderingAuditReport) {
    println!(
        "Database: {} (collation: {}, ctype: {}, provider: {})",
        report.database.datname,
        report.database.datcollate,
        report.database.datctype,
        report.database.datlocprovider
    );
    let db_byte_order = if report.database.is_byte_order_default {
        "YES"
    } else {
        "NO"
    };
    println!("Database default byte-order collation: {db_byte_order}");
    println!();
    println!(
        "Column Collation Inventory ({} columns):",
        report.columns.len()
    );
    for col in &report.columns {
        let status = if col.is_byte_order {
            "OK"
        } else {
            "INCOMPATIBLE"
        };
        println!(
            "  [{status}] {}.{} ({}, effective: {})",
            col.table_name, col.column_name, col.data_type, col.effective_collation
        );
    }
    if !report.foreign_keys.is_empty() {
        println!();
        println!(
            "Foreign Key References ({} constraints):",
            report.foreign_keys.len()
        );
        for fk in &report.foreign_keys {
            println!(
                "  {}: {}({}) -> {}({})",
                fk.constraint_name,
                fk.source_table,
                fk.source_column,
                fk.target_table,
                fk.target_column
            );
        }
    }
    println!();
    println!(
        "Synthetic Ordering Parity Checks ({} categories):",
        report.comparisons.len()
    );
    for cmp in &report.comparisons {
        let status = if cmp.matches { "OK" } else { "MISMATCH" };
        print!("  [{status}] {}: {} item(s)", cmp.category, cmp.count);
        if let Some((sql_val, rust_val)) = &cmp.first_mismatch {
            print!(" (first mismatch: SQL={sql_val:?}, Rust={rust_val:?})");
        }
        println!();
    }
    println!();
    if report.compatible {
        println!("Result: OK — all columns and synthetic strings match Rust byte order.");
    } else {
        println!(
            "Result: MISMATCH — {} incompatible column(s), {} ordering mismatch(es) detected.",
            report.incompatible_columns.len(),
            report.ordering_mismatches
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn operator_subcommands_parse_cleanly() {
        Cli::command().debug_assert();
        assert!(matches!(
            Cli::try_parse_from(["engine-admin", "migrate"])
                .unwrap()
                .command,
            Command::Migrate
        ));
        assert!(matches!(
            Cli::try_parse_from(["engine-admin", "openapi", "--out", "openapi.yaml"])
                .unwrap()
                .command,
            Command::Openapi { out: Some(_) }
        ));
    }
}
