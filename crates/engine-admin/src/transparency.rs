//! `engine-admin transparency ...` (design section 4.8, decision 032): the log worker
//! and the anchor export for operators (owner credential, MIGRATION_DATABASE_URL).
//! Offline client verification commands (`verify-anchor`, `verify-bundle`,
//! `export-checkpoint`, `import-checkpoint`) live in the standalone `dynodoc` CLI.

use anyhow::{anyhow, ensure, Context};
use clap::Subcommand;
use engine_core::transparency::{
    witness::AddCheckpoint, KeyKind, Note, Origin, Signer, VerifierKey,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

#[derive(Subcommand)]
pub enum Action {
    /// Run the log worker (one leader at a time; owner credential). Integrates the
    /// outbox into the tile tree, signs a checkpoint with the log key, submits it to
    /// each witness with a consistency proof and stores the cosignatures; with
    /// --anchor also anchors each completed hour of document event-chain heads.
    LogWorker {
        /// Log key: unencrypted Ed25519 PKCS#8 DER, distinct from the receipt
        /// authority key (design 3.3). Its key name is the origin.
        #[arg(long)]
        key: PathBuf,
        /// `<host>/dynodoc/v1/transparency`, as DYNODOC_TRANSPARENCY_ORIGIN.
        #[arg(long)]
        origin: String,
        /// `https://witness.example/add-checkpoint=VKEY` (repeatable). HTTP only for
        /// loopback addresses.
        #[arg(long = "witness")]
        witnesses: Vec<String>,
        #[arg(long, default_value_t = 10)]
        interval_seconds: u64,
        #[arg(long)]
        anchor: bool,
        /// One pass, then exit.
        #[arg(long)]
        once: bool,
        /// Serve Prometheus text metrics of the log and of history pruning on this
        /// loopback address (for example 127.0.0.1:9464) while the worker runs.
        #[arg(long)]
        metrics: Option<std::net::SocketAddr>,
    },
    /// Rotate the log key (owner credential): integrate every pending leaf with the old
    /// key first, then this appends a log-successor leaf naming the old origin's last
    /// checkpoint and signs it with the new key under the new origin. Update
    /// DYNODOC_TRANSPARENCY_ORIGIN, restart the worker with the new key and register the
    /// new log with each witness (they bind origin and key).
    RotateLog {
        /// New log key (unencrypted Ed25519 PKCS#8 DER), named by the new origin.
        #[arg(long)]
        key: PathBuf,
        /// The new origin, for example `<host>/dynodoc/v2/transparency`.
        #[arg(long)]
        origin: String,
        /// Confirm that all pending outbox leaves were integrated and you want to append an
        /// irreversible successor leaf.
        #[arg(long)]
        confirm_rotate: bool,
        /// Inspect pending outbox leaf count without modifying the database.
        #[arg(long)]
        dry_run: bool,
    },
    /// Export the proof that a document's latest event of one anchored hour is
    /// committed by that hour's event-heads leaf (owner credential).
    AnchorProof {
        #[arg(long)]
        interval: i64,
        #[arg(long)]
        document: Uuid,
        /// New file; never overwrites.
        #[arg(long)]
        out: PathBuf,
    },
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct WitnessTarget {
    url: reqwest::Url,
    key: VerifierKey,
    /// The size this witness last cosigned, as far as the worker knows.
    size: u64,
    /// Set after a 403 or 422: stop submitting and alert (design 4.9).
    halted: bool,
}

fn parse_witness(spec: &str) -> anyhow::Result<WitnessTarget> {
    let (url, key) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("--witness is URL=VKEY"))?;
    let url = reqwest::Url::parse(url)?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "a witness URL must be HTTPS (HTTP only for loopback)"
    );
    let key = VerifierKey::parse(key).map_err(|e| anyhow!("witness key: {e}"))?;
    ensure!(
        key.kind() == KeyKind::Cosigner,
        "a witness key must be a cosignature key"
    );
    Ok(WitnessTarget {
        url,
        key,
        size: 0,
        halted: false,
    })
}

async fn submit(
    http: &reqwest::Client,
    pool: &sqlx::PgPool,
    target: &mut WitnessTarget,
    origin: &Origin,
    size: u64,
    note: &Note,
) -> anyhow::Result<()> {
    for _ in 0..2 {
        let old = target.size;
        let proof = if old == 0 || old >= size {
            Vec::new()
        } else {
            engine_api::transparency::consistency_proof(pool, origin, old, size).await?
        };
        let body = AddCheckpoint {
            old_size: old,
            proof,
            note: note.clone(),
        }
        .encode();
        let response = http.post(target.url.clone()).body(body).send().await?;
        let status = response.status().as_u16();
        let text = response.text().await?;
        match status {
            200 => {
                engine_api::transparency::add_cosignature(pool, size, &target.key, &text).await?;
                target.size = size;
                tracing::info!(witness = target.key.name(), size, "witness cosigned");
                return Ok(());
            }
            409 => {
                target.size = text.trim().parse().context("witness 409 without a size")?;
                ensure!(
                    target.size <= size,
                    "ALERT: witness {} holds a larger tree than the log",
                    target.key.name()
                );
            }
            403 | 422 => {
                target.halted = true;
                anyhow::bail!(
                    "ALERT: witness {} refused the checkpoint with {status}; submissions to it stop",
                    target.key.name()
                );
            }
            other => anyhow::bail!("witness {} answered {other}", target.key.name()),
        }
    }
    anyhow::bail!("witness {} kept answering 409", target.key.name())
}

pub async fn run(action: Action) -> anyhow::Result<()> {
    match action {
        Action::LogWorker {
            key,
            origin,
            witnesses,
            interval_seconds,
            anchor,
            once,
            metrics,
        } => {
            let origin = Origin::new(&origin).map_err(|e| anyhow!("origin: {e}"))?;
            let signer = Signer::from_pkcs8(
                origin.as_str(),
                KeyKind::Log,
                &crate::key_read::read_key_file(&key)?,
            )
            .map_err(|_| anyhow!("the log key must be an unencrypted Ed25519 PKCS#8 file"))?;
            println!("log verifier key: {}", signer.verifier_key());
            let mut targets = witnesses
                .iter()
                .map(|w| parse_witness(w))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let pool = crate::connect_migration().await?;
            if let Some(addr) = metrics {
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(error) = engine_api::metrics::serve(pool, addr).await {
                        tracing::error!(%error, "metrics endpoint stopped");
                    }
                });
            }
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?;
            loop {
                if anchor {
                    let hour = (now() / 3600) as i64 - 1;
                    let documents = engine_api::transparency::anchor_interval(&pool, hour).await?;
                    tracing::info!(interval = hour, documents, "event heads anchored");
                }
                match engine_api::transparency::integrate(&pool, &signer, &origin).await? {
                    Some(step) => {
                        tracing::info!(
                            size = step.size,
                            leaves = step.leaves,
                            old = step.old_size,
                            "checkpoint signed"
                        );
                        for target in targets.iter_mut().filter(|t| !t.halted) {
                            if let Err(error) =
                                submit(&http, &pool, target, &origin, step.size, &step.note).await
                            {
                                tracing::error!(witness = target.key.name(), %error, "witness submission failed");
                            }
                        }
                    }
                    None => tracing::debug!("outbox empty; no checkpoint"),
                }
                let (lag, age): (i64, Option<f64>) = sqlx::query_as(
                    "select (select count(*) from transparency_outbox o where not exists(select 1 from transparency_leaf l where l.outbox_seq=o.seq)),
                            (select extract(epoch from now()-max(created_at))::float8 from transparency_checkpoint)",
                )
                .fetch_one(&pool)
                .await?;
                tracing::info!(
                    outbox_lag = lag,
                    checkpoint_age_seconds = age,
                    "transparency log"
                );
                if once {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(interval_seconds.max(1))).await;
            }
            Ok(())
        }
        Action::RotateLog {
            key,
            origin,
            confirm_rotate,
            dry_run,
        } => {
            let origin = Origin::new(&origin).map_err(|e| anyhow!("origin: {e}"))?;
            let signer = Signer::from_pkcs8(
                origin.as_str(),
                KeyKind::Log,
                &crate::key_read::read_key_file(&key)?,
            )
            .map_err(|_| anyhow!("the log key must be an unencrypted Ed25519 PKCS#8 file"))?;
            let pool = crate::connect_migration().await?;
            let pending: i64 = sqlx::query_scalar(
                "select count(*) from transparency_outbox o where not exists(select 1 from transparency_leaf l where l.outbox_seq=o.seq)",
            )
            .fetch_one(&pool)
            .await
            .context("checking pending transparency outbox leaves")?;
            if dry_run {
                println!(
                    "{}",
                    json!({"dry_run": true, "origin": origin.as_str(), "verifier_key": signer.verifier_key().to_string(), "pending_outbox_leaves": pending})
                );
                return Ok(());
            }
            ensure!(
                pending == 0,
                "cannot rotate transparency log while {pending} outbox leaf/leaves remain pending; run `engine-admin transparency log-worker --once` with the old key first"
            );
            ensure!(
                confirm_rotate,
                "rotating the transparency log key appends an irreversible successor leaf; re-run with --confirm-rotate (or --dry-run to preview)"
            );
            let step = engine_api::transparency::rotate_log(&pool, &signer, &origin).await?;
            println!(
                "{}",
                json!({"origin": origin.as_str(), "verifier_key": signer.verifier_key().to_string(), "size": step.size, "successor_index": step.old_size})
            );
            Ok(())
        }
        Action::AnchorProof {
            interval,
            document,
            out,
        } => {
            let pool = crate::connect_migration().await?;
            let proof = engine_api::transparency::anchor_proof(&pool, interval, document).await?;
            write_new(&out, &serde_json::to_vec_pretty(&proof)?)?;
            println!(
                "{}",
                json!({"out": out.display().to_string(), "leaf_index": proof["leaf_index"]})
            );
            Ok(())
        }
    }
}
