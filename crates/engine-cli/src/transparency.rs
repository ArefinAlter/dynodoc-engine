//! `engine-cli transparency ...` (design section 4.8, decision 032): the log worker
//! and the anchor export for operators (owner credential, MIGRATION_DATABASE_URL),
//! and offline verbs for clients and auditors (a trust policy and a journal).
use anyhow::{anyhow, ensure, Context};
use clap::Subcommand;
use engine_core::{
    repository::receipt_journal::ReceiptJournal,
    transparency::{
        anchor, assess, witness::AddCheckpoint, InclusionBundle, KeyKind, Leaf, Level, NoProofs,
        Note, Origin, Policy, Signer, VerifierKey,
    },
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
    /// Offline auditor check: the head proof folds to the anchor root, the inclusion
    /// bundle carries exactly that event-heads leaf, and the bundle's checkpoint
    /// verifies under the policy. Compare `chain_hash` with `engine-cli verify`.
    VerifyAnchor {
        proof: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Offline: the assurance level of an inclusion bundle under a policy and the
    /// journal's checkpoints; records the checkpoint when it reaches L2.
    VerifyBundle {
        bundle: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        journal: PathBuf,
        /// Exit non-zero below this level.
        #[arg(long, value_enum)]
        require: Option<crate::sync::RequiredLevel>,
    },
    /// Write the newest checkpoint the journal holds for --origin (air-gapped exchange).
    ExportCheckpoint {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        origin: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Import a cosigned checkpoint from a file: recorded only when it verifies under
    /// the policy with a fresh quorum and agrees with every size already recorded.
    ImportCheckpoint {
        file: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        journal: PathBuf,
    },
}

fn read(path: &Path, cap: usize) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
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

fn policy(path: &Path) -> anyhow::Result<Policy> {
    Policy::from_json(&read(path, 64 * 1024)?).map_err(|e| anyhow!("trust policy: {e}"))
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
                anyhow::bail!("ALERT: witness {} refused the checkpoint with {status}; submissions to it stop", target.key.name());
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
                &crate::signing::read_key_file(&key)?,
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
        Action::RotateLog { key, origin } => {
            let origin = Origin::new(&origin).map_err(|e| anyhow!("origin: {e}"))?;
            let signer = Signer::from_pkcs8(
                origin.as_str(),
                KeyKind::Log,
                &crate::signing::read_key_file(&key)?,
            )
            .map_err(|_| anyhow!("the log key must be an unencrypted Ed25519 PKCS#8 file"))?;
            let pool = crate::connect_migration().await?;
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
        Action::VerifyAnchor {
            proof,
            bundle,
            policy: path,
        } => {
            let value: serde_json::Value = serde_json::from_slice(&read(&proof, 1024 * 1024)?)?;
            let head: anchor::HeadProof = serde_json::from_value(value["proof"].clone())?;
            let root: [u8; 32] = hex::decode(value["root"].as_str().unwrap_or_default())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| anyhow!("proof root"))?;
            let interval = value["interval"]
                .as_u64()
                .ok_or_else(|| anyhow!("proof interval"))?;
            anchor::verify(&head, &root).map_err(|e| anyhow!("head proof: {e}"))?;
            let bundle = InclusionBundle::from_json(&read(&bundle, 256 * 1024)?)?;
            let expected = Leaf::EventHeads {
                root,
                count: head.count,
                interval,
            };
            let policy = policy(&path)?;
            let known = engine_core::transparency::KnownCheckpoints::new(policy.origin());
            let assessment = assess(&policy, &bundle, Some(&expected), &known, &NoProofs, now());
            if let Some(rejection) = assessment.rejection {
                anyhow::bail!("bundle refused: {rejection}");
            }
            println!(
                "{}",
                json!({"verified": true, "level": assessment.level.to_string(), "seq": head.head.seq, "chain_hash": hex::encode(head.head.chain_hash)})
            );
            Ok(())
        }
        Action::VerifyBundle {
            bundle,
            policy: path,
            journal,
            require,
        } => {
            let policy = policy(&path)?;
            let bytes = read(&bundle, 256 * 1024)?;
            let bundle = InclusionBundle::from_json(&bytes)?;
            let journal = ReceiptJournal::open(&journal).await?;
            let known = journal.known_checkpoints(&policy).await?;
            let assessment = assess(&policy, &bundle, None, &known, &NoProofs, now());
            if let (None, Some(checkpoint)) =
                (&assessment.rejection, assessment.trusted_checkpoint())
            {
                journal
                    .record_checkpoint(checkpoint, &Note::parse(bundle.checkpoint.as_bytes())?)
                    .await?;
            }
            journal.close().await;
            println!(
                "{}",
                json!({
                    "level": assessment.level.to_string(),
                    "rejection": assessment.rejection.as_ref().map(ToString::to_string),
                    "limits": assessment.limits.iter().map(|l| format!("{l:?}")).collect::<Vec<_>>(),
                })
            );
            if let Some(rejection) = assessment.rejection {
                anyhow::bail!("bundle refused: {rejection}");
            }
            if let Some(required) = require {
                ensure!(
                    assessment.level >= Level::from(required),
                    "below the required level"
                );
            }
            Ok(())
        }
        Action::ExportCheckpoint {
            journal,
            origin,
            out,
        } => {
            let journal = ReceiptJournal::open(&journal).await?;
            let note = journal.latest_checkpoint(&origin).await?;
            journal.close().await;
            let note =
                note.ok_or_else(|| anyhow!("the journal holds no checkpoint of that log"))?;
            write_new(&out, note.encode().as_bytes())?;
            Ok(())
        }
        Action::ImportCheckpoint {
            file,
            policy: path,
            journal,
        } => {
            let policy = policy(&path)?;
            let note = Note::parse(&read(&file, 64 * 1024)?)?;
            let verified = policy.verify_checkpoint(&note)?;
            ensure!(
                policy.meets_quorum(&verified, now()),
                "the checkpoint lacks a fresh witness quorum under this policy"
            );
            let journal = ReceiptJournal::open(&journal).await?;
            let result = journal.record_checkpoint(&verified, &note).await;
            journal.close().await;
            result?;
            println!("{}", json!({"imported_size": verified.checkpoint().size}));
            Ok(())
        }
    }
}
