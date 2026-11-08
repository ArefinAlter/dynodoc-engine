//! Transparency and horizons in `sync` (designs: witnesses section 4.10, pruning
//! phase P4; decision 032). Without `--transparency-policy` nothing here runs and
//! sync behaves as before.
use super::http::Client;
use anyhow::{anyhow, ensure, Context};
use clap::ValueEnum;
use engine_core::{
    repository::{
        attestation::{Scope, SignedReceipt},
        horizon::{Envelope, SkeletonEntry},
        local::LocalRepository,
        receipt_journal::ReceiptJournal,
    },
    shared_checkpoint::Address,
    transparency::{
        assess, merkle::verify_consistency, monitor, tiles::entry_bundle_path, ConsistencySource,
        Hash, InclusionBundle, Leaf, Level, Note, Policy, TagKey,
    },
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RequiredLevel {
    L1,
    L2,
    L3,
}

impl From<RequiredLevel> for Level {
    fn from(level: RequiredLevel) -> Self {
        match level {
            RequiredLevel::L1 => Level::L1,
            RequiredLevel::L2 => Level::L2,
            RequiredLevel::L3 => Level::L3,
        }
    }
}

pub fn load_policy(path: &Path) -> anyhow::Result<Policy> {
    Policy::from_json(&super::read(path, 64 * 1024)?)
        .map_err(|e| anyhow!("transparency policy {}: {e}", path.display()))
}

#[derive(Deserialize)]
struct KeyInfo {
    origin: String,
    origin_hash: String,
    key: Option<String>,
    checkpoint: Option<String>,
}

fn raw(address: &Address) -> anyhow::Result<Hash> {
    hex32(address.as_str())
}

fn hex32(text: &str) -> anyhow::Result<Hash> {
    let mut out = [0u8; 32];
    ensure!(text.len() == 64, "expected 64 hex digits");
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

/// A consistency proof fetched before the (synchronous) assessment.
struct Prefetched(Option<(u64, u64, Vec<Hash>)>);

impl ConsistencySource for Prefetched {
    fn consistency_proof(&self, first: u64, second: u64) -> Option<Vec<Hash>> {
        self.0
            .as_ref()
            .filter(|(a, b, _)| *a == first && *b == second)
            .map(|(_, _, proof)| proof.clone())
    }
}

async fn consistency(client: &Client, first: u64, second: u64) -> anyhow::Result<Vec<Hash>> {
    #[derive(Deserialize)]
    struct Proof {
        proof: Vec<String>,
    }
    let proof: Proof = client
        .get(
            "history/transparency/consistency",
            &[("first", first.to_string()), ("second", second.to_string())],
            64 * 1024,
        )
        .await?;
    proof.proof.iter().map(|h| hex32(h)).collect()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The assurance level of `receipt`: inclusion in a checkpoint of the policy's log
/// (L1), a fresh witness quorum (L2), consistency with the newest checkpoint this
/// journal holds (L3). A checkpoint at L2 or better is remembered; the inclusion is
/// kept. A rejection (fork, split view, wrong leaf) is an error, never a level.
pub async fn check_receipt(
    client: &Client,
    journal: &ReceiptJournal,
    scope: &Scope,
    receipt: &SignedReceipt,
    policy: &Policy,
) -> anyhow::Result<Value> {
    let address = receipt.verify()?;
    let info: KeyInfo = client
        .get("history/transparency-key", &[], 128 * 1024)
        .await?;
    ensure!(
        info.origin == policy.origin().as_str(),
        "the remote's log origin differs from the trust policy"
    );
    let Some(bundle) = client
        .get_optional::<Value>(
            "history/transparency/inclusion",
            &[("subject", address.as_str().to_owned())],
            256 * 1024,
        )
        .await?
    else {
        return Ok(json!({"level":"L0","inclusion":"pending"}));
    };
    let bundle = InclusionBundle::from_json(&serde_json::to_vec(&bundle)?)?;
    let expected = match &info.key {
        Some(key) => Some(Leaf::RefReceipt {
            tag: TagKey::new(hex32(key)?)
                .ref_tag(&scope.branch, receipt.receipt.head.generation as u64),
            receipt: raw(&address)?,
        }),
        None => None,
    };
    let known = journal.known_checkpoints(policy).await?;
    let proofs = match known.latest() {
        Some((size, _)) if size != bundle.size => {
            let (first, second) = (size.min(bundle.size), size.max(bundle.size));
            Prefetched(Some((
                first,
                second,
                consistency(client, first, second).await?,
            )))
        }
        _ => Prefetched(None),
    };
    let assessment = assess(policy, &bundle, expected.as_ref(), &known, &proofs, now());
    if let Some(rejection) = &assessment.rejection {
        anyhow::bail!("transparency check refused the head receipt: {rejection}");
    }
    if let Some(checkpoint) = assessment.trusted_checkpoint() {
        journal
            .record_checkpoint(checkpoint, &Note::parse(bundle.checkpoint.as_bytes())?)
            .await?;
        journal
            .record_inclusion(&address, policy.origin().as_str(), &bundle)
            .await?;
    }
    Ok(json!({
        "level": assessment.level.to_string(),
        "limits": assessment.limits.iter().map(|l| format!("{l:?}")).collect::<Vec<_>>(),
        "index": bundle.index,
        "size": bundle.size,
    }))
}

/// Fetch the remote's horizon chain, verify it against the pinned authority and the
/// journal's accepted chain, and store each horizon's verified skeleton in the
/// repository so a shallow replica can import retained history above it.
pub async fn horizons(
    repo: &LocalRepository,
    client: &Client,
    journal: &ReceiptJournal,
) -> anyhow::Result<Value> {
    #[derive(Deserialize)]
    struct Item {
        sequence: u64,
        envelope: Value,
        policy: Value,
    }
    #[derive(Deserialize)]
    struct Page<T> {
        items: Vec<T>,
    }
    let server = client.server().await?;
    let mut chain: Vec<(Envelope, Vec<u8>)> = Vec::new();
    loop {
        let after = chain.len().to_string();
        let page: Page<Item> = client
            .get(
                "history/horizons",
                &[("after_sequence", after), ("limit", "64".into())],
                16 * 1024 * 1024,
            )
            .await?;
        if page.items.is_empty() {
            break;
        }
        for item in page.items {
            ensure!(
                item.sequence == chain.len() as u64 + 1,
                "remote horizons are not contiguous"
            );
            let envelope: Envelope =
                serde_json::from_value(item.envelope).context("remote horizon envelope")?;
            chain.push((envelope, serde_json::to_vec(&item.policy)?));
        }
        ensure!(
            chain.len() <= engine_core::repository::receipt_journal::MAX_REMOTE_HORIZONS,
            "remote horizon limit"
        );
    }
    let configured = client.remote.public_key.clone();
    let trusted = move |key: &str| server.vet(&configured, key).is_ok();
    let accepted = journal
        .accept_horizons(client.remote.authority, client.project, &chain, &trusted)
        .await?;
    let mut stored = 0u64;
    for (envelope, _) in &chain {
        #[derive(Deserialize)]
        struct Row {
            address: Address,
            parents: Vec<Address>,
            height: u64,
        }
        let sequence = envelope.horizon.sequence.to_string();
        let mut entries = Vec::new();
        loop {
            let mut query = vec![("limit", "256".to_owned())];
            if let Some(last) = entries
                .last()
                .map(|e: &SkeletonEntry| e.address.as_str().to_owned())
            {
                query.push(("after", last));
            }
            let page: Page<Row> = client
                .get(
                    &format!("history/horizons/{sequence}/skeleton"),
                    &query,
                    1024 * 1024,
                )
                .await?;
            if page.items.is_empty() {
                break;
            }
            entries.extend(page.items.into_iter().map(|r| SkeletonEntry {
                address: r.address,
                parents: r.parents,
                height: r.height,
            }));
            ensure!(entries.len() <= 1_000_000, "remote skeleton limit");
        }
        stored += repo
            .import_remote_skeleton(envelope, &entries)
            .await?
            .stored;
    }
    Ok(json!({
        "horizons": chain.len(),
        "newly_accepted": accepted.new.len(),
        "skeleton_entries_stored": stored,
        "local_branches_changed": false,
    }))
}

/// The member monitor (design 4.9): verify the remote's latest checkpoint and its
/// consistency with what the journal holds, read every log leaf, and check that each
/// receipt of the branch is logged once under its blinded tag. An equivocation is an
/// error; missing (possibly pending) receipts are reported.
pub async fn monitor(
    client: &Client,
    journal: &ReceiptJournal,
    scope: &Scope,
    policy: &Policy,
) -> anyhow::Result<Value> {
    let info: KeyInfo = client
        .get("history/transparency-key", &[], 128 * 1024)
        .await?;
    ensure!(
        info.origin == policy.origin().as_str(),
        "the remote's log origin differs from the trust policy"
    );
    let key = TagKey::new(hex32(
        info.key
            .as_deref()
            .ok_or_else(|| anyhow!("this project has no logged leaves yet"))?,
    )?);
    let note = Note::parse(
        info.checkpoint
            .ok_or_else(|| anyhow!("the log has no checkpoint yet"))?
            .as_bytes(),
    )?;
    let verified = policy.verify_checkpoint(&note)?;
    let checkpoint = verified.checkpoint().clone();
    let known = journal.known_checkpoints(policy).await?;
    if let Some((size, root)) = known.latest() {
        let (first, second, first_root, second_root) = if size <= checkpoint.size {
            (size, checkpoint.size, root, checkpoint.root)
        } else {
            (checkpoint.size, size, checkpoint.root, root)
        };
        if first != second {
            let proof = consistency(client, first, second).await?;
            verify_consistency(first, second, &first_root, &second_root, &proof)
                .map_err(|_| anyhow!("ALERT: the log's checkpoint is not consistent with the one this journal holds (rewrite or fork)"))?;
        } else {
            ensure!(
                first_root == second_root,
                "ALERT: split view at size {first}"
            );
        }
    }
    let mut bundles = Vec::new();
    let mut index = 0u64;
    while index * 256 < checkpoint.size {
        let width = (checkpoint.size - index * 256).min(256);
        bundles.push(
            client
                .get_bytes(
                    &format!(
                        "transparency/v1/{}/{}",
                        info.origin_hash,
                        entry_bundle_path(index, width)
                    ),
                    256 * 1024,
                )
                .await?,
        );
        index += 1;
    }
    let leaves = monitor::leaves_from_bundles(&bundles, checkpoint.size, &checkpoint.root)?;
    #[derive(Deserialize)]
    struct Page {
        items: Vec<SignedReceipt>,
    }
    let mut expected = Vec::new();
    loop {
        let page: Page = client
            .get(
                "history/receipts",
                &[
                    ("branch", scope.branch.clone()),
                    ("after_generation", expected.len().to_string()),
                    ("limit", "256".into()),
                ],
                2 * 1024 * 1024,
            )
            .await?;
        if page.items.is_empty() {
            break;
        }
        for receipt in page.items {
            ensure!(
                receipt.receipt.scope == *scope,
                "a receipt of another scope"
            );
            expected.push(monitor::Expected {
                branch: scope.branch.clone(),
                generation: receipt.receipt.head.generation as u64,
                receipt: raw(&receipt.verify()?)?,
            });
        }
    }
    let findings = monitor::check_receipts(&key, &leaves, &expected);
    if policy.meets_quorum(&verified, now()) {
        journal.record_checkpoint(&verified, &note).await?;
    }
    let mut missing = Vec::new();
    for finding in &findings {
        match finding {
            monitor::Finding::Equivocation { generation, logged, .. } => anyhow::bail!(
                "ALERT: equivocation on {} generation {generation}: leaves {:?} commit to other receipts",
                scope.branch,
                logged.iter().map(|(i, _)| *i).collect::<Vec<_>>()
            ),
            monitor::Finding::Missing { generation, .. } => missing.push(*generation),
        }
    }
    Ok(json!({
        "checkpoint_size": checkpoint.size,
        "leaves": leaves.len(),
        "receipts_checked": expected.len(),
        "missing_generations": missing,
        "equivocation": false,
    }))
}
