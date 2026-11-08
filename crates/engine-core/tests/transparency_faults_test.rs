//! Fault matrix for the transparency log (design phase W7, decision 032), end to end
//! through the pieces a deployment uses: the log, a witness with durable state, the
//! client trust policy and the client journal. A rewritten or truncated log is refused
//! by the witness; a fork cosigned by a witness restored from an old backup, and a
//! split view at one size, are detected by a client that remembers a checkpoint; a
//! stopped witness clock caps the level.
use engine_core::{
    repository::receipt_journal::ReceiptJournal,
    transparency::{
        assess,
        witness::{AddCheckpoint, Refusal, Witness, WitnessState},
        KeyKind, KnownCheckpoints, Leaf, Level, Log, MemoryTileStore, Note, Origin, Policy, Signer,
    },
};

const ORIGIN: &str = "log.example/dynodoc/v1/transparency";
const NOW: u64 = 1_791_000_000;

fn log_key() -> Signer {
    Signer::from_seed(ORIGIN, KeyKind::Log, &[1; 32]).unwrap()
}

fn witness_key() -> Signer {
    Signer::from_seed("witness.partner.example/w", KeyKind::Cosigner, &[2; 32]).unwrap()
}

fn witness() -> Witness {
    Witness::new(witness_key(), vec![log_key().verifier_key()]).unwrap()
}

fn policy() -> Policy {
    Policy::from_json(
        serde_json::json!({
            "version": 1,
            "log": {"origin": ORIGIN, "vkey": log_key().verifier_key().to_string()},
            "witnesses": [{"name": "witness.partner.example/w", "vkey": witness_key().verifier_key().to_string(), "operator": "partner"}],
            "quorum": {"threshold": 1, "distinct_operators": true},
            "freshness": {"max_age_seconds": 86400},
            "on_failure": "reject"
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap()
}

fn leaf(i: u64, salt: u8) -> Leaf {
    Leaf::EventHeads {
        root: [salt; 32],
        count: 1,
        interval: i,
    }
}

/// `n` leaves, the first `common` shared with the honest log.
fn log(n: u64, common: u64) -> Log<MemoryTileStore> {
    let mut log = Log::open(Origin::new(ORIGIN).unwrap(), MemoryTileStore::new()).unwrap();
    for i in 0..n {
        log.append(&leaf(i, if i < common { 0 } else { 7 }))
            .unwrap();
    }
    log
}

async fn cosign(
    state: &WitnessState,
    log: &Log<MemoryTileStore>,
    time: u64,
) -> Result<Note, Refusal> {
    let old = state.size(ORIGIN).await?;
    let request = AddCheckpoint {
        old_size: old,
        proof: if old == 0 || old > log.size() {
            vec![]
        } else {
            log.consistency_proof(old, log.size()).unwrap()
        },
        note: log.signed_checkpoint(&log_key()).unwrap(),
    };
    state.add_checkpoint(&witness(), &request, time).await?;
    Ok(Note::parse(state.latest(ORIGIN).await?.unwrap().as_bytes()).unwrap())
}

fn temp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("dynodoc-{name}-{}.sqlite", uuid::Uuid::new_v4()))
}

#[tokio::test]
async fn forks_rewrites_truncations_split_views_and_stale_witnesses_are_detected() {
    let policy = policy();
    let state_path = temp("witness");
    let state = WitnessState::open(&state_path).await.unwrap();
    let journal_path = temp("journal");
    let journal = ReceiptJournal::open(&journal_path).await.unwrap();

    // The witness has seen size 4; the operator keeps that state as a "backup".
    cosign(&state, &log(4, 4), NOW).await.unwrap();
    // A restored backup is a witness whose state is size 4 again.
    let restored = || async {
        let path = temp("witness-restored");
        let old = WitnessState::open(&path).await.unwrap();
        cosign(&old, &log(4, 4), NOW).await.unwrap();
        (old, path)
    };

    // A client sees size 9 cosigned: L2 on first contact, and remembers it.
    let honest9 = log(9, 9);
    let note9 = cosign(&state, &honest9, NOW).await.unwrap();
    let bundle = honest9.bundle(2, &note9).unwrap();
    let first = assess(
        &policy,
        &bundle,
        Some(&leaf(2, 0)),
        &journal.known_checkpoints(&policy).await.unwrap(),
        &honest9,
        NOW,
    );
    assert_eq!(first.level, Level::L2, "{first:?}");
    journal
        .record_checkpoint(first.trusted_checkpoint().unwrap(), &note9)
        .await
        .unwrap();

    // The honest log grows: L3, consistent with what the client knew.
    let honest12 = log(12, 12);
    let note12 = cosign(&state, &honest12, NOW).await.unwrap();
    let known = journal.known_checkpoints(&policy).await.unwrap();
    let grown = assess(
        &policy,
        &honest12.bundle(10, &note12).unwrap(),
        None,
        &known,
        &honest12,
        NOW,
    );
    assert_eq!(grown.level, Level::L3, "{grown:?}");
    journal
        .record_checkpoint(grown.trusted_checkpoint().unwrap(), &note12)
        .await
        .unwrap();

    // The witness refuses a rewrite of history it witnessed and a truncation.
    assert_eq!(
        cosign(&state, &log(14, 6), NOW).await,
        Err(Refusal::Inconsistent)
    );
    assert_eq!(cosign(&state, &log(8, 8), NOW).await, Err(Refusal::Smaller));

    // The operator restores the size-4 backup; the stale witness cosigns a fork.
    state.close().await;
    let (stale, stale_path) = restored().await;
    let fork = log(14, 6);
    let fork_note = cosign(&stale, &fork, NOW).await.unwrap();
    let known = journal.known_checkpoints(&policy).await.unwrap();
    let forked = assess(
        &policy,
        &fork.bundle(13, &fork_note).unwrap(),
        None,
        &known,
        &fork,
        NOW,
    );
    assert!(
        forked.rejection.is_some(),
        "a fork must not pass: {forked:?}"
    );
    assert_eq!(forked.level, Level::L0);

    // A split view at a size the client knows is refused by the verifier and the journal.
    stale.close().await;
    let (stale, split_path) = restored().await;
    let split = log(12, 6);
    let split_note = cosign(&stale, &split, NOW).await.unwrap();
    let viewed = assess(
        &policy,
        &split.bundle(11, &split_note).unwrap(),
        None,
        &known,
        &split,
        NOW,
    );
    assert!(viewed.rejection.is_some(), "{viewed:?}");
    let mut alone = KnownCheckpoints::new(&Origin::new(ORIGIN).unwrap());
    let verified = policy.verify_checkpoint(&split_note).unwrap();
    alone.record(&verified).unwrap();
    assert!(journal
        .record_checkpoint(&verified, &split_note)
        .await
        .is_err());

    // A witness whose clock stopped a week ago: its cosignature no longer counts.
    stale.close().await;
    let fresh_path = temp("witness-clock");
    let frozen = WitnessState::open(&fresh_path).await.unwrap();
    let note = cosign(&frozen, &honest12, NOW - 7 * 86400).await.unwrap();
    let capped = assess(
        &policy,
        &honest12.bundle(1, &note).unwrap(),
        None,
        &KnownCheckpoints::new(&Origin::new(ORIGIN).unwrap()),
        &honest12,
        NOW,
    );
    assert_eq!(capped.level, Level::L1, "{capped:?}");
    frozen.close().await;
    journal.close().await;
    for path in [state_path, stale_path, split_path, journal_path, fresh_path] {
        let _ = std::fs::remove_file(path);
    }
}
