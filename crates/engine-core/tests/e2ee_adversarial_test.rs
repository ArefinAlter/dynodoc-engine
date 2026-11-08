//! A server that lies (decision 041; threat model "malicious service"): it can reorder, drop,
//! replay or roll back what it stores, show different clients different branches, and insert
//! records under keys of its own, but it cannot sign as a member. Each lie below must be
//! caught by a client's checks: `Log::replay`, `verify_epochs` and the client's `Pin`.
use engine_core::e2ee::records::{verify_epochs, Entry, EpochRecord, Log, Pin, SignedEntry};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use uuid::Uuid;

const PROJECT: Uuid = Uuid::from_u128(0x0190_a3b4_0000_7000_8000_0000_0000_00aa);

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn pk(k: &Ed25519KeyPair) -> String {
    hex::encode(k.public_key().as_ref())
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// The honest history: owner A, member B, epoch 1, member C, epoch 2, C removed, epoch 3.
struct History {
    entries: Vec<SignedEntry>,
    records: Vec<(EpochRecord, String)>,
}

fn append(
    log: &mut Log,
    entries: &mut Vec<SignedEntry>,
    signer: &Ed25519KeyPair,
    kind: &str,
    body: Value,
) {
    let e = Entry {
        version: 1,
        project: PROJECT,
        index: log.length,
        previous: log.head.map(hex::encode),
        entry_type: kind.into(),
        body,
        signer_key: pk(signer),
        created_at_ms: 1_791_000_000_000 + log.length as i64,
    }
    .sign(signer)
    .unwrap();
    log.append(&e).unwrap();
    entries.push(e);
}

fn open_epoch(log: &mut Log, h: &mut History, owner: &Ed25519KeyPair, reason: &str, salt: u8) {
    let epoch = h.records.len() as u32 + 1;
    let record = EpochRecord {
        version: 1,
        project: PROJECT,
        epoch,
        previous_epoch_record: h
            .records
            .last()
            .map(|(r, _)| hex::encode(r.hash().unwrap())),
        reason: reason.into(),
        suite: 1,
        key_id: hex::encode([epoch as u8 ^ salt; 8]),
        recipients_digest: hex::encode([salt; 32]),
        membership_head: hex::encode(log.head.unwrap()),
        history_policy: "full".into(),
        created_by_key: pk(owner),
        created_at_ms: 1_791_000_000_000,
    };
    let hash = hex::encode(record.hash().unwrap());
    let signature = record.sign(owner).unwrap();
    append(
        log,
        &mut h.entries,
        owner,
        "epoch_open",
        json!({"epoch": epoch, "record_hash": hash}),
    );
    h.records.push((record, signature));
}

fn device(member: &Ed25519KeyPair, enc: u8) -> Value {
    json!([{"signing_key": pk(member), "encryption_key": hex::encode([enc; 32])}])
}

fn honest() -> (History, Log) {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut log = Log::new(PROJECT);
    let mut h = History {
        entries: Vec::new(),
        records: Vec::new(),
    };
    append(
        &mut log,
        &mut h.entries,
        &a,
        "genesis",
        json!({"identity": id(1), "signing_key": pk(&a), "encryption_key": hex::encode([0xa1; 32])}),
    );
    append(
        &mut log,
        &mut h.entries,
        &a,
        "member_add",
        json!({"identity": id(2), "role": "editor", "devices": device(&b, 0xb1)}),
    );
    open_epoch(&mut log, &mut h, &a, "project_created", 1);
    append(
        &mut log,
        &mut h.entries,
        &a,
        "member_add",
        json!({"identity": id(3), "role": "viewer", "devices": device(&c, 0xc1)}),
    );
    open_epoch(&mut log, &mut h, &a, "member_added", 2);
    append(
        &mut log,
        &mut h.entries,
        &a,
        "member_remove",
        json!({"identity": id(3)}),
    );
    open_epoch(&mut log, &mut h, &a, "member_removed", 3);
    (h, log)
}

/// What a client does with whatever the server returns.
fn client(
    pin: &mut Pin,
    entries: &[SignedEntry],
    records: &[(EpochRecord, String)],
) -> Result<Log, String> {
    let log = Log::replay(PROJECT, entries).map_err(|e| e.to_string())?;
    verify_epochs(&log, records).map_err(|e| e.to_string())?;
    pin.advance(
        &log,
        &records.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>(),
    )
    .map_err(|e| e.to_string())?;
    Ok(log)
}

#[test]
fn every_lie_of_a_malicious_server_is_detected() {
    let (h, full) = honest();
    let mut pin = Pin::default();
    client(&mut pin, &h.entries, &h.records).expect("the honest history verifies");

    // Replay: an older log and epoch chain, consistent with each other (C not yet removed).
    let mut p = pin.clone();
    let err = client(&mut p, &h.entries[..5], &h.records[..2]).unwrap_err();
    assert!(err.contains("older"), "{err}");

    // Withhold an epoch record the log announces.
    let mut p = pin.clone();
    let err = client(&mut p, &h.entries, &h.records[..2]).unwrap_err();
    assert!(err.contains("withheld"), "{err}");

    // Withhold an entry in the middle (the removal of C).
    let mut skipped = h.entries.clone();
    skipped.remove(5);
    assert!(
        client(&mut Pin::default(), &skipped, &h.records).is_err(),
        "chain link"
    );

    // Reorder two entries.
    let mut swapped = h.entries.clone();
    swapped.swap(3, 4);
    assert!(
        client(&mut Pin::default(), &swapped, &h.records).is_err(),
        "reorder"
    );

    // Withhold the tail from a new client, then show it a commit made after the removal.
    let mut fresh = Pin::default();
    let short = client(&mut fresh, &h.entries[..5], &h.records[..2]).expect("a consistent prefix");
    let later_head = hex::encode(full.head.unwrap());
    let err = Pin::knows(&short, &later_head).unwrap_err().to_string();
    assert!(err.contains("withholds"), "{err}");
    assert!(Pin::knows(&full, &later_head).is_ok());

    // An entry under the server's own key, and one by the removed member.
    let server = key(9);
    let mut log = full.clone();
    let mut forged = h.entries.clone();
    for (signer, what) in [(&server, "server key"), (&key(3), "removed member")] {
        let e = Entry {
            version: 1,
            project: PROJECT,
            index: log.length,
            previous: log.head.map(hex::encode),
            entry_type: "member_add".into(),
            body: json!({"identity": id(7), "role": "owner", "devices": device(&server, 0x99)}),
            signer_key: pk(signer),
            created_at_ms: 1_791_000_000_100,
        }
        .sign(signer)
        .unwrap();
        assert!(log.append(&e).is_err(), "{what}");
        forged.push(e);
        assert!(Log::replay(PROJECT, &forged).is_err(), "{what}");
        forged.pop();
    }

    // Fork the epochs: a second epoch 3 the log does not announce (server-made or replayed).
    let mut other = h.records.clone();
    let mut fork = other[2].0.clone();
    fork.key_id = hex::encode([0xee; 8]);
    let owner = key(1);
    other[2] = (fork.clone(), fork.sign(&owner).unwrap());
    let err = client(&mut pin.clone(), &h.entries, &other).unwrap_err();
    assert!(err.contains("announced"), "{err}");
    // An epoch record signed by someone else than its creator.
    let mut resigned = h.records.clone();
    resigned[2].1 = h.records[1].1.clone();
    assert!(client(&mut pin.clone(), &h.entries, &resigned).is_err());

    // Fork the log (a colluding owner signs a second branch): this client saw one branch, the
    // server now shows the other. The pin catches it at the first differing position.
    let mut branch_log = Log::replay(PROJECT, &h.entries[..6]).unwrap();
    let mut branch = History {
        entries: h.entries[..6].to_vec(),
        records: h.records[..2].to_vec(),
    };
    open_epoch(
        &mut branch_log,
        &mut branch,
        &owner,
        "suspected_compromise",
        7,
    );
    assert_eq!(
        branch.entries.len(),
        h.entries.len(),
        "same length, different last entry"
    );
    let err = client(&mut pin.clone(), &branch.entries, &branch.records).unwrap_err();
    assert!(err.contains("differs"), "{err}");

    // The pin survives storage as JSON and still refuses the replay.
    let mut stored: Pin = serde_json::from_str(&serde_json::to_string(&pin).unwrap()).unwrap();
    assert!(client(&mut stored, &h.entries[..5], &h.records[..2]).is_err());
}
