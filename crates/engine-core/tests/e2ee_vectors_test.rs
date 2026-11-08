//! Encrypted projects: the Rust side of `fixtures/e2ee-v1.json`, written by the independent
//! generator `fixtures/gen_e2ee_vectors.py` (RFC 9180 and the design's appendix A checked
//! there). Every sealed object, grant, record, log entry, recovery key, relay answer and
//! block hash is reproduced byte for byte, and every negative case is refused.
use engine_core::e2ee::{
    grant::{self, DeviceKey, Grant},
    keys::{self, Key},
    records::{self, Binding, EpochRecord, Log, SignedEntry},
    recovery, relay,
    seal::{self, Context, Kind},
    state, Error,
};
use engine_core::shared_checkpoint::Address;
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/e2ee-v1.json")).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn key(v: &Value) -> Key {
    Key::from_slice(&bytes(v)).unwrap()
}
fn kind(name: &str) -> Kind {
    let n = [
        "node_fields",
        "text_chunk",
        "comment",
        "suggestion",
        "meta",
        "asset_chunk",
        "bundle",
        "event",
        "state_index",
    ]
    .iter()
    .position(|k| *k == name)
    .unwrap();
    Kind::from_byte(n as u8 + 1).unwrap()
}
fn uuid(v: &Value) -> Option<Uuid> {
    v.as_str().map(|s| s.parse().unwrap())
}

#[test]
fn the_key_hierarchy_matches_the_vectors() {
    for k in vectors()["keys"].as_array().unwrap() {
        let root = key(&k["root"]);
        let (p, d) = (uuid(&k["project"]).unwrap(), uuid(&k["document"]).unwrap());
        assert_eq!(
            hex::encode(keys::meta_key(&root).unwrap().as_bytes()),
            k["meta"]
        );
        assert_eq!(
            hex::encode(keys::cid_key(&root).unwrap().as_bytes()),
            k["cid"]
        );
        let doc = keys::doc_key(&root, p, d).unwrap();
        assert_eq!(hex::encode(doc.as_bytes()), k["doc"]);
        assert_eq!(
            hex::encode(keys::key_id(k["epoch"].as_u64().unwrap() as u32, &root)),
            k["key_id"]
        );
        assert_eq!(
            hex::encode(keys::ledger_block_key(&doc).unwrap().as_bytes()),
            k["ledger_block"]
        );
    }
}

struct Case {
    key: Key,
    cid: Key,
    key_id: [u8; 8],
    project: Uuid,
    document: Option<Uuid>,
    node: String,
    kind: Kind,
    epoch: u32,
    revision: u64,
}
fn case(c: &Value) -> Case {
    let root = key(&c["root"]);
    let project = uuid(&c["project"]).unwrap();
    let document = uuid(&c["document"]);
    let epoch = c["epoch"].as_u64().unwrap() as u32;
    let k = if c["key"] == "doc" {
        keys::doc_key(&root, project, document.unwrap()).unwrap()
    } else {
        keys::meta_key(&root).unwrap()
    };
    Case {
        key: k,
        cid: keys::cid_key(&root).unwrap(),
        key_id: keys::key_id(epoch, &root),
        project,
        document,
        node: c["node"].as_str().unwrap().into(),
        kind: kind(c["kind"].as_str().unwrap()),
        epoch,
        revision: c["revision"].as_u64().unwrap(),
    }
}
impl Case {
    fn ctx(&self) -> Context<'_> {
        Context {
            project: self.project,
            document: self.document,
            node: &self.node,
            kind: self.kind,
            epoch: self.epoch,
            revision: self.revision,
        }
    }
}

#[test]
fn sealed_objects_match_the_vectors_byte_for_byte_and_open() {
    for c in vectors()["seal"].as_array().unwrap() {
        let k = case(c);
        let refs: Vec<Address> = c["refs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| Address::try_from(r.as_str().unwrap().to_owned()).unwrap())
            .collect();
        let raw: Vec<[u8; 32]> = {
            let mut v: Vec<[u8; 32]> = refs
                .iter()
                .map(|r| hex::decode(r.as_str()).unwrap().try_into().unwrap())
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            hex::encode(seal::aad(&k.ctx(), &raw)),
            c["aad"],
            "{}",
            c["name"]
        );
        let salt: [u8; 32] = bytes(&c["salt"]).try_into().unwrap();
        let block = seal::key_block(&k.key, &salt).unwrap();
        assert_eq!(hex::encode(block.key.as_bytes()), c["aead_key"]);
        assert_eq!(hex::encode(block.nonce), c["nonce"]);
        assert_eq!(hex::encode(block.commit_key.as_bytes()), c["commit_key"]);
        assert_eq!(
            String::from_utf8(seal::body(&k.cid, k.kind, &c["content"])).unwrap(),
            c["body"]
        );
        let sealed = seal::seal_with_salt(
            &k.key,
            k.key_id,
            &k.cid,
            &k.ctx(),
            &refs,
            &c["content"],
            salt,
        )
        .unwrap();
        assert_eq!(hex::encode(&sealed), c["envelope"], "{}", c["name"]);
        let address = seal::address(&sealed).unwrap();
        assert_eq!(address.as_str(), c["address"]);
        assert_eq!(seal::references(&address, &sealed).unwrap(), {
            let mut r = refs.clone();
            r.sort();
            r
        });
        assert_eq!(
            seal::open(&k.key, k.key_id, &k.cid, &k.ctx(), &sealed).unwrap(),
            c["content"]
        );
    }
}

#[test]
fn every_negative_seal_vector_is_refused() {
    let v = vectors();
    let a = &v["seal"][0];
    for n in v["seal_negative"].as_array().unwrap() {
        let mut c = a.clone();
        for (field, value) in n["context"].as_object().unwrap() {
            c[field] = value.clone();
        }
        let k = case(&c);
        let envelope = bytes(&n["envelope"]);
        let result = seal::open(&k.key, k.key_id, &k.cid, &k.ctx(), &envelope);
        assert!(result.is_err(), "{} was accepted", n["name"]);
    }
    // A wrong key is caught by the commitment before AES-GCM runs.
    let k = case(a);
    let other = Key::from_bytes([9; 32]);
    assert_eq!(
        seal::open(&other, k.key_id, &k.cid, &k.ctx(), &bytes(&a["envelope"])),
        Err(Error::Commitment)
    );
}

#[test]
fn padding_buckets_match_the_vectors() {
    for p in vectors()["padding"].as_array().unwrap() {
        let framed = p["framed"].as_u64().unwrap() as usize;
        let expected = p["padded"].as_u64().unwrap() as usize;
        let got = seal::BUCKETS
            .iter()
            .copied()
            .find(|b| *b >= framed)
            .unwrap_or(framed);
        assert_eq!(got, expected);
    }
}

#[test]
fn grants_match_the_vectors_open_and_refuse_tampering() {
    let v = vectors();
    let creator = Ed25519KeyPair::from_seed_unchecked(&[0x22; 32]).unwrap();
    let creator_key = v["creator_public"].as_str().unwrap();
    let ikms = [0x33u8, 0x34, 0x35];
    let mut stored = Vec::new();
    for (g, ikm) in v["grants"].as_array().unwrap().iter().zip(ikms) {
        let expected: Grant = serde_json::from_value(g["grant"].clone()).unwrap();
        let mut blank = expected.clone();
        blank.enc.clear();
        blank.ciphertext.clear();
        blank.signature.clear();
        assert_eq!(hex::encode(blank.info()), g["info"]);
        assert_eq!(hex::encode(blank.aad().unwrap()), g["aad"]);
        let secret = match g["secret"].as_str() {
            Some(s) if s.starts_with('[') => s.as_bytes().to_vec(),
            Some(s) => hex::decode(s).unwrap(),
            None => unreachable!(),
        };
        let sealed = blank.seal_with_ikm(&secret, &creator, [ikm; 32]).unwrap();
        assert_eq!(sealed, expected);
        assert_eq!(hex::encode(sealed.hash().unwrap()), g["hash"]);
        assert_eq!(
            hex::encode(sealed.digest_entry().unwrap().1),
            g["digest_entry"]
        );
        let recipient = DeviceKey::from_secret(&key(&g["recipient_secret"])).unwrap();
        assert_eq!(recipient.public_hex(), sealed.recipient_key);
        assert_eq!(
            &**sealed.open(creator_key, &recipient).unwrap(),
            secret.as_slice()
        );
        // Wrong creator key, altered field, altered ciphertext, wrong recipient.
        assert_eq!(
            sealed.open(&"0".repeat(64), &recipient).unwrap_err(),
            Error::Signature
        );
        let mut moved = sealed.clone();
        moved.epoch += 1;
        assert!(moved.open(creator_key, &recipient).is_err());
        let mut flipped = sealed.clone();
        flipped.ciphertext.replace_range(
            0..2,
            if flipped.ciphertext.starts_with("00") {
                "01"
            } else {
                "00"
            },
        );
        assert!(flipped.open(creator_key, &recipient).is_err());
        assert!(sealed
            .open(
                creator_key,
                &DeviceKey::from_secret(&Key::from_bytes([1; 32])).unwrap()
            )
            .is_err());
        stored.push(sealed);
    }
    assert_eq!(
        grant::recipients_digest(&stored[..2]).unwrap(),
        v["recipients_digest"]
    );
    // The project grant opens to a root whose key id matches the record; delegation lists keys.
    let recipient = DeviceKey::from_secret(&key(&v["grants"][0]["recipient_secret"])).unwrap();
    let record: EpochRecord = serde_json::from_value(v["epoch_record"]["record"].clone()).unwrap();
    let root = stored[0]
        .open_root(creator_key, &recipient, &record.key_id)
        .unwrap();
    assert_eq!(hex::encode(root.as_bytes()), v["grants"][0]["secret"]);
    assert!(stored[0]
        .open_root(creator_key, &recipient, "0000000000000000")
        .is_err());
    let agent = DeviceKey::from_secret(&key(&v["grants"][2]["recipient_secret"])).unwrap();
    let list = stored[2]
        .open_delegation(creator_key, &agent, 1_791_000_000_000)
        .unwrap();
    assert_eq!(
        list.iter()
            .map(|(e, k)| (*e, hex::encode(k.doc.as_bytes()), hex::encode(k.key_id)))
            .collect::<Vec<_>>(),
        [0, 1]
            .map(|i| (
                v["keys"][i]["epoch"].as_u64().unwrap() as u32,
                v["keys"][i]["doc"].as_str().unwrap().to_owned(),
                v["keys"][i]["key_id"].as_str().unwrap().to_owned()
            ))
            .to_vec()
    );
    assert!(
        stored[2]
            .open_delegation(creator_key, &agent, 1_791_003_600_000)
            .is_err(),
        "expired"
    );
}

#[test]
fn epoch_record_binding_and_fingerprint_match_the_vectors() {
    let v = vectors();
    let creator = Ed25519KeyPair::from_seed_unchecked(&[0x22; 32]).unwrap();
    let record: EpochRecord = serde_json::from_value(v["epoch_record"]["record"].clone()).unwrap();
    assert_eq!(
        hex::encode(record.hash().unwrap()),
        v["epoch_record"]["hash"]
    );
    assert_eq!(
        record.sign(&creator).unwrap(),
        v["epoch_record"]["signature"]
    );
    record
        .verify(v["epoch_record"]["signature"].as_str().unwrap())
        .unwrap();
    let mut changed = record.clone();
    changed.recipients_digest = "0".repeat(64);
    assert_eq!(
        changed.verify(v["epoch_record"]["signature"].as_str().unwrap()),
        Err(Error::Signature)
    );
    let binding: Binding = serde_json::from_value(v["binding"]["message"].clone()).unwrap();
    let dsk = Ed25519KeyPair::from_seed_unchecked(&[0x44; 32]).unwrap();
    assert_eq!(binding.sign(&dsk).unwrap(), v["binding"]["signature"]);
    binding
        .verify(v["binding"]["signature"].as_str().unwrap())
        .unwrap();
    let (fp, digits) = records::fingerprint(&binding.signing_key, &binding.encryption_key).unwrap();
    assert_eq!(fp, v["binding"]["fingerprint"]);
    assert_eq!(digits, v["binding"]["digits"]);
}

#[test]
fn the_membership_log_replays_and_refuses_bad_entries() {
    let v = vectors();
    let project: Uuid = v["seal"][0]["project"].as_str().unwrap().parse().unwrap();
    let entries: Vec<SignedEntry> = v["log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| serde_json::from_value(e["signed"].clone()).unwrap())
        .collect();
    for (e, expected) in entries.iter().zip(v["log"].as_array().unwrap()) {
        assert_eq!(hex::encode(e.entry.hash().unwrap()), expected["hash"]);
    }
    let log = Log::replay(project, &entries).unwrap();
    assert_eq!(log.members.len(), 1, "bob was removed");
    assert_eq!(log.epochs.len(), 2);
    assert_eq!(
        log.recipients().len(),
        1,
        "only the owner's device remains a recipient"
    );
    for r in v["log_rejected"].as_array().unwrap() {
        let after = r["after"].as_u64().unwrap() as usize;
        let mut partial = Log::replay(project, &entries[..after]).unwrap();
        let signed: SignedEntry = serde_json::from_value(r["signed"].clone()).unwrap();
        assert!(
            partial.append(&signed).is_err(),
            "{} was accepted",
            r["name"]
        );
    }
}

#[test]
fn the_recovery_key_and_escrow_recipient_match_the_vectors() {
    let r = &vectors()["recovery"];
    let rk = key(&r["key"]);
    assert_eq!(recovery::encode(&rk), r["text"]);
    let typed = r["text"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .replace('1', "l")
        .replace('0', "o");
    assert_eq!(recovery::decode(&typed).unwrap().as_bytes(), rk.as_bytes());
    let mut typo = r["text"].as_str().unwrap().to_owned();
    typo.replace_range(5..6, if &typo[5..6] == "A" { "B" } else { "A" });
    assert!(recovery::decode(&typo).is_err());
    let derived = recovery::derive(&rk).unwrap();
    assert_eq!(derived.recipient.public_hex(), r["recipient_public"]);
    use ring::signature::KeyPair;
    assert_eq!(
        hex::encode(derived.signer.public_key().as_ref()),
        r["signer_public"]
    );
    assert_eq!(
        recovery::escrow_recipient(&key(&r["escrow_secret"]))
            .unwrap()
            .public_hex(),
        r["escrow_public"]
    );
}

#[test]
fn ledger_relay_answers_and_block_hashes_match_the_vectors() {
    let l = &vectors()["ledger"];
    assert_eq!(relay::block_hash(None, &l["fields"]), l["unkeyed"]);
    assert_eq!(
        relay::block_hash(Some(&key(&l["ledger_block_key"])), &l["fields"]),
        l["keyed"]
    );
    let r = &l["relay"];
    let requester = DeviceKey::from_secret(&key(&r["requester_secret"])).unwrap();
    let pk: [u8; 32] = hex::decode(requester.public_hex())
        .unwrap()
        .try_into()
        .unwrap();
    let doc: Uuid = r["document"].as_str().unwrap().parse().unwrap();
    let subject: [u8; 32] = bytes(&r["subject"]).try_into().unwrap();
    let payload = r["payload"].as_str().unwrap().as_bytes();
    let sealed = relay::seal_answer_with_ikm(
        &pk,
        doc,
        "block",
        &subject,
        payload,
        bytes(&r["ikm"]).try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(hex::encode(&sealed), r["sealed"]);
    assert_eq!(
        &**relay::open_answer(&requester, doc, "block", &subject, &sealed).unwrap(),
        payload
    );
    // Bound to the document, the kind and the requested hash.
    assert!(relay::open_answer(&requester, Uuid::nil(), "block", &subject, &sealed).is_err());
    assert!(relay::open_answer(&requester, doc, "media", &subject, &sealed).is_err());
    assert!(relay::open_answer(&requester, doc, "block", &[0; 32], &sealed).is_err());
}

#[test]
fn a_sealed_state_round_trips_reuses_unchanged_nodes_and_the_service_sees_no_plaintext() {
    use engine_core::materializer::{CommentState, DocumentState, MaterializedNode};
    use engine_shared::NodeId;
    let (project, document) = (Uuid::from_u128(1), Uuid::from_u128(2));
    let root = Key::from_bytes([5; 32]);
    let keys1 = state::EpochKeys {
        key_id: keys::key_id(1, &root),
        doc: keys::doc_key(&root, project, document).unwrap(),
        cid: keys::cid_key(&root).unwrap(),
    };
    let node = |id: &str, parent: Option<&str>, text: &str| MaterializedNode {
        id: NodeId(id.into()),
        parent_id: parent.map(|p| NodeId(p.into())),
        node_type: if parent.is_none() {
            "form".into()
        } else {
            "paragraph".into()
        },
        pos: "a0".into(),
        current_fields: json!({"label": text}),
        var_name: (text == "named").then(|| "v1".into()),
        deleted: false,
    };
    let mut doc = DocumentState::default();
    for n in [
        node("R", None, "ZEUS-CANARY-title"),
        node("A", Some("R"), "ZEUS-CANARY-secret paragraph"),
        node("B", Some("R"), "named"),
    ] {
        doc.nodes.insert(n.id.clone(), n);
    }
    doc.comments.push(CommentState {
        node_id: Some(NodeId("A".into())),
        body: "ZEUS-CANARY-comment".into(),
    });
    let written = state::write(&doc, project, document, 1, &keys1, None).unwrap();
    for (address, bytes) in &written.objects {
        assert!(
            !String::from_utf8_lossy(bytes).contains("ZEUS-CANARY"),
            "plaintext in a stored object"
        );
        assert!(
            !String::from_utf8_lossy(bytes).contains("\"v1\""),
            "var_name in a stored object"
        );
        // The service-side validators accept every object without keys.
        if bytes.starts_with(seal::MAGIC) {
            seal::validate(address, bytes).unwrap();
        } else {
            state::validate(address, bytes).unwrap();
        }
    }
    let store: BTreeMap<Address, Vec<u8>> = written.objects.iter().cloned().collect();
    let mut held = BTreeMap::new();
    held.insert(1, keys1);
    let (read, refs) = state::read(&written.root, &store, project, document, &held).unwrap();
    assert_eq!(read, doc);
    // Epoch 2 seals only the changed node; the others keep their epoch-1 objects.
    let root2 = Key::from_bytes([6; 32]);
    let keys2 = state::EpochKeys {
        key_id: keys::key_id(2, &root2),
        doc: keys::doc_key(&root2, project, document).unwrap(),
        cid: keys::cid_key(&root2).unwrap(),
    };
    let mut next = doc.clone();
    next.nodes
        .get_mut(&NodeId("A".into()))
        .unwrap()
        .current_fields = json!({"label": "changed"});
    let second = state::write(&next, project, document, 2, &keys2, Some((&doc, &refs))).unwrap();
    assert_eq!(second.nodes["A"].rev, 2);
    assert_eq!(second.nodes["A"].epoch, 2);
    assert_eq!(second.nodes["R"], refs["R"]);
    let mut store2 = store.clone();
    store2.extend(second.objects.iter().cloned());
    assert!(
        state::read(&second.root, &store2, project, document, &held).is_err(),
        "epoch 2 needs its key"
    );
    held.insert(2, keys2);
    assert_eq!(
        state::read(&second.root, &store2, project, document, &held)
            .unwrap()
            .0,
        next
    );
    // A node record pointed at another node's sealed fields is refused (AAD binds the node).
    let a = &second.nodes["A"];
    let mut swapped = store2.clone();
    let b_record = second
        .objects
        .iter()
        .find(|(_, b)| String::from_utf8_lossy(b).contains("\"id\":\"B\""))
        .unwrap();
    let mut obj: serde_json::Value =
        serde_json::from_slice(&b_record.1[state::MAGIC.len()..]).unwrap();
    obj["value"]["fields"] = json!(a.fields.as_str());
    let (addr, bytes) = state::encode(&serde_json::from_value(obj).unwrap()).unwrap();
    swapped.insert(addr.clone(), bytes);
    let mut idx: Vec<(String, Address)> = Vec::new();
    for (k, r) in [
        ("A", &second.nodes["A"]),
        ("B", &second.nodes["B"]),
        ("R", &second.nodes["R"]),
    ] {
        let _ = r;
        let found = second
            .objects
            .iter()
            .find(|(_, b)| String::from_utf8_lossy(b).contains(&format!("\"id\":\"{k}\"")))
            .unwrap();
        idx.push((
            k.into(),
            if k == "B" {
                addr.clone()
            } else {
                found.0.clone()
            },
        ));
    }
    let (index, ib) = state::encode(&state::Object::Index(state::Index {
        entries: idx,
        children: vec![],
    }))
    .unwrap();
    swapped.insert(index.clone(), ib);
    let Ok(state::Object::State(mut s)) = state::decode(&second.root, &store2[&second.root]) else {
        panic!()
    };
    s.nodes = index;
    let (root3, rb) = state::encode(&state::Object::State(s)).unwrap();
    swapped.insert(root3.clone(), rb);
    assert!(state::read(&root3, &swapped, project, document, &held).is_err());
}
