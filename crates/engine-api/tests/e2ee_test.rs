//! Encrypted projects through the real router and the restricted database login (decision
//! 035). Trust boundaries: the service never receives plaintext or keys (a storage scan of
//! every table after the flow), a removed member gets no grant for the new epoch and cannot
//! open it, tampered objects and wrong signatures are refused, plaintext is refused in a
//! sealed file and sealed bytes in a plaintext one, and plaintext-only features answer
//! `422 encrypted_project`.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use engine_api::{
    app,
    auth::{store, token, AuthConfig},
    AppState,
};
use engine_core::e2ee::{
    commit::{self, Sealed},
    grant::{DeviceKey, Grant, Scope, GRANT_SUITE},
    keys::{self, Key},
    records::{Binding, Entry, EpochRecord, SignedEntry},
    seal::{self, Context, Kind},
    state,
};
use engine_core::materializer::{DocumentState, MaterializedNode};
use engine_core::repository::{device::Challenge, device::Proof, Commit, FileEntry, SignedCommit};
use engine_shared::{DocumentId, NodeId};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;
use tower::ServiceExt;
use uuid::Uuid;
mod common;
const KEY: [u8; 32] = [9; 32];
const CANARY: &str = "ZEUS-CANARY-e2ee-paragraph";

fn router(pool: PgPool) -> Router {
    let mut state = AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.e2ee_create = true;
    app(state)
}
async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        }))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// One person with one device: login, signing key, encryption key.
struct Member {
    id: Uuid,
    login: String,
    sign: Ed25519KeyPair,
    enc: DeviceKey,
    device: Uuid,
}
impl Member {
    fn signing(&self) -> String {
        hex::encode(self.sign.public_key().as_ref())
    }
}

async fn member(app: &Router, pool: &PgPool, name: &str, seed: u8) -> Member {
    let id = store::upsert_identity(pool, &format!("{name}@example.test"), None)
        .await
        .unwrap()
        .id
        .0;
    let login = token::mint(&KEY, id, 3600).unwrap();
    let sign = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let (st, challenge) = call(
        app,
        "POST",
        "/devices/challenge",
        &login,
        json!({"public_key": hex::encode(sign.public_key().as_ref())}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{challenge}");
    let challenge: Challenge = serde_json::from_value(challenge).unwrap();
    let proof = Proof::sign(
        challenge.clone(),
        challenge.authority,
        challenge.identity,
        &sign,
    )
    .unwrap();
    let (st, enrolled) = call(app, "POST", "/devices", &login, json!(proof)).await;
    assert_eq!(st, StatusCode::OK, "{enrolled}");
    let key_id: Uuid = serde_json::from_value(enrolled["id"].clone()).unwrap();
    let enc = DeviceKey::from_secret(&Key::from_bytes([seed.wrapping_add(100); 32])).unwrap();
    let binding = Binding {
        version: 1,
        authority: challenge.authority,
        identity: id,
        signing_key: hex::encode(sign.public_key().as_ref()),
        encryption_key: enc.public_hex(),
        created_at_ms: 1_791_000_000_000,
    };
    let signature = binding.sign(&sign).unwrap();
    // A binding naming someone else's account is refused.
    let mut wrong = binding.clone();
    wrong.identity = Uuid::new_v4();
    let bad_sig = wrong.sign(&sign).unwrap();
    let (st, _) = call(
        app,
        "POST",
        &format!("/devices/{key_id}/encryption-key"),
        &login,
        json!({"public_key": enc.public_hex(), "binding": wrong, "signature": bad_sig}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, registered) = call(
        app,
        "POST",
        &format!("/devices/{key_id}/encryption-key"),
        &login,
        json!({"public_key": enc.public_hex(), "binding": binding, "signature": signature}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{registered}");
    assert_eq!(
        registered["fingerprint"].as_str().unwrap().len(),
        71,
        "60 digits in 12 groups"
    );
    Member {
        id,
        login,
        sign,
        enc,
        device: serde_json::from_value(registered["id"].clone()).unwrap(),
    }
}

fn entry(
    project: Uuid,
    index: u64,
    previous: Option<&str>,
    kind: &str,
    body: Value,
    signer: &Member,
) -> SignedEntry {
    Entry {
        version: 1,
        project,
        index,
        previous: previous.map(str::to_owned),
        entry_type: kind.into(),
        body,
        signer_key: signer.signing(),
        created_at_ms: 1_791_000_000_000 + index as i64,
    }
    .sign(&signer.sign)
    .unwrap()
}

async fn head(app: &Router, project: Uuid, login: &str) -> (u64, String) {
    let (st, s) = call(
        app,
        "GET",
        &format!("/projects/{project}/e2ee"),
        login,
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{s}");
    (
        s["log_head"]["index"].as_u64().unwrap() + 1,
        s["log_head"]["hash"].as_str().unwrap().to_owned(),
    )
}

fn grant_for(
    project: Uuid,
    epoch: u32,
    record_hash: &str,
    recipient: &Member,
    root: &Key,
    author: &Member,
) -> Grant {
    Grant {
        version: 1,
        project,
        epoch,
        scope: Scope::Project,
        recipient_kind: "device".into(),
        recipient_device: Some(recipient.device),
        recipient_key: recipient.enc.public_hex(),
        suite: GRANT_SUITE,
        delegation: None,
        enc: String::new(),
        ciphertext: String::new(),
        epoch_record: record_hash.into(),
        created_by_key: String::new(),
        created_at_ms: 1_791_000_000_000,
        signature: String::new(),
    }
    .seal(root.as_bytes(), &author.sign)
    .unwrap()
}

/// Build and send an epoch: grants first (the digest needs them), then the record.
#[allow(clippy::too_many_arguments)]
async fn open_epoch(
    app: &Router,
    project: Uuid,
    epoch: u32,
    previous: Option<String>,
    root: &Key,
    author: &Member,
    to: &[&Member],
    removal: Option<SignedEntry>,
) -> (StatusCode, Value, String) {
    let (mut next, mut head_hash) = head(app, project, &author.login).await;
    if let Some(r) = &removal {
        next += 1;
        head_hash = hex::encode(r.entry.hash().unwrap());
    }
    // The record hash depends on the digest, the digest on the grants, the grants on the
    // record hash: the grant's HPKE aad leaves the record out (decision 035), so seal with a
    // placeholder, compute the digest, then re-sign each grant with the final record hash.
    let draft: Vec<Grant> = to
        .iter()
        .map(|m| grant_for(project, epoch, &"0".repeat(64), m, root, author))
        .collect();
    let record = EpochRecord {
        version: 1,
        project,
        epoch,
        previous_epoch_record: previous,
        reason: if removal.is_some() {
            "member_removed".into()
        } else {
            "project_created".into()
        },
        suite: 1,
        key_id: hex::encode(keys::key_id(epoch, root)),
        recipients_digest: engine_core::e2ee::grant::recipients_digest(&draft).unwrap(),
        membership_head: head_hash.clone(),
        history_policy: "full".into(),
        created_by_key: author.signing(),
        created_at_ms: 1_791_000_000_000,
    };
    let record_hash = hex::encode(record.hash().unwrap());
    let grants: Vec<Grant> = draft
        .into_iter()
        .map(|mut g| {
            g.epoch_record = record_hash.clone();
            g.signature.clear();
            let message = [
                engine_core::e2ee::grant::SIGNATURE_LABEL,
                &g.hash().unwrap(),
            ]
            .concat();
            g.signature = hex::encode(author.sign.sign(&message).as_ref());
            g
        })
        .collect();
    let log_entry = entry(
        project,
        next,
        Some(&head_hash),
        "epoch_open",
        json!({"epoch": epoch, "record_hash": record_hash}),
        author,
    );
    let (st, body) = call(app, "POST", &format!("/projects/{project}/e2ee/epochs"), &author.login, json!({
        "record": record, "signature": record.sign(&author.sign).unwrap(), "log_entry": log_entry, "grants": grants, "removal": removal,
    })).await;
    (st, body, record_hash)
}

fn epoch_keys(root: &Key, epoch: u32, project: Uuid, document: Uuid) -> state::EpochKeys {
    state::EpochKeys {
        key_id: keys::key_id(epoch, root),
        doc: keys::doc_key(root, project, document).unwrap(),
        cid: keys::cid_key(root).unwrap(),
    }
}

fn meta_envelope(root: &Key, epoch: u32, project: Uuid, node: &str, value: Value) -> String {
    let ctx = Context {
        project,
        document: None,
        node,
        kind: Kind::Meta,
        epoch,
        revision: 0,
    };
    commit::encode(
        &seal::seal(
            &keys::meta_key(root).unwrap(),
            keys::key_id(epoch, root),
            &keys::cid_key(root).unwrap(),
            &ctx,
            &[],
            &value,
        )
        .unwrap(),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_encrypted_project_keeps_content_and_keys_off_the_service(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let app = router(runtime.pool.clone());
    let alice = member(&app, &runtime.pool, "alice", 11).await;
    let bob = member(&app, &runtime.pool, "bob", 12).await;
    let carol = member(&app, &runtime.pool, "carol", 13).await;
    let (st, project) = call(
        &app,
        "POST",
        "/projects",
        &alice.login,
        json!({"name": "Board papers"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{project}");
    let project: Uuid = serde_json::from_value(project["id"].clone()).unwrap();
    for m in [&bob, &carol] {
        sqlx::query("insert into space_member(space_id,identity_id,role) values($1,$2,'editor')")
            .bind(project)
            .bind(m.id)
            .execute(&pool)
            .await
            .unwrap();
    }
    let p = format!("/projects/{project}/e2ee");

    // Only the owner begins; the genesis entry names the owner's bound keys.
    let genesis = entry(
        project,
        0,
        None,
        "genesis",
        json!({"identity": alice.id.to_string(), "signing_key": alice.signing(), "encryption_key": alice.enc.public_hex()}),
        &alice,
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{p}/begin"),
            &bob.login,
            json!({"genesis": genesis})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (st, b) = call(
        &app,
        "POST",
        &format!("{p}/begin"),
        &alice.login,
        json!({"genesis": genesis}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{b}");

    // Members join the log with the devices the owner verified. An editor cannot add one.
    let (n, h) = head(&app, project, &alice.login).await;
    let by_bob = entry(
        project,
        n,
        Some(&h),
        "member_add",
        json!({"identity": carol.id.to_string(), "role": "editor"}),
        &bob,
    );
    assert_eq!(
        call(&app, "POST", &format!("{p}/log"), &bob.login, json!(by_bob))
            .await
            .0,
        StatusCode::BAD_REQUEST,
        "bob's key is not in the log yet"
    );
    for m in [&bob, &carol] {
        let (n, h) = head(&app, project, &alice.login).await;
        let add = entry(
            project,
            n,
            Some(&h),
            "member_add",
            json!({"identity": m.id.to_string(), "role": "editor", "devices": [{"signing_key": m.signing(), "encryption_key": m.enc.public_hex()}]}),
            &alice,
        );
        let (st, b) = call(&app, "POST", &format!("{p}/log"), &alice.login, json!(add)).await;
        assert_eq!(st, StatusCode::CREATED, "{b}");
    }
    let (n, h) = head(&app, project, &alice.login).await;
    let rogue = entry(
        project,
        n,
        Some(&h),
        "member_add",
        json!({"identity": Uuid::new_v4().to_string(), "role": "editor"}),
        &bob,
    );
    assert_eq!(
        call(&app, "POST", &format!("{p}/log"), &bob.login, json!(rogue))
            .await
            .0,
        StatusCode::BAD_REQUEST,
        "an editor's entry is refused by the log rules"
    );

    // Epoch 1: the recipient set must be exactly the log's devices.
    let root1 = Key::from_bytes([0x51; 32]);
    let (st, b, _) = open_epoch(
        &app,
        project,
        1,
        None,
        &root1,
        &alice,
        &[&alice, &bob],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "carol left out: {b}");
    assert_eq!(b["code"], "recipient_set_mismatch");
    let (st, b, rec1) = open_epoch(
        &app,
        project,
        1,
        None,
        &root1,
        &alice,
        &[&alice, &bob, &carol],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{b}");
    let (st, b, _) = open_epoch(
        &app,
        project,
        1,
        None,
        &root1,
        &alice,
        &[&alice, &bob, &carol],
        None,
    )
    .await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("epoch_conflict"))
    );

    // A sealed file: placeholder title, sealed content, sealed commit message and path.
    let (st, d) = call(
        &app,
        "POST",
        &format!("{p}/documents"),
        &alice.login,
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{d}");
    let doc: Uuid = serde_json::from_value(d["id"].clone()).unwrap();
    let mut state1 = DocumentState::default();
    for (id, parent, text) in [("R", None, "form"), ("A", Some("R"), CANARY)] {
        state1.nodes.insert(
            NodeId(id.into()),
            MaterializedNode {
                id: NodeId(id.into()),
                parent_id: parent.map(|x: &str| NodeId(x.into())),
                node_type: if parent.is_some() {
                    "paragraph".into()
                } else {
                    "form".into()
                },
                pos: "a0".into(),
                current_fields: json!({"label": text}),
                var_name: None,
                deleted: false,
            },
        );
    }
    let written = state::write(
        &state1,
        project,
        doc,
        1,
        &epoch_keys(&root1, 1, project, doc),
        None,
    )
    .unwrap();
    // Tampered bytes under a claimed address are refused at upload.
    let (addr0, bytes0) = written
        .objects
        .iter()
        .find(|(_, b)| b.starts_with(seal::MAGIC))
        .unwrap();
    let mut flipped = bytes0.clone();
    *flipped.last_mut().unwrap() ^= 1;
    let (st, _) = call(&app, "POST", &format!("/projects/{project}/staging/objects"), &alice.login, json!({"document": doc, "objects": [{"address": addr0, "bytes": STANDARD.encode(&flipped)}]})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "tampered sealed object");
    // Plaintext typed objects are refused in a sealed file.
    let mut plain_store = engine_core::shared_checkpoint::MemoryStore::default();
    let (plain_root, _) = engine_core::shared_checkpoint::typed::write_state(
        &mut plain_store,
        DocumentId(doc),
        &state1,
        engine_core::shared_checkpoint::Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();
    let plain_bytes = engine_core::shared_checkpoint::ObjectStore::get(
        &mut plain_store,
        DocumentId(doc),
        &plain_root,
    )
    .await
    .unwrap();
    let (st, b) = call(&app, "POST", &format!("/projects/{project}/staging/objects"), &alice.login, json!({"document": doc, "objects": [{"address": plain_root, "bytes": STANDARD.encode(&plain_bytes)}]})).await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("mode_mismatch")),
        "{b}"
    );
    for chunk in written.objects.chunks(32) {
        let objects: Vec<Value> = chunk
            .iter()
            .map(|(a, b)| json!({"address": a, "bytes": STANDARD.encode(b)}))
            .collect();
        let (st, b) = call(
            &app,
            "POST",
            &format!("/projects/{project}/staging/objects"),
            &alice.login,
            json!({"document": doc, "objects": objects}),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{b}");
    }
    let (_, membership_head) = head(&app, project, &alice.login).await;
    let sealed = Sealed {
        epoch: 1,
        membership_head,
        message: meta_envelope(
            &root1,
            1,
            project,
            commit::MESSAGE_NODE,
            json!("ZEUS-CANARY-commit message"),
        ),
        paths: meta_envelope(
            &root1,
            1,
            project,
            commit::PATHS_NODE,
            json!({doc.to_string(): "ZEUS-CANARY-Board minutes.docx"}),
        ),
    };
    let make = |version: u8, sealed: Option<Sealed>, message: &str, key: String| {
        SignedCommit::sign(
            Commit {
                version,
                project,
                parents: vec![],
                files: BTreeMap::from([(
                    key,
                    FileEntry {
                        document: DocumentId(doc),
                        state: written.root.clone(),
                    },
                )]),
                author_key: String::new(),
                authored_at_ms: 1_791_000_000_000,
                message: message.into(),
                recovery: None,
                same_file_resolutions: Vec::new(),
                merge_policy: None,
                project_resolutions: Vec::new(),
                relocations: Vec::new(),
                sealed: sealed.map(Box::new),
            },
            &alice.sign,
        )
        .unwrap()
    };
    let plain = make(1, None, "", "Board minutes.docx".into());
    let (st, b) = call(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &alice.login,
        json!(plain),
    )
    .await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("mode_mismatch")),
        "a plaintext commit of a sealed file: {b}"
    );
    let signed = make(4, Some(sealed), "", doc.to_string());
    let (st, b) = call(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &alice.login,
        json!(signed),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let address = signed.verify().unwrap().as_str().to_owned();
    let (st, b) = call(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &alice.login,
        json!({"address": address}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");

    // Bob reads: his grant opens to the epoch root, the objects open to the state.
    let (st, g) = call(
        &app,
        "GET",
        &format!("{p}/grants?recipient_key={}", bob.enc.public_hex()),
        &bob.login,
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let grants: Vec<Grant> = serde_json::from_value(g["grants"].clone()).unwrap();
    let (_, epochs) = call(&app, "GET", &format!("{p}/epochs"), &bob.login, Value::Null).await;
    let key_id = epochs["epochs"][0]["record"]["key_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let opened = grants[0]
        .open_root(&alice.signing(), &bob.enc, &key_id)
        .unwrap();
    assert_eq!(opened.as_bytes(), root1.as_bytes());
    let mut fetched = BTreeMap::new();
    for (a, _) in &written.objects {
        let a_str = a.as_str();
        let (st, o) = call(
            &app,
            "GET",
            &format!("/projects/{project}/history/commits/{address}/objects/{doc}/{a_str}"),
            &bob.login,
            Value::Null,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{o}");
        fetched.insert(
            a.clone(),
            STANDARD.decode(o["bytes"].as_str().unwrap()).unwrap(),
        );
    }
    let held = BTreeMap::from([(1, epoch_keys(&opened, 1, project, doc))]);
    assert_eq!(
        state::read(&written.root, &fetched, project, doc, &held)
            .unwrap()
            .0,
        state1
    );
    // Carol cannot fetch Bob's device grant.
    let (_, g) = call(
        &app,
        "GET",
        &format!("{p}/grants?recipient_key={}", bob.enc.public_hex()),
        &carol.login,
        Value::Null,
    )
    .await;
    assert!(g["grants"].as_array().unwrap().is_empty());

    // The browser path (decision 041): leaves sealed outside the engine, the graph assembled
    // over them, an incremental second version. The storage scan below covers it too.
    let mut state2 = state1.clone();
    state2
        .nodes
        .get_mut(&NodeId("A".into()))
        .unwrap()
        .current_fields = json!({"label": "ZEUS-CANARY-second edit"});
    state2
        .comments
        .push(engine_core::materializer::CommentState {
            node_id: Some(NodeId("A".into())),
            body: "ZEUS-CANARY-browser comment".into(),
        });
    let k1 = epoch_keys(&root1, 1, project, doc);
    let previous = Some((&state1, &written.nodes));
    let leaves = state::leaves(&state2, previous).unwrap();
    assert_eq!(
        leaves.len(),
        2,
        "only the edited block and the comment are re-sealed"
    );
    let sealed_leaves: Vec<Vec<u8>> = leaves
        .iter()
        .map(|l| {
            let ctx = seal::Context {
                project,
                document: Some(doc),
                node: &l.node,
                kind: l.kind,
                epoch: 1,
                revision: l.revision,
            };
            seal::seal(&k1.doc, k1.key_id, &k1.cid, &ctx, &[], &l.value).unwrap()
        })
        .collect();
    let written2 = state::assemble(&state2, 1, previous, sealed_leaves).unwrap();
    assert_eq!(
        written2.nodes["R"], written.nodes["R"],
        "an unchanged block keeps its object"
    );
    let objects: Vec<Value> = written2
        .objects
        .iter()
        .map(|(a, b)| json!({"address": a, "bytes": STANDARD.encode(b)}))
        .collect();
    let (st, b) = call(
        &app,
        "POST",
        &format!("/projects/{project}/staging/objects"),
        &alice.login,
        json!({"document": doc, "objects": objects}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let (_, membership_head) = head(&app, project, &alice.login).await;
    let second = SignedCommit::sign(
        Commit {
            version: 4,
            project,
            parents: vec![signed.verify().unwrap()],
            files: BTreeMap::from([(
                doc.to_string(),
                FileEntry {
                    document: DocumentId(doc),
                    state: written2.root.clone(),
                },
            )]),
            author_key: String::new(),
            authored_at_ms: 1_791_000_000_001,
            message: String::new(),
            recovery: None,
            same_file_resolutions: Vec::new(),
            merge_policy: None,
            project_resolutions: Vec::new(),
            relocations: Vec::new(),
            sealed: Some(Box::new(Sealed {
                epoch: 1,
                membership_head,
                message: meta_envelope(
                    &root1,
                    1,
                    project,
                    commit::MESSAGE_NODE,
                    json!("ZEUS-CANARY-second message"),
                ),
                paths: meta_envelope(
                    &root1,
                    1,
                    project,
                    commit::PATHS_NODE,
                    json!({doc.to_string(): "ZEUS-CANARY-Board minutes.docx"}),
                ),
            })),
        },
        &alice.sign,
    )
    .unwrap();
    let (st, b) = call(
        &app,
        "POST",
        &format!("/projects/{project}/staging/commits"),
        &alice.login,
        json!(second),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let second_address = second.verify().unwrap().as_str().to_owned();
    let (st, b) = call(
        &app,
        "POST",
        &format!("/projects/{project}/history/commits"),
        &alice.login,
        json!({"address": second_address}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");

    // Plaintext-only features answer 422 with their alternative.
    for (method, uri, feature) in [
        ("GET", format!("/documents/{doc}/structure"), "server_diff"),
        (
            "POST",
            format!("/documents/{doc}/ops/field-edit"),
            "web_block_edit",
        ),
        ("POST", format!("/documents/{doc}/batch"), "web_block_edit"),
        (
            "GET",
            format!("/documents/{doc}/versions"),
            "server_restore",
        ),
        (
            "POST",
            format!("/documents/{doc}/drafts"),
            "drafts_autosave",
        ),
        (
            "GET",
            format!("/documents/{doc}/change-requests"),
            "server_review_rendering",
        ),
        ("GET", format!("/documents/{doc}/copies"), "similarity"),
        (
            "GET",
            format!("/connector/documents/{doc}/checkpoint"),
            "office_google_addins",
        ),
    ] {
        let (st, b) = call(&app, method, &uri, &alice.login, json!({})).await;
        assert_eq!(
            (st, b["code"].as_str(), b["details"]["feature"].as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Some("encrypted_project"),
                Some(feature)
            ),
            "{uri}: {b}"
        );
        assert!(!b["details"]["alternative"].as_str().unwrap().is_empty());
    }
    // A percent-encoded id names the same document to the router; the guard refuses it.
    let text = doc.to_string();
    let uri = format!(
        "/documents/%{:02x}{}/versions",
        text.as_bytes()[0],
        &text[1..]
    );
    let (st, b) = call(&app, "GET", &uri, &alice.login, Value::Null).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{uri}: {b}");

    // Remove Carol: one request removes her and opens epoch 2 for Alice and Bob only.
    let (n, h) = head(&app, project, &alice.login).await;
    let removal = entry(
        project,
        n,
        Some(&h),
        "member_remove",
        json!({"identity": carol.id.to_string()}),
        &alice,
    );
    let root2 = Key::from_bytes([0x52; 32]);
    let (st, b, _) = open_epoch(
        &app,
        project,
        2,
        Some(rec1.clone()),
        &root2,
        &alice,
        &[&alice, &bob, &carol],
        Some(removal.clone()),
    )
    .await;
    assert_ne!(
        st,
        StatusCode::CREATED,
        "a grant to the removed member is refused: {b}"
    );
    let (st, b, rec2) = open_epoch(
        &app,
        project,
        2,
        Some(rec1),
        &root2,
        &alice,
        &[&alice, &bob],
        Some(removal),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{b}");
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{p}/grants?recipient_key={}", carol.enc.public_hex()),
            &carol.login,
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "no longer a member"
    );
    let carol_epoch2: i64 = sqlx::query_scalar(
        "select count(*) from project_key_grant where recipient_key=$1 and epoch=2",
    )
    .bind(carol.enc.public_hex())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(carol_epoch2, 0);
    let all_epoch2: Vec<Vec<u8>> =
        sqlx::query_scalar("select grant_body from project_key_grant where epoch=2")
            .fetch_all(&pool)
            .await
            .unwrap();
    for body in &all_epoch2 {
        let g: Grant = serde_json::from_slice(body).unwrap();
        assert!(
            g.open(&alice.signing(), &carol.enc).is_err(),
            "carol's key opens no epoch-2 grant"
        );
    }
    // Wrong signatures are refused: a record signed by Bob's key, a grant re-signed by Bob.
    let (st, b, _) = open_epoch(
        &app,
        project,
        3,
        Some(rec2),
        &Key::from_bytes([0x53; 32]),
        &bob,
        &[&alice, &bob],
        None,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "an editor cannot open an epoch: {b}"
    );
    let mut forged = grant_for(project, 2, &hex::encode([0u8; 32]), &bob, &root2, &alice);
    forged.signature = hex::encode(bob.sign.sign(b"other").as_ref());
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{p}/grants"),
            &alice.login,
            json!({"grants": [forged]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    // Storage scan: no plaintext, no epoch root, no derived or private key anywhere.
    let mut needles = vec![
        CANARY.to_owned(),
        hex::encode(CANARY),
        "ZEUS-CANARY".into(),
        hex::encode("ZEUS-CANARY"),
    ];
    for root in [&root1, &root2] {
        needles.push(hex::encode(root.as_bytes()));
        needles.push(hex::encode(
            keys::doc_key(root, project, doc).unwrap().as_bytes(),
        ));
        needles.push(hex::encode(keys::meta_key(root).unwrap().as_bytes()));
    }
    for m in [&alice, &bob, &carol] {
        needles.push(hex::encode(m.enc.secret().unwrap().as_bytes()));
    }
    let tables: Vec<String> = sqlx::query_scalar("select table_name::text from information_schema.tables where table_schema='public' and table_type='BASE TABLE'").fetch_all(&pool).await.unwrap();
    for t in tables {
        let dump: Option<String> = sqlx::query_scalar(&format!(
            "select string_agg(t::text, E'\\n') from \"{t}\" t"
        ))
        .fetch_one(&pool)
        .await
        .unwrap();
        let dump = dump.unwrap_or_default().to_lowercase();
        if t == "checkpoint_object" {
            // The dump includes stored bytes (as hex): the scan sees what a thief would.
            assert!(dump.contains(&hex::encode(seal::MAGIC)), "scan control");
        }
        for needle in &needles {
            assert!(
                !dump.contains(&needle.to_lowercase()),
                "table {t} holds a secret or plaintext value"
            );
        }
    }
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_plaintext_project_refuses_sealed_objects_and_creation_needs_the_switch(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let app = router(runtime.pool.clone());
    let alice = member(&app, &runtime.pool, "alice", 21).await;
    let (_, project) = call(
        &app,
        "POST",
        "/projects",
        &alice.login,
        json!({"name": "Plain"}),
    )
    .await;
    let project: Uuid = serde_json::from_value(project["id"].clone()).unwrap();
    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Plain',$1,$2) returning id",
    )
    .bind(alice.id)
    .bind(project)
    .fetch_one(&pool)
    .await
    .unwrap();
    let root = Key::from_bytes([3; 32]);
    let ctx = Context {
        project,
        document: Some(doc),
        node: "A",
        kind: Kind::NodeFields,
        epoch: 1,
        revision: 1,
    };
    let bytes = seal::seal(
        &keys::doc_key(&root, project, doc).unwrap(),
        keys::key_id(1, &root),
        &keys::cid_key(&root).unwrap(),
        &ctx,
        &[],
        &json!({"label": "x"}),
    )
    .unwrap();
    let (st, b) = call(&app, "POST", &format!("/projects/{project}/staging/objects"), &alice.login, json!({"document": doc, "objects": [{"address": seal::address(&bytes).unwrap(), "bytes": STANDARD.encode(&bytes)}]})).await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("mode_mismatch")),
        "{b}"
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/projects/{project}/e2ee/documents"),
            &alice.login,
            Value::Null
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (st, caps) = call(&app, "GET", "/capabilities", "", Value::Null).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        caps["e2ee"]["status"],
        "pre-release, not independently reviewed"
    );
    // Without E2EE_ALLOW_CREATE an owner cannot begin.
    let closed = app_without_switch(runtime.pool.clone());
    let genesis = entry(
        project,
        0,
        None,
        "genesis",
        json!({"identity": alice.id.to_string(), "signing_key": alice.signing(), "encryption_key": alice.enc.public_hex()}),
        &alice,
    );
    assert_eq!(
        call(
            &closed,
            "POST",
            &format!("/projects/{project}/e2ee/begin"),
            &alice.login,
            json!({"genesis": genesis})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    runtime.close().await;
}

fn app_without_switch(pool: PgPool) -> Router {
    app(AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    ))
}

/// OQ-PR-4 (owner decision of 6 November 2026): legacy plaintext of a project that moved to
/// encryption is erased only when its owner asks and a different administrator confirms, both
/// as people (agents and connector keys refused), through the audited erasure with a receipt.
#[sqlx::test(migrations = "../../migrations")]
async fn legacy_plaintext_erasure_needs_the_owner_and_another_administrator(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let mut state = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.admin_emails = "alice@example.test,admin@example.test".into();
    let app = app(state);
    let alice = member(&app, &runtime.pool, "alice", 41).await;
    let admin = member(&app, &runtime.pool, "admin", 42).await;
    // An AI agent's identity: born disabled, kind agent, no email (schemas 44 and 117).
    let agent = Uuid::new_v4();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "insert into identity(id,display_name,disabled_at,kind) values($1,'Agent',now(),'agent')",
    )
    .bind(agent)
    .execute(&mut *tx)
    .await
    .unwrap();
    let refused = [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN];
    sqlx::query("insert into agent_identity(identity_id,principal_id,client_kind,client_ref) values($1,$2,'claude','k')")
        .bind(agent).bind(alice.id).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let agent_login = token::mint(&KEY, agent, 3600).unwrap();
    let (_, project) = call(
        &app,
        "POST",
        "/projects",
        &alice.login,
        json!({"name": "Moved"}),
    )
    .await;
    let project: Uuid = serde_json::from_value(project["id"].clone()).unwrap();
    let doc: Uuid = sqlx::query_scalar("insert into document(title,created_by,space_id,status) values('Old notes',$1,$2,'archived') returning id")
        .bind(alice.id).bind(project).fetch_one(&pool).await.unwrap();
    let ask = format!("/documents/{doc}/e2ee/legacy-erasure");

    // Only after the project completed its move to encryption.
    let (st, b) = call(&app, "POST", &ask, &alice.login, Value::Null).await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("not_legacy_plaintext")),
        "{b}"
    );
    sqlx::query("update project_settings set encryption_mode='sealed' where space_id=$1")
        .bind(project)
        .execute(&pool)
        .await
        .unwrap();
    // Not an agent, not a connector key, not someone who does not own the file.
    assert!(refused.contains(&call(&app, "POST", &ask, &agent_login, Value::Null).await.0));
    assert_eq!(
        call(
            &app,
            "POST",
            &ask,
            "dk_connector_key_not_a_login",
            Value::Null
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "POST", &ask, &admin.login, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    let (st, asked) = call(&app, "POST", &ask, &alice.login, Value::Null).await;
    assert_eq!(st, StatusCode::CREATED, "{asked}");
    let request = asked["id"].as_str().unwrap().to_owned();
    assert_eq!(
        call(&app, "POST", &ask, &alice.login, Value::Null).await.0,
        StatusCode::CONFLICT
    );
    let (st, list) = call(
        &app,
        "GET",
        "/admin/e2ee/legacy-erasures",
        &admin.login,
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list["items"][0]["id"].as_str(), Some(request.as_str()));

    let confirm = format!("/admin/e2ee/legacy-erasures/{request}/confirm");
    let body = json!({"confirmation": "Old notes", "acknowledge_backups": true});
    // The person who asked cannot confirm, even as an administrator; nor can an agent.
    assert_eq!(
        call(&app, "POST", &confirm, &alice.login, body.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert!(refused.contains(
        &call(&app, "POST", &confirm, &agent_login, body.clone())
            .await
            .0
    ));
    assert_eq!(
        call(
            &app,
            "POST",
            &confirm,
            &admin.login,
            json!({"confirmation": "Old", "acknowledge_backups": true})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        sqlx::query_scalar::<_, bool>("select exists(select 1 from document where id=$1)")
            .bind(doc)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    let (st, done) = call(&app, "POST", &confirm, &admin.login, body.clone()).await;
    assert_eq!(st, StatusCode::OK, "{done}");

    assert!(
        !sqlx::query_scalar::<_, bool>("select exists(select 1 from document where id=$1)")
            .bind(doc)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    let receipt: (String, Uuid, String) =
        sqlx::query_as("select kind,actor_id,reason from erasure_receipt where resource_id=$1")
            .bind(doc)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        receipt,
        ("documents".into(), admin.id, "owner_request".into())
    );
    let actions: Vec<(String, Uuid)> = sqlx::query_as("select action,actor_id from operation_audit where resource_id=$1 and action like 'e2ee.legacy_erasure_%' order by created_at")
        .bind(doc).fetch_all(&pool).await.unwrap();
    assert_eq!(
        actions,
        vec![
            ("e2ee.legacy_erasure_requested".into(), alice.id),
            ("e2ee.legacy_erasure_confirmed".into(), admin.id),
        ]
    );
    let who: (Uuid, Option<Uuid>) = sqlx::query_as(
        "select requested_by,confirmed_by from legacy_erasure_request where document_id=$1",
    )
    .bind(doc)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(who, (alice.id, Some(admin.id)));
    assert_eq!(
        call(&app, "POST", &confirm, &admin.login, body).await.0,
        StatusCode::NOT_FOUND
    );
    runtime.close().await;
}

/// OQ-CR-5: a signing key can bind a new encryption key (the newest is current in the
/// directory), and another account cannot bind that key.
#[sqlx::test(migrations = "../../migrations")]
async fn either_device_key_rotates_without_the_other(pool: PgPool) {
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let app = router(runtime.pool.clone());
    let alice = member(&app, &runtime.pool, "alice", 51).await;
    let bob = member(&app, &runtime.pool, "bob", 52).await;
    let authority: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(&pool)
        .await
        .unwrap();
    let register = |who: &Member, key_id: Uuid, enc: &str| {
        let binding = Binding {
            version: 1,
            authority,
            identity: who.id,
            signing_key: who.signing(),
            encryption_key: enc.to_owned(),
            created_at_ms: 1_791_000_000_000,
        };
        let signature = binding.sign(&who.sign).unwrap();
        (
            format!("/devices/{key_id}/encryption-key"),
            json!({"public_key": enc, "binding": binding, "signature": signature}),
        )
    };
    let signing_key = |device: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "select signing_key_id from device_encryption_key where id=$1",
            )
            .bind(device)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    // A new encryption key for the same signing key.
    let fresh = DeviceKey::from_secret(&Key::from_bytes([77; 32]))
        .unwrap()
        .public_hex();
    let (uri, body) = register(&alice, signing_key(alice.device).await, &fresh);
    let (st, b) = call(&app, "POST", &uri, &alice.login, body.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "{b}");
    assert_eq!(
        call(&app, "POST", &uri, &alice.login, body).await.0,
        StatusCode::CONFLICT
    );
    let (_, project) = call(
        &app,
        "POST",
        "/projects",
        &alice.login,
        json!({"name": "Keys"}),
    )
    .await;
    let project: Uuid = serde_json::from_value(project["id"].clone()).unwrap();
    let (st, dir) = call(
        &app,
        "GET",
        &format!("/projects/{project}/e2ee/directory"),
        &alice.login,
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{dir}");
    let listed = dir.to_string();
    assert!(
        listed.contains(&fresh) && !listed.contains(&alice.enc.public_hex()),
        "{dir}"
    );
    // Bob cannot bind Alice's encryption key to his signing key.
    let (uri, body) = register(&bob, signing_key(bob.device).await, &fresh);
    assert_eq!(
        call(&app, "POST", &uri, &bob.login, body).await.0,
        StatusCode::CONFLICT
    );
    runtime.close().await;
}
