//! Shared history horizons, the transparency log and the object collector through the
//! real router and the restricted runtime login (decision 032). Trust boundaries:
//! no horizon without the receipt authority, owner signatures by active owner keys
//! only, no record that the plan does not describe, released commits answer 410,
//! bytes go only after the quarantine and only through the batch guard, the log's
//! checkpoints, inclusion and consistency proofs verify, and a witness lifts L1 to L2.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use engine_api::{
    app,
    auth::{store, token, AuthConfig},
    transparency::{add_cosignature, integrate, Transparency},
    AppState,
};
use engine_core::{
    materializer::DocumentState,
    repository::{
        device::{Challenge, Proof},
        horizon::{self, Envelope, HorizonRecord, Role, Scope},
        server_authority, Commit, FileEntry, SignedCommit,
    },
    shared_checkpoint::{typed, Address, Limits, MemoryStore, ObjectStore},
    transparency::{
        assess,
        witness::{AddCheckpoint, Witness},
        InclusionBundle, KeyKind, KnownCheckpoints, Level, Note, Origin, Policy, Signer,
    },
};
use engine_shared::DocumentId;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;
use tower::ServiceExt;
use uuid::Uuid;
mod common;

const KEY: [u8; 32] = [9; 32];
const ORIGIN: &str = "log.test.local/dynodoc/v1/transparency";

fn signer(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn public(seed: u8) -> String {
    hex::encode(signer(seed).public_key().as_ref())
}
fn router(pool: PgPool, authority: Option<u8>) -> Router {
    let mut state = AppState::new(
        pool,
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.ref_signer = authority.map(|s| std::sync::Arc::new(signer(s)));
    // The test releases at once; deployments keep the 14-day floor.
    state.horizon_min_quarantine_days = 0;
    state.transparency = Some(Transparency::new(Origin::new(ORIGIN).unwrap()));
    app(state)
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn ok(app: &Router, method: &str, path: &str, token: &str, body: Value) -> Value {
    let (status, result) = request(app, method, path, token, body).await;
    assert_eq!(status, StatusCode::OK, "{path}: {result}");
    result
}

#[derive(Default)]
struct Collect {
    inner: MemoryStore,
    objects: BTreeMap<Address, Vec<u8>>,
}
impl ObjectStore for Collect {
    async fn put(
        &mut self,
        doc: DocumentId,
        address: &Address,
        bytes: &[u8],
    ) -> Result<bool, engine_core::shared_checkpoint::Error> {
        self.objects.insert(address.clone(), bytes.to_vec());
        self.inner.put(doc, address, bytes).await
    }
    async fn get(
        &mut self,
        doc: DocumentId,
        address: &Address,
    ) -> Result<Vec<u8>, engine_core::shared_checkpoint::Error> {
        self.inner.get(doc, address).await
    }
}
fn state(label: &str) -> DocumentState {
    let node = engine_core::materializer::MaterializedNode {
        id: engine_shared::NodeId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        parent_id: None,
        node_type: "paragraph".into(),
        pos: "a0".into(),
        var_name: None,
        deleted: false,
        current_fields: json!({"label":label, "runs":[{"text":label}]}),
    };
    DocumentState {
        nodes: BTreeMap::from([(node.id.clone(), node)]),
        ..Default::default()
    }
}

struct World {
    login: String,
    project: Uuid,
    document: Uuid,
    commits: Vec<Address>,
}

/// One owner, one enrolled key (seed 7), six published commits in a line, each with
/// its own Report state, and `main` at the last.
async fn world(runtime: &PgPool, app: &Router) -> World {
    let actor = store::upsert_identity(runtime, "owner@example.test", None)
        .await
        .unwrap()
        .id
        .0;
    let login = token::mint(&KEY, actor, 3600).unwrap();
    let project: Uuid = serde_json::from_value(
        ok(app, "POST", "/projects", &login, json!({"name":"Horizons"})).await["id"].clone(),
    )
    .unwrap();
    let document: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Report',$1,$2) returning id",
    )
    .bind(actor)
    .bind(project)
    .fetch_one(runtime)
    .await
    .unwrap();
    let challenge: Challenge = serde_json::from_value(
        ok(
            app,
            "POST",
            "/devices/challenge",
            &login,
            json!({"public_key":public(7)}),
        )
        .await,
    )
    .unwrap();
    let proof = Proof::sign(challenge.clone(), challenge.authority, actor, &signer(7)).unwrap();
    ok(app, "POST", "/devices", &login, json!(proof)).await;
    let mut commits: Vec<Address> = Vec::new();
    for i in 0..6 {
        let mut store = Collect::default();
        let (root, _) = typed::write_state(
            &mut store,
            DocumentId(document),
            &state(&format!("version {i}")),
            Limits::default(),
            Default::default(),
        )
        .await
        .unwrap();
        let objects: Vec<Value> = store
            .objects
            .into_iter()
            .map(|(a, b)| json!({"address":a,"bytes":STANDARD.encode(b)}))
            .collect();
        ok(
            app,
            "POST",
            &format!("/projects/{project}/staging/objects"),
            &login,
            json!({"document":document,"objects":objects}),
        )
        .await;
        let signed = SignedCommit::sign(
            Commit {
                version: 1,
                project,
                parents: commits.last().cloned().into_iter().collect(),
                files: BTreeMap::from([(
                    "Report.docx".into(),
                    FileEntry {
                        document: DocumentId(document),
                        state: root,
                    },
                )]),
                author_key: String::new(),
                authored_at_ms: 1,
                message: format!("c{i}"),
                recovery: None,
                same_file_resolutions: Vec::new(),
                sealed: None,
                project_resolutions: Vec::new(),
                relocations: Vec::new(),
                merge_policy: None,
            },
            &signer(7),
        )
        .unwrap();
        ok(
            app,
            "POST",
            &format!("/projects/{project}/staging/commits"),
            &login,
            json!(signed),
        )
        .await;
        let address = signed.verify().unwrap();
        ok(
            app,
            "POST",
            &format!("/projects/{project}/history/commits"),
            &login,
            json!({"address":address}),
        )
        .await;
        commits.push(address);
    }
    World {
        login,
        project,
        document,
        commits,
    }
}

fn policy(quarantine_days: u32) -> Value {
    json!({"version":1,"id":"team","tier":"history","window":{"keep_last_commits":2},
           "protect":{"branch_heads":true},"signatures":{"required":2},"quarantine_days":quarantine_days})
}

#[sqlx::test(migrations = "../../migrations")]
async fn shared_horizons_need_the_authority_owner_signatures_and_an_exact_plan(pool: PgPool) {
    server_authority::install(&pool, &public(99)).await.unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let api = router(runtime.pool.clone(), Some(99));
    let w = world(&runtime.pool, &api).await;
    let main = ok(
        &api,
        "POST",
        &format!("/projects/{}/history/refs", w.project),
        &w.login,
        json!({"branch":"main","candidate":w.commits[5],"expected":null}),
    )
    .await;
    let horizons = format!("/projects/{}/history/horizons", w.project);

    // Plan: the head and its parent stay, four commits would be released.
    let planned = ok(
        &api,
        "POST",
        &format!("{horizons}/plan"),
        &w.login,
        json!({"policy":policy(0)}),
    )
    .await;
    let record: HorizonRecord = serde_json::from_value(planned["record"].clone()).unwrap();
    assert_eq!(record.counts.commits_released, 4);
    let plan_hash = planned["plan_hash"].as_str().unwrap().to_owned();
    let owner = horizon::sign(&record, Role::Owner, &signer(7)).unwrap();
    let create = |record: &HorizonRecord, signatures: Vec<horizon::Signature>| json!({"policy":policy(0),"plan_hash":plan_hash,"record":record,"signatures":signatures});

    // The deployment default keeps released bytes for at least 14 days.
    let mut floor = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    floor.ref_signer = Some(std::sync::Arc::new(signer(99)));
    assert_eq!(floor.horizon_min_quarantine_days, 14);
    let (status, _) = request(
        &app(floor),
        "POST",
        &format!("{horizons}/plan"),
        &w.login,
        json!({"policy":policy(0)}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Without the receipt authority no horizon can exist.
    let without = router(runtime.pool.clone(), None);
    let (status, _) = request(
        &without,
        "POST",
        &horizons,
        &w.login,
        create(&record, vec![owner.clone()]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A signature by a key that is no enrolled owner key, and a record claiming more.
    let stranger = horizon::sign(&record, Role::Owner, &signer(8)).unwrap();
    assert_eq!(
        request(
            &api,
            "POST",
            &horizons,
            &w.login,
            create(&record, vec![stranger])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut forged = record.clone();
    forged.counts.commits_released += 1;
    let forged_sig = horizon::sign(&forged, Role::Owner, &signer(7)).unwrap();
    assert_eq!(
        request(
            &api,
            "POST",
            &horizons,
            &w.login,
            create(&forged, vec![forged_sig])
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    // Nothing was released by the refusals.
    ok(
        &api,
        "GET",
        &format!(
            "/projects/{}/history/commits/{}",
            w.project,
            w.commits[0].as_str()
        ),
        &w.login,
        Value::Null,
    )
    .await;

    let created = ok(
        &api,
        "POST",
        &horizons,
        &w.login,
        create(&record, vec![owner]),
    )
    .await;
    let envelope: Envelope = serde_json::from_value(created["envelope"].clone()).unwrap();
    envelope.verify(Scope::Shared, 2).unwrap();
    assert!(envelope
        .signatures
        .iter()
        .any(|s| s.role == Role::Authority && s.key == public(99)));
    // Released commits answer 410 with their skeleton at once.
    let (status, gone) = request(
        &api,
        "GET",
        &format!(
            "/projects/{}/history/commits/{}",
            w.project,
            w.commits[0].as_str()
        ),
        &w.login,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::GONE, "{gone}");
    assert_eq!(gone["code"], "history_pruned");
    // The skeleton served reproduces the signed root.
    let page = ok(
        &api,
        "GET",
        &format!("{horizons}/1/skeleton"),
        &w.login,
        Value::Null,
    )
    .await;
    let entries: Vec<horizon::SkeletonEntry> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .collect();
    assert_eq!(
        horizon::skeleton_root(&entries).unwrap(),
        envelope.horizon.roots.skeleton
    );
    // The runtime login cannot delete a released body itself.
    assert!(
        sqlx::query("delete from project_published_commit where project_id=$1 and address=$2")
            .bind(w.project)
            .bind(w.commits[0].as_str())
            .execute(&runtime.pool)
            .await
            .is_err()
    );
    // Release (no quarantine in this policy): bodies and reachability rows go.
    let released = ok(
        &api,
        "POST",
        &format!("{horizons}/1/release"),
        &w.login,
        Value::Null,
    )
    .await;
    assert_eq!(released["phase"], "released", "{released}");
    let bodies: i64 =
        sqlx::query_scalar("select count(*) from project_published_commit where project_id=$1")
            .bind(w.project)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bodies, 2);

    // An old replica publishes work based on a released commit: accepted.
    let parent = w.commits[1].clone();
    let head_state = SignedCommit::sign(
        Commit {
            version: 1,
            project: w.project,
            parents: vec![parent],
            files: BTreeMap::new(),
            author_key: String::new(),
            authored_at_ms: 2,
            message: "offline work".into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
            sealed: None,
            project_resolutions: Vec::new(),
            relocations: Vec::new(),
            merge_policy: None,
        },
        &signer(7),
    )
    .unwrap();
    ok(
        &api,
        "POST",
        &format!("/projects/{}/staging/commits", w.project),
        &w.login,
        json!(head_state),
    )
    .await;

    // The object collector: every released object is still held by the publisher's
    // private staged copy (immutable outside erasure), so nothing may go yet.
    let held = engine_api::object_collector::plan(&pool, w.document)
        .await
        .unwrap();
    assert!(held.sweep.is_empty() && held.candidates == 0, "{held:?}");
    // A released state no root holds (written by the operator to model expired copies):
    // exactly its objects are swept.
    let mut orphan = Collect::default();
    let (orphan_root, _) = typed::write_state(
        &mut orphan,
        DocumentId(w.document),
        &state("orphan"),
        Limits::default(),
        Default::default(),
    )
    .await
    .unwrap();
    // Objects it shares with live states already exist and stay held.
    let mut fresh = 0;
    for (address, bytes) in &orphan.objects {
        fresh += sqlx::query("insert into checkpoint_object(document_id,address,bytes) values($1,$2,$3) on conflict do nothing")
            .bind(w.document)
            .bind(address.as_str())
            .bind(bytes)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected() as usize;
    }
    assert!(fresh > 0);
    sqlx::query("insert into project_history_released_state(project_id,document_id,state_root,horizon_sequence) values($1,$2,$3,1)")
        .bind(w.project)
        .bind(w.document)
        .bind(orphan_root.as_str())
        .execute(&pool)
        .await
        .unwrap();
    // The runtime login cannot delete checkpoint bytes outside a collection.
    assert!(
        sqlx::query("delete from checkpoint_object where document_id=$1 and address=$2")
            .bind(w.document)
            .bind(orphan_root.as_str())
            .execute(&runtime.pool)
            .await
            .is_err()
    );
    let before: i64 =
        sqlx::query_scalar("select count(*) from checkpoint_object where document_id=$1")
            .bind(w.document)
            .fetch_one(&pool)
            .await
            .unwrap();
    let plan = engine_api::object_collector::plan(&pool, w.document)
        .await
        .unwrap();
    assert_eq!(plan.sweep.len(), fresh, "{plan:?}");
    assert!(
        engine_api::object_collector::apply(&pool, w.document, &"0".repeat(64))
            .await
            .is_err()
    );
    engine_api::object_collector::apply(&pool, w.document, &plan.plan_hash)
        .await
        .unwrap();
    let after: i64 =
        sqlx::query_scalar("select count(*) from checkpoint_object where document_id=$1")
            .bind(w.document)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after, before - plan.sweep.len() as i64);
    // The retained head's state is still complete.
    let head = ok(
        &api,
        "GET",
        &format!(
            "/projects/{}/history/commits/{}",
            w.project,
            w.commits[5].as_str()
        ),
        &w.login,
        Value::Null,
    )
    .await;
    let root = head["commit"]["files"]["Report.docx"]["state"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        &api,
        "GET",
        &format!(
            "/projects/{}/history/commits/{}/objects/{}",
            w.project,
            w.commits[5].as_str(),
            w.document
        ),
        &w.login,
        Value::Null,
    )
    .await;
    assert!(!plan.sweep.contains(&root));

    // Transparency: the receipt and the horizon were enqueued; the worker logs them.
    let log_key = Signer::from_seed(ORIGIN, KeyKind::Log, &[3; 32]).unwrap();
    let witness_key =
        Signer::from_seed("witness.test.local/w", KeyKind::Cosigner, &[4; 32]).unwrap();
    let origin = Origin::new(ORIGIN).unwrap();
    let step = integrate(&pool, &log_key, &origin).await.unwrap().unwrap();
    assert_eq!(step.leaves, 2);
    assert!(integrate(&pool, &log_key, &origin).await.unwrap().is_none());
    let trust = Policy::from_json(
        json!({"version":1,"log":{"origin":ORIGIN,"vkey":log_key.verifier_key().to_string()},
               "witnesses":[{"name":"witness.test.local/w","vkey":witness_key.verifier_key().to_string(),"operator":"partner"}],
               "quorum":{"threshold":1,"distinct_operators":true},"freshness":{"max_age_seconds":86400},"on_failure":"reject"})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let receipt = main["signed_receipt"]["receipt"].clone();
    let receipt_address: Address = serde_json::from_value::<
        engine_core::repository::attestation::SignedReceipt,
    >(main["signed_receipt"].clone())
    .unwrap()
    .verify()
    .unwrap();
    assert_eq!(receipt["head"]["generation"], 1);
    let bundle = |app: Router| {
        let path = format!(
            "/projects/{}/history/transparency/inclusion?subject={}",
            w.project,
            receipt_address.as_str()
        );
        let login = w.login.clone();
        async move {
            InclusionBundle::from_json(
                &serde_json::to_vec(&ok(&app, "GET", &path, &login, Value::Null).await).unwrap(),
            )
            .unwrap()
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let known = KnownCheckpoints::new(&origin);
    let first = bundle(api.clone()).await;
    let l1 = assess(
        &trust,
        &first,
        None,
        &known,
        &engine_core::transparency::NoProofs,
        now,
    );
    assert_eq!(
        (l1.level, l1.rejection.is_none()),
        (Level::L1, true),
        "{l1:?}"
    );
    // One external witness cosigns: L2.
    let witness = Witness::new(witness_key, vec![log_key.verifier_key()]).unwrap();
    let (_, line) = witness
        .decide(
            None,
            &AddCheckpoint {
                old_size: 0,
                proof: vec![],
                note: step.note.clone(),
            },
            now,
        )
        .unwrap();
    add_cosignature(&pool, step.size, &witness.verifier_key(), &line.encode())
        .await
        .unwrap();
    // A line by another key is refused, never stored.
    let impostor = Signer::from_seed("witness.test.local/w", KeyKind::Cosigner, &[5; 32]).unwrap();
    let forged_line = impostor.cosign_checkpoint(step.note.text(), now).unwrap();
    assert!(add_cosignature(
        &pool,
        step.size,
        &witness.verifier_key(),
        &forged_line.encode()
    )
    .await
    .is_err());
    let second = bundle(api.clone()).await;
    let l2 = assess(
        &trust,
        &second,
        None,
        &known,
        &engine_core::transparency::NoProofs,
        now,
    );
    assert_eq!(l2.level, Level::L2, "{l2:?}");
    // The public checkpoint carries the cosignature; consistency proofs verify.
    let checkpoint = Note::parse(second.checkpoint.as_bytes()).unwrap();
    assert!(checkpoint
        .verify(&witness.verifier_key())
        .unwrap()
        .is_some());
    let mut known = KnownCheckpoints::new(&origin);
    known.record(l2.trusted_checkpoint().unwrap()).unwrap();
    // A later receipt: a new checkpoint, consistent with the one the client knows.
    let generation = ok(
        &api,
        "POST",
        &format!("/projects/{}/history/refs", w.project),
        &w.login,
        json!({"branch":"feature","candidate":w.commits[5],"expected":null}),
    )
    .await;
    let next = integrate(&pool, &log_key, &origin).await.unwrap().unwrap();
    assert_eq!((next.old_size, next.size), (2, 3));
    let proof = ok(
        &api,
        "GET",
        &format!(
            "/projects/{}/history/transparency/consistency?first=2&second=3",
            w.project
        ),
        &w.login,
        Value::Null,
    )
    .await;
    let hashes: Vec<[u8; 32]> = proof["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            hex::decode(h.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    engine_core::transparency::merkle::verify_consistency(2, 3, &step.root, &next.root, &hashes)
        .unwrap();
    let mut tampered = hashes.clone();
    tampered[0][0] ^= 1;
    assert!(engine_core::transparency::merkle::verify_consistency(
        2, 3, &step.root, &next.root, &tampered
    )
    .is_err());
    assert!(generation["signed_receipt"].is_object());
    // Every new table is immutable for the runtime login and its own outbox rows.
    assert!(sqlx::query("delete from transparency_outbox")
        .execute(&runtime.pool)
        .await
        .is_err());
    assert!(
        sqlx::query("insert into transparency_checkpoint(size,root,note) values(99,$1,'x')")
            .bind(vec![0u8; 32])
            .execute(&runtime.pool)
            .await
            .is_err()
    );
    runtime.close().await;
}

/// History holds (decision 042). Trust boundaries: a project hold refuses every horizon
/// and release batch, a commit hold pins its commit and blocks the release of a horizon
/// that names it, only people on account sessions with the right role set or release a
/// hold (the database refuses any other identity too), and a hold is never deleted.
#[sqlx::test(migrations = "../../migrations")]
async fn holds_block_pruning_and_only_people_set_or_release_them(pool: PgPool) {
    server_authority::install(&pool, &public(99)).await.unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let api = router(runtime.pool.clone(), Some(99));
    let w = world(&runtime.pool, &api).await;
    ok(
        &api,
        "POST",
        &format!("/projects/{}/history/refs", w.project),
        &w.login,
        json!({"branch":"main","candidate":w.commits[5],"expected":null}),
    )
    .await;
    let horizons = format!("/projects/{}/history/horizons", w.project);
    let holds = format!("/projects/{}/history/holds", w.project);
    let member = async |email: &str, role: &str| {
        let id = store::upsert_identity(&runtime.pool, email, None)
            .await
            .unwrap()
            .id
            .0;
        sqlx::query("insert into space_member(space_id,identity_id,role) values($1,$2,$3)")
            .bind(w.project)
            .bind(id)
            .bind(role)
            .execute(&pool)
            .await
            .unwrap();
        (id, token::mint(&KEY, id, 3600).unwrap())
    };
    let (_, manager) = member("manager@example.test", "manager").await;
    let (_, editor) = member("editor@example.test", "editor").await;
    let plan = async || {
        request(
            &api,
            "POST",
            &format!("{horizons}/plan"),
            &w.login,
            json!({"policy":policy(0)}),
        )
        .await
    };

    // Only an owner sets a legal hold; an editor sets no hold at all.
    let legal = json!({"reason":"legal-hold:LH-17","legal":true});
    assert_eq!(
        request(&api, "POST", &holds, &editor, json!({"reason":"keep"}))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&api, "POST", &holds, &manager, legal.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, _) = request(
        &api,
        "POST",
        &holds,
        &w.login,
        json!({"reason":"x","legal":true,"commit":w.commits[0]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let hold = ok(&api, "POST", &holds, &w.login, legal).await;
    assert_eq!(hold["active"], true);
    // While it is in force no horizon can even be planned.
    let (status, refused) = plan().await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "history_held");
    // A service identity is not a person: refused even as a project owner, by the API
    // and by the database.
    let owner: Uuid = sqlx::query_scalar("select created_by from project_history_hold where id=$1")
        .bind(Uuid::parse_str(hold["id"].as_str().unwrap()).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    let service: Uuid = sqlx::query_scalar("insert into identity(email,kind,service_owner) values('robot@example.test','service',$1) returning id")
        .bind(owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("insert into space_member(space_id,identity_id,role) values($1,$2,'owner')")
        .bind(w.project)
        .bind(service)
        .execute(&pool)
        .await
        .unwrap();
    let robot = token::mint(&KEY, service, 3600).unwrap();
    let release_path = format!("{holds}/{}/release", hold["id"].as_str().unwrap());
    assert_ne!(
        request(&api, "POST", &release_path, &robot, Value::Null)
            .await
            .0,
        StatusCode::OK
    );
    assert_ne!(
        request(&api, "POST", &holds, &robot, json!({"reason":"keep"}))
            .await
            .0,
        StatusCode::OK
    );
    assert!(sqlx::query(
        "insert into project_history_hold(project_id,reason,created_by) values($1,'keep',$2)"
    )
    .bind(w.project)
    .bind(service)
    .execute(&runtime.pool)
    .await
    .is_err());
    assert!(
        sqlx::query("update project_history_hold set released_by=$1,released_at=now()")
            .bind(service)
            .execute(&runtime.pool)
            .await
            .is_err()
    );
    // A manager cannot release a legal hold; the owner can, once.
    assert_eq!(
        request(&api, "POST", &release_path, &manager, Value::Null)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let released = ok(&api, "POST", &release_path, &w.login, Value::Null).await;
    assert_eq!(released["active"], false);
    ok(&api, "POST", &release_path, &w.login, Value::Null).await;
    // Holds are never deleted, and a released hold does not change again.
    assert!(sqlx::query("delete from project_history_hold")
        .execute(&runtime.pool)
        .await
        .is_err());
    assert!(
        sqlx::query("update project_history_hold set reason='other'")
            .execute(&runtime.pool)
            .await
            .is_err()
    );

    // A manager's hold on one commit pins it: three of the four commits are released.
    let pin = ok(
        &api,
        "POST",
        &holds,
        &manager,
        json!({"reason":"audit-2026","commit":w.commits[1]}),
    )
    .await;
    let (status, planned) = plan().await;
    assert_eq!(status, StatusCode::OK, "{planned}");
    let record: HorizonRecord = serde_json::from_value(planned["record"].clone()).unwrap();
    assert_eq!(record.counts.commits_released, 3);
    assert!(record.holds.iter().any(|h| h.commit == w.commits[1]));
    let owner_sig = horizon::sign(&record, Role::Owner, &signer(7)).unwrap();
    ok(
        &api,
        "POST",
        &horizons,
        &w.login,
        json!({"policy":policy(0),"plan_hash":planned["plan_hash"],"record":record,"signatures":[owner_sig]}),
    )
    .await;
    ok(
        &api,
        "GET",
        &format!(
            "/projects/{}/history/commits/{}",
            w.project,
            w.commits[1].as_str()
        ),
        &w.login,
        Value::Null,
    )
    .await;
    // A hold set after the horizon on a commit it released blocks the release batches.
    let late = ok(
        &api,
        "POST",
        &holds,
        &w.login,
        json!({"reason":"dispute","commit":w.commits[0]}),
    )
    .await;
    let (status, refused) = request(
        &api,
        "POST",
        &format!("{horizons}/1/release"),
        &w.login,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "history_held");
    // The database refuses the batch too, whoever inserts it.
    assert!(sqlx::query(
        "insert into project_history_horizon_batch(project_id,sequence,batch) values($1,1,1)"
    )
    .bind(w.project)
    .execute(&pool)
    .await
    .is_err());
    ok(
        &api,
        "POST",
        &format!("{holds}/{}/release", late["id"].as_str().unwrap()),
        &w.login,
        Value::Null,
    )
    .await;
    ok(
        &api,
        "POST",
        &format!("{horizons}/1/release"),
        &w.login,
        Value::Null,
    )
    .await;
    let listed = ok(&api, "GET", &holds, &w.login, Value::Null).await;
    assert_eq!(listed["items"].as_array().unwrap().len(), 3);
    assert_eq!(listed["items"][0]["id"], pin["id"]);
}
