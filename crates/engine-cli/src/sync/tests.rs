use super::*;
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use engine_api::{
    app,
    auth::{store, token, AuthConfig},
    AppState,
};
use engine_core::{
    materializer::{DocumentState, MaterializedNode},
    repository::{
        attestation::Receipt,
        device::{Challenge, Proof},
        Commit, FileEntry,
    },
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
#[path = "../../../engine-api/tests/common/mod.rs"]
mod common;
const TOKEN_KEY: [u8; 32] = [9; 32];
fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn remote(url: String, authority: Uuid) -> Remote {
    Remote {
        version: 1,
        url,
        authority,
        public_key: hex::encode(key(99).public_key().as_ref()),
    }
}
/// What an installation that never rotated serves at `history/authority`.
fn epoch_one(authority: Uuid) -> Value {
    let public = hex::encode(key(99).public_key().as_ref());
    json!({
        "authority": authority, "public_key": public, "epoch": 1, "revocation": null,
        "genesis": {"epoch": 1, "kind": "genesis", "public_key": public,
                    "installed_at_ms": 0, "statement": null, "revocation": null},
        "rotations": [], "next_epoch": null, "independent_verification_required": true
    })
}
async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, server)
}
async fn post(url: &str, path: &str, login: &str, body: Value) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{url}{path}"))
        .bearer_auth(login)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{path}: {value}");
    value
}
async fn actor(pool: &PgPool, name: &str) -> (Uuid, String) {
    let id = store::upsert_identity(pool, &format!("{name}@example.test"), None)
        .await
        .unwrap()
        .id
        .0;
    (id, token::mint(&TOKEN_KEY, id, 3600).unwrap())
}
async fn enroll(url: &str, login: &str, actor: Uuid, seed: u8) -> Ed25519KeyPair {
    let key = key(seed);
    let challenge: Challenge = serde_json::from_value(
        post(
            url,
            "devices/challenge",
            login,
            json!({"public_key":hex::encode(key.public_key().as_ref())}),
        )
        .await,
    )
    .unwrap();
    let proof = Proof::sign(challenge.clone(), challenge.authority, actor, &key).unwrap();
    // Account-wide keys, as before per-project grants; `enroll_granted` is the new
    // default mode.
    let mut body = json!(proof);
    body["project_access"] = json!("all");
    post(url, "devices", login, body).await;
    key
}
async fn enroll_granted(url: &str, login: &str, actor: Uuid, seed: u8) -> (Ed25519KeyPair, Uuid) {
    let key = key(seed);
    let challenge: Challenge = serde_json::from_value(
        post(
            url,
            "devices/challenge",
            login,
            json!({"public_key":hex::encode(key.public_key().as_ref())}),
        )
        .await,
    )
    .unwrap();
    let proof = Proof::sign(challenge.clone(), challenge.authority, actor, &key).unwrap();
    let enrolled = post(url, "devices", login, json!(proof)).await;
    assert_eq!(enrolled["project_access"], "granted");
    (key, challenge.id)
}
async fn repo(project: Uuid) -> (PathBuf, LocalRepository) {
    let path = std::env::temp_dir().join(format!("dynodoc-sync-{}.sqlite", Uuid::new_v4()));
    let repo = LocalRepository::open(&path, project).await.unwrap();
    (path, repo)
}
async fn journal() -> (PathBuf, ReceiptJournal) {
    let path = std::env::temp_dir().join(format!("dynodoc-sync-pin-{}.sqlite", Uuid::new_v4()));
    let journal = ReceiptJournal::open(&path).await.unwrap();
    (path, journal)
}
async fn remove(path: PathBuf) {
    for attempt in 0..20 {
        match std::fs::remove_file(&path) {
            Ok(()) => return,
            Err(e) if matches!(e.raw_os_error(), Some(32 | 33)) && attempt < 19 => {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await
            }
            Err(e) => panic!("test SQLite cleanup: {e}"),
        }
    }
}
fn state(text: &str) -> DocumentState {
    let node = MaterializedNode {
        id: engine_shared::NodeId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        parent_id: None,
        node_type: "paragraph".into(),
        pos: "a0".into(),
        var_name: None,
        deleted: false,
        current_fields: json!({"text":text}),
    };
    DocumentState {
        nodes: BTreeMap::from([(node.id.clone(), node)]),
        ..Default::default()
    }
}
async fn commit(
    repo: &LocalRepository,
    doc: Uuid,
    key: &Ed25519KeyPair,
    parents: Vec<Address>,
    text: &str,
) -> SignedCommit {
    let (root, _) = repo
        .write_state(DocumentId(doc), &state(text))
        .await
        .unwrap();
    let signed = SignedCommit::sign(
        Commit {
            version: 1,
            project: repo.project(),
            parents,
            files: BTreeMap::from([(
                "Report.docx".into(),
                FileEntry {
                    document: DocumentId(doc),
                    state: root,
                },
            )]),
            author_key: String::new(),
            authored_at_ms: 1,
            message: text.into(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        key,
    )
    .unwrap();
    repo.import_commit(&signed).await.unwrap();
    signed
}

#[test]
fn explicit_origin_and_token_rules_reject_credential_urls_and_insecure_hosts() {
    for url in [
        "http://example.test/",
        "http://localhost/",
        "ftp://127.0.0.1/",
        "https://user:secret@example.test/",
        "https://example.test/?token=secret",
        "https://example.test/#x",
        "https://example.test/api",
    ] {
        assert!(
            Client::new(
                remote(url.into(), Uuid::new_v4()),
                Uuid::new_v4(),
                "synthetic",
                true
            )
            .is_err(),
            "{url}"
        );
    }
    assert!(Client::new(
        remote("http://127.0.0.1/".into(), Uuid::new_v4()),
        Uuid::new_v4(),
        "synthetic",
        false
    )
    .is_err());
    assert!(Client::new(
        remote("https://example.test/".into(), Uuid::new_v4()),
        Uuid::new_v4(),
        "bad\r\ntoken",
        false
    )
    .is_err());
}

#[tokio::test]
async fn redirects_and_oversize_bodies_are_rejected_without_reflecting_remote_secrets() {
    let router = Router::new()
        .route(
            "/projects/{id}/redirect",
            get(|| async { axum::response::Redirect::temporary("/secret") }),
        )
        .route(
            "/projects/{id}/large",
            get(|| async { Json(json!({"value":"private-remote-content".repeat(300)})) }),
        );
    let (url, server) = serve(router).await;
    let client = Client::new(
        remote(url, Uuid::new_v4()),
        Uuid::new_v4(),
        "synthetic",
        true,
    )
    .unwrap();
    let err = client
        .get::<Value>("redirect", &[], 1024)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("307"));
    let err = client
        .get::<Value>("large", &[], 128)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("byte limit") && !err.contains("private-remote-content"));
    server.abort();
    let _ = server.await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn real_http_selected_push_fetch_reuse_review_and_stale_plan_are_restart_safe(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let mut api = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    api.ref_signer = Some(Arc::new(key(99)));
    let (url, server) = serve(app(api)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let project: Uuid = serde_json::from_value(
        post(&url, "projects", &login, json!({"name":"Sync"})).await["id"].clone(),
    )
    .unwrap();
    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Report',$1,$2) returning id",
    )
    .bind(owner)
    .bind(project)
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    let owner_key = enroll(&url, &login, owner, 7).await;
    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let first = commit(&r1, doc, &owner_key, vec![], "visible base").await;
    let a = first.verify().unwrap();
    let secret = commit(&r1, doc, &owner_key, vec![], "private unrelated branch").await;
    r1.compare_and_swap("private", None, &secret.verify().unwrap())
        .await
        .unwrap();
    let approved = plan(&r1, &client, &journal1, &scope, a.clone(), true)
        .await
        .unwrap();
    assert_eq!(approved.publish.len(), 1);
    // No remote mutation during preview, and removing a required manifest is rejected.
    let mut truncated = approved.clone();
    truncated.publish.clear();
    assert!(push(&r1, &client, &journal1, &scope, truncated)
        .await
        .unwrap_err()
        .to_string()
        .contains("reviewed plan"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from project_staged_object")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let result = push(&r1, &client, &journal1, &scope, approved.clone())
        .await
        .unwrap();
    assert_eq!(result["head"]["generation"], 1);
    assert!(client
        .published(&secret.verify().unwrap())
        .await
        .unwrap()
        .is_none());
    assert!(!sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from checkpoint_object where document_id=$1 and address=$2)"
    )
    .bind(doc)
    .bind(secret.commit.files["Report.docx"].state.as_str())
    .fetch_one(&pool)
    .await
    .unwrap());
    let bytes: i64 =
        sqlx::query_scalar("select sum(octet_length(bytes))::bigint from checkpoint_object")
            .fetch_one(&pool)
            .await
            .unwrap();
    // Reopen the pin and retry a lost success acknowledgement: no new generation or bytes.
    journal1.close().await;
    let journal1 = ReceiptJournal::open(&j1).await.unwrap();
    assert_eq!(
        push(&r1, &client, &journal1, &scope, approved)
            .await
            .unwrap()["already_applied"],
        true
    );
    assert!(r1.head("main").await.unwrap().is_none());
    let (other, other_login) = actor(&runtime.pool, "contributor").await;
    sqlx::query("insert into space_member(space_id,identity_id,role) values($1,$2,'reviewer')")
        .bind(project)
        .bind(other)
        .execute(&runtime.pool)
        .await
        .unwrap();
    let other_key = enroll(&url, &other_login, other, 8).await;
    let c2 = Client::new(remote(url.clone(), authority), project, &other_login, true).unwrap();
    let (p2, r2) = repo(project).await;
    let (j2, journal2) = journal().await;
    assert_eq!(transfer::fetch(&r2, &c2, &a).await.unwrap(), 1);
    let receipt = c2.head(&scope).await.unwrap().unwrap();
    track(&c2, &journal2, &scope, receipt).await.unwrap();
    assert_eq!(
        r2.read_state(DocumentId(doc), &first.commit.files["Report.docx"].state)
            .await
            .unwrap(),
        state("visible base")
    );
    assert_eq!(transfer::fetch(&r2, &c2, &a).await.unwrap(), 0);
    // Second author reuses the entire root through published acknowledgements.
    let second = commit(&r2, doc, &other_key, vec![a.clone()], "visible base").await;
    let b = second.verify().unwrap();
    let feature = Scope {
        branch: "feature/local".into(),
        ..scope.clone()
    };
    let feature_plan = plan(&r2, &c2, &journal2, &feature, b.clone(), true)
        .await
        .unwrap();
    assert_eq!(feature_plan.publish.len(), 1);
    push(&r2, &c2, &journal2, &feature, feature_plan)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select sum(octet_length(bytes))::bigint from checkpoint_object"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        bytes
    );
    assert!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from project_staged_object where identity_id=$1"
        )
        .bind(other)
        .fetch_one(&pool)
        .await
        .unwrap()
            > 0
    );
    assert!(r2.head("feature/local").await.unwrap().is_none());
    // Competing plans bind the original generation; later push cannot overwrite it.
    transfer::fetch(&r1, &client, &b).await.unwrap();
    let divergent = commit(
        &r1,
        doc,
        &owner_key,
        vec![a.clone()],
        "independent alternative",
    )
    .await;
    let stale = plan(
        &r1,
        &client,
        &journal1,
        &scope,
        divergent.verify().unwrap(),
        true,
    )
    .await
    .unwrap();
    let advance = plan(&r1, &client, &journal1, &scope, b.clone(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, advance)
        .await
        .unwrap();
    assert!(push(&r1, &client, &journal1, &scope, stale)
        .await
        .unwrap_err()
        .to_string()
        .contains("branch changed"));
    assert!(client
        .published(&divergent.verify().unwrap())
        .await
        .unwrap()
        .is_none());
    // Publish-only leaves the protected/main ref alone and makes a reviewable candidate.
    let third = commit(&r2, doc, &other_key, vec![b.clone()], "review me").await;
    let review_plan = plan(&r2, &c2, &journal2, &scope, third.verify().unwrap(), false)
        .await
        .unwrap();
    assert_eq!(
        push(&r2, &c2, &journal2, &scope, review_plan)
            .await
            .unwrap()["branch_changed"],
        false
    );
    assert_eq!(
        c2.head(&scope).await.unwrap().unwrap().receipt.head.commit,
        b
    );
    assert_eq!(
        r1.head("private").await.unwrap().unwrap().commit,
        secret.verify().unwrap()
    );
    // A selected merge explicitly discloses private ancestry. Removing that
    // ancestor from the saved approval cannot turn it into implicit publication.
    let mut merge = first.commit.clone();
    merge.parents = vec![a, secret.verify().unwrap()];
    merge.message = "merge a private line".into();
    let merge = SignedCommit::sign(merge, &owner_key).unwrap();
    r1.import_commit(&merge).await.unwrap();
    let mut disclosure = plan(
        &r1,
        &client,
        &journal1,
        &scope,
        merge.verify().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(disclosure.publish.len(), 2);
    assert_eq!(
        disclosure.publish[0].verify().unwrap(),
        secret.verify().unwrap()
    );
    disclosure.publish.remove(0);
    assert!(push(&r1, &client, &journal1, &scope, disclosure)
        .await
        .is_err());
    assert!(client
        .published(&secret.verify().unwrap())
        .await
        .unwrap()
        .is_none());
    let old = r2
        .compare_and_swap("work", None, &first.verify().unwrap())
        .await
        .unwrap();
    let pulled = pull(&r2, &c2, &journal2, &scope, "work", Some(&old))
        .await
        .unwrap();
    assert_eq!(pulled["local_head"]["commit"], json!(b));
    let work = r2.head("work").await.unwrap().unwrap();
    assert_eq!(work.generation, 2);
    assert_eq!(
        pull(&r2, &c2, &journal2, &scope, "fresh", None)
            .await
            .unwrap()["local_head"]["generation"],
        1
    );
    assert_eq!(
        pull(&r2, &c2, &journal2, &scope, "work", Some(&work))
            .await
            .unwrap()["local_branch_changed"],
        false
    );
    assert!(pull(&r2, &c2, &journal2, &scope, "work", None)
        .await
        .is_err());
    // A local-only descendant must survive pulling the older shared main.
    let local = r2
        .compare_and_swap("work", Some(&work), &third.verify().unwrap())
        .await
        .unwrap();
    assert!(pull(&r2, &c2, &journal2, &scope, "work", Some(&local))
        .await
        .unwrap_err()
        .to_string()
        .contains("diverged"));
    assert_eq!(r2.head("work").await.unwrap(), Some(local));
    server.abort();
    let _ = server.await;
    journal1.close().await;
    journal2.close().await;
    r1.close().await;
    r2.close().await;
    for path in [p1, p2, j1, j2] {
        remove(path).await;
    }
    runtime.close().await;
}

fn receipt(
    scope: Scope,
    generation: i64,
    previous: Option<Address>,
    commit: Address,
) -> SignedReceipt {
    SignedReceipt::sign(
        Receipt {
            version: 1,
            scope,
            head: Head { commit, generation },
            previous,
            issued_at_ms: 1,
            issuer_key: String::new(),
        },
        &key(99),
    )
    .unwrap()
}

#[tokio::test]
async fn up_to_date_push_rechecks_head_before_pinning_a_concurrent_unfetched_update() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let scope = Scope {
        project,
        authority,
        branch: "main".into(),
    };
    let (file, repo) = repo(project).await;
    let signed = commit(&repo, Uuid::new_v4(), &key(7), vec![], "local head").await;
    let address = signed.verify().unwrap();
    let first = receipt(scope.clone(), 1, None, address.clone());
    let next = receipt(
        scope.clone(),
        2,
        Some(first.verify().unwrap()),
        Address::try_from("b".repeat(64)).unwrap(),
    );
    let count = Arc::new(AtomicUsize::new(0));
    let expected = first.receipt.head.clone();
    let (url,server) = serve(Router::new()
        .route("/projects/{id}/history/authority",get(move || async move { Json(epoch_one(authority)) }))
        .route("/projects/{id}/history/refs",get(move || {
            let r = if count.fetch_add(1,Ordering::Relaxed) == 0 {first.clone()} else {next.clone()};
            async move { Json(json!({"items":[{"branch":"main","head":r.receipt.head}],"receipts":[r]})) }
        }))
        .route("/projects/{id}/history/commits/{commit}",get(move || {let signed = signed.clone();async move {Json(json!(signed))}}))
    ).await;
    let client = Client::new(remote(url, authority), project, "synthetic", true).unwrap();
    let (pin_path, journal) = journal().await;
    let approved = Plan {
        version: 1,
        remote: client.remote.clone(),
        project,
        branch: "main".into(),
        candidate: address,
        expected: Some(expected),
        update_branch: true,
        publish: vec![],
    };
    assert!(push(&repo, &client, &journal, &scope, approved)
        .await
        .unwrap_err()
        .to_string()
        .contains("up-to-date"));
    assert!(journal.pin(&scope).await.unwrap().is_none());
    server.abort();
    let _ = server.await;
    repo.close().await;
    journal.close().await;
    remove(file).await;
    remove(pin_path).await;
}
#[tokio::test]
async fn rollback_fork_wrong_key_revocation_and_gapped_receipts_never_replace_tracking() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let scope = Scope {
        project,
        authority,
        branch: "main".into(),
    };
    let a = Address::try_from("a".repeat(64)).unwrap();
    let b = Address::try_from("b".repeat(64)).unwrap();
    let first = receipt(scope.clone(), 1, None, a.clone());
    let second = receipt(scope.clone(), 2, Some(first.verify().unwrap()), b.clone());
    let gap = receipt(scope.clone(), 4, Some(second.verify().unwrap()), a.clone());
    let served = gap.clone();
    let (url, server) = serve(
        Router::new()
            .route(
                "/projects/{id}/history/authority",
                get(move || async move { Json(epoch_one(authority)) }),
            )
            .route(
                "/projects/{id}/history/receipts",
                get(move || {
                    let r = served.clone();
                    async move { Json(json!({"items":[r]})) }
                }),
            ),
    )
    .await;
    let client = Client::new(remote(url, authority), project, "synthetic", true).unwrap();
    let (path, journal) = journal().await;
    journal
        .trust_checkpoint(&scope, &client.remote.public_key, second.clone())
        .await
        .unwrap();
    assert!(track(&client, &journal, &scope, first).await.is_err());
    let fork = receipt(scope.clone(), 2, second.receipt.previous.clone(), a);
    assert!(track(&client, &journal, &scope, fork).await.is_err());
    assert!(track(&client, &journal, &scope, gap).await.is_err());
    let wrong_key = SignedReceipt::sign(second.receipt.clone(), &key(3)).unwrap();
    assert!(track(&client, &journal, &scope, wrong_key).await.is_err());
    assert_eq!(
        journal.pin(&scope).await.unwrap().unwrap().receipt(),
        &second
    );
    journal.revoke(&scope).await.unwrap();
    assert!(track(&client, &journal, &scope, second).await.is_err());
    server.abort();
    let _ = server.await;
    journal.close().await;
    remove(path).await;
}

#[tokio::test]
async fn interrupted_or_corrupt_download_retains_verified_objects_and_never_imports_a_commit() {
    let project = Uuid::new_v4();
    let doc = Uuid::new_v4();
    let (p1, r1) = repo(project).await;
    let (p2, r2) = repo(project).await;
    let signed = commit(&r1, doc, &key(7), vec![], "selected history").await;
    let address = signed.verify().unwrap();
    let selected = signed.clone();
    let root = selected.commit.files["Report.docx"].state.clone();
    let packet = r1
        .object(&ObjectKey {
            document: DocumentId(doc),
            address: root.clone(),
        })
        .await
        .unwrap();
    let served_root = root.clone();
    let served_bytes = STANDARD.encode(packet.bytes);
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let corrupt = Arc::new(AtomicBool::new(true));
    let switch = corrupt.clone();
    let root_calls = Arc::new(AtomicUsize::new(0));
    let calls = root_calls.clone();
    let source = r1.clone();
    let router = Router::new()
        .route(
            "/projects/{id}/history/commits/{address}",
            get(move || {
                let c = selected.clone();
                async move { Json(json!(c)) }
            }),
        )
        .route(
            "/projects/{id}/history/commits/{commit}/objects/{doc}/{address}",
            get(
                move |axum::extract::Path((_id, _commit, _doc, object)): axum::extract::Path<(
                    String,
                    String,
                    String,
                    String,
                )>| {
                    let root = served_root.clone();
                    let bytes = served_bytes.clone();
                    let switch = switch.clone();
                    let calls = calls.clone();
                    let source = source.clone();
                    async move {
                        let bytes = if object == root.as_str() {
                            calls.fetch_add(1, Ordering::Relaxed);
                            bytes
                        } else if switch.load(Ordering::Relaxed) {
                            STANDARD.encode(b"corrupt")
                        } else {
                            STANDARD.encode(
                                source
                                    .object(&ObjectKey {
                                        document: DocumentId(doc),
                                        address: Address::try_from(object.clone()).unwrap(),
                                    })
                                    .await
                                    .unwrap()
                                    .bytes,
                            )
                        };
                        Json(json!({"address":object,"bytes":bytes}))
                    }
                },
            ),
        );
    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, Uuid::new_v4()), project, "synthetic", true).unwrap();
    assert!(transfer::fetch(&r2, &client, &address).await.is_err());
    assert!(r2.commit(&address).await.is_err());
    assert!(r2.head("main").await.unwrap().is_none());
    assert!(r2
        .missing(&[ObjectKey {
            document: DocumentId(doc),
            address: root
        }])
        .await
        .unwrap()
        .is_empty());
    assert_eq!(r2.storage_usage().await.unwrap().objects_used, 1);
    corrupt.store(false, Ordering::Relaxed);
    assert_eq!(transfer::fetch(&r2, &client, &address).await.unwrap(), 1);
    assert_eq!(
        root_calls.load(Ordering::Relaxed),
        1,
        "retry must reuse the already verified root"
    );
    assert_eq!(
        r2.commit(&address).await.unwrap().verify().unwrap(),
        address
    );
    server.abort();
    let _ = server.await;
    r1.close().await;
    r2.close().await;
    remove(p1).await;
    remove(p2).await;
}

// --- renewal and project device sessions -------------------------------------------

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dynodoc-credentials-{}", Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    dir
}
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}
async fn get_json(url: &str, path: &str, login: &str) -> Value {
    let response = reqwest::Client::new()
        .get(format!("{url}{path}"))
        .bearer_auth(login)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "{path}");
    response.json().await.unwrap()
}
async fn api(
    pool: &PgPool,
    signer: Option<Arc<Ed25519KeyPair>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let mut state = AppState::new(
        pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    state.ref_signer = signer;
    serve(app(state)).await
}
fn device(url: &str, authority: Uuid, project: Uuid, seed: u8, scopes: &[&str]) -> Client {
    Client::with_credential(
        remote(url.to_owned(), authority),
        project,
        Credential::Device {
            key: key(seed),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        },
        None,
        true,
    )
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_rotation_retries_once_and_replaces_files_atomically(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (url, server) = api(&runtime.pool, None).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let project: Uuid = serde_json::from_value(
        post(&url, "projects", &login, json!({"name":"Renewal"})).await["id"].clone(),
    )
    .unwrap();
    // A real login: bound session, an access token that has already expired, and
    // a refresh secret the server knows only by hash.
    let session = Uuid::new_v4();
    let secret = "ab".repeat(32);
    sqlx::query("insert into refresh_token(identity_id,token_hash,expires_at,session_generation,session_id) values($1,$2,now()+interval '1 day',0,$3)")
        .bind(owner)
        .bind(engine_api::auth::sha256(secret.as_bytes()))
        .bind(session)
        .execute(&runtime.pool)
        .await
        .unwrap();
    let expired = token::mint_bound_session(&TOKEN_KEY, owner, -30, 0, Some(session)).unwrap();
    let dir = scratch();
    let (access_file, refresh_file) = (dir.join("access.txt"), dir.join("refresh.txt"));
    std::fs::write(&access_file, &expired).unwrap();
    std::fs::write(&refresh_file, &secret).unwrap();
    let credential = || Credential::Refresh {
        refresh_file: refresh_file.clone(),
        access_file: Some(access_file.clone()),
    };

    let client = Client::with_credential(
        remote(url.clone(), authority),
        project,
        credential(),
        Some(&expired),
        true,
    )
    .unwrap();
    let files: Value = client.get("files", &[], 1 << 20).await.unwrap();
    assert!(files["items"].is_array());
    // Rotation persisted both secrets completely and left no temporary files.
    let rotated = std::fs::read_to_string(&refresh_file).unwrap();
    let access = std::fs::read_to_string(&access_file).unwrap();
    assert!(rotated.len() == 64 && rotated != secret);
    assert!(!access.is_empty() && access != expired);
    assert_eq!(entries(&dir), ["access.txt", "refresh.txt"]);
    // The consumed refresh secret is dead; the new files work without renewal.
    let stale = reqwest::Client::new()
        .post(format!("{url}auth/refresh"))
        .json(&json!({"refresh_token":secret}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(stale, reqwest::StatusCode::UNAUTHORIZED);
    let second = Client::with_credential(
        remote(url.clone(), authority),
        project,
        credential(),
        Some(access.trim()),
        true,
    )
    .unwrap();
    second.get::<Value>("files", &[], 1 << 20).await.unwrap();
    assert_eq!(std::fs::read_to_string(&refresh_file).unwrap(), rotated);
    // A start with only the refresh file renews before its first request.
    let only_refresh = Client::with_credential(
        remote(url.clone(), authority),
        project,
        Credential::Refresh {
            refresh_file: refresh_file.clone(),
            access_file: None,
        },
        None,
        true,
    )
    .unwrap();
    only_refresh
        .get::<Value>("files", &[], 1 << 20)
        .await
        .unwrap();
    let rotated_again = std::fs::read_to_string(&refresh_file).unwrap();
    assert_ne!(rotated_again, rotated);
    // An invalid refresh secret changes nothing and reports no secret.
    std::fs::write(&refresh_file, "cd".repeat(32)).unwrap();
    let broken = Client::with_credential(
        remote(url.clone(), authority),
        project,
        credential(),
        Some(&expired),
        true,
    )
    .unwrap();
    let error = broken
        .get::<Value>("files", &[], 1 << 20)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("401") && !error.contains(&"cd".repeat(32)),
        "{error}"
    );
    assert_eq!(
        std::fs::read_to_string(&refresh_file).unwrap(),
        "cd".repeat(32)
    );
    assert_eq!(entries(&dir), ["access.txt", "refresh.txt"]);
    // A fixed expired token stops with the server's refusal rather than looping.
    let fixed = Client::new(remote(url.clone(), authority), project, &expired, true).unwrap();
    assert!(fixed
        .get::<Value>("files", &[], 1 << 20)
        .await
        .unwrap_err()
        .to_string()
        .contains("401"));
    std::fs::remove_dir_all(dir).unwrap();
    server.abort();
    let _ = server.await;
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn device_sessions_push_fetch_keep_policy_and_end_with_revocation_or_removal(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (url, server) = api(&runtime.pool, Some(Arc::new(key(99)))).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (contributor, contributor_login) = actor(&runtime.pool, "contributor").await;
    let project: Uuid = serde_json::from_value(
        post(&url, "projects", &login, json!({"name":"Device"})).await["id"].clone(),
    )
    .unwrap();
    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Report',$1,$2) returning id",
    )
    .bind(owner)
    .bind(project)
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    sqlx::query("insert into space_member(space_id,identity_id,role) values($1,$2,'reviewer')")
        .bind(project)
        .bind(contributor)
        .execute(&runtime.pool)
        .await
        .unwrap();
    let owner_key = enroll(&url, &login, owner, 7).await;
    let contributor_key = enroll(&url, &contributor_login, contributor, 8).await;
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let rw = ["history:read", "history:write"];

    // The owner publishes main with no account token anywhere.
    let owner_client = device(&url, authority, project, 7, &rw);
    owner_client.authority().await.unwrap();
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let first = commit(&r1, doc, &owner_key, vec![], "base").await;
    let a = first.verify().unwrap();
    let approved = plan(&r1, &owner_client, &journal1, &scope, a.clone(), true)
        .await
        .unwrap();
    let result = push(&r1, &owner_client, &journal1, &scope, approved)
        .await
        .unwrap();
    assert_eq!(result["head"]["generation"], 1);

    // A read-only session fetches but cannot stage, publish or review.
    let (p2, r2) = repo(project).await;
    let (j2, journal2) = journal().await;
    let reader = device(&url, authority, project, 8, &["history:read"]);
    assert_eq!(transfer::fetch(&r2, &reader, &a).await.unwrap(), 1);
    let second = commit(&r2, doc, &contributor_key, vec![a.clone()], "feature").await;
    let b = second.verify().unwrap();
    let review = plan(&r2, &reader, &journal2, &scope, b.clone(), false)
        .await
        .unwrap();
    assert_eq!(review.publish.len(), 1);
    let denied = push(&r2, &reader, &journal2, &scope, review.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(denied.contains("403"), "{denied}");
    assert!(reader.published(&b).await.unwrap().is_none());

    // A writing session publishes a candidate, but the contributor role still
    // cannot move protected main: the server's rules are unchanged.
    let writer = device(&url, authority, project, 8, &rw);
    assert_eq!(
        push(&r2, &writer, &journal2, &scope, review).await.unwrap()["branch_changed"],
        false
    );
    assert!(writer.published(&b).await.unwrap().is_some());
    let advance = plan(&r2, &writer, &journal2, &scope, b.clone(), true)
        .await
        .unwrap();
    let refused = push(&r2, &writer, &journal2, &scope, advance)
        .await
        .unwrap_err();
    assert!(format!("{refused:#}").contains("403"), "{refused:#}");
    assert_eq!(
        owner_client
            .head(&scope)
            .await
            .unwrap()
            .unwrap()
            .receipt
            .head
            .commit,
        a
    );
    // Review rules are the same too: with one required approval the owner cannot
    // merge the contributor's candidate until a current approval exists.
    sqlx::query("update project_settings set required_approvals=1 where space_id=$1")
        .bind(project)
        .execute(&runtime.pool)
        .await
        .unwrap();
    transfer::fetch(&r1, &owner_client, &b).await.unwrap();
    let merge = plan(&r1, &owner_client, &journal1, &scope, b.clone(), true)
        .await
        .unwrap();
    let unreviewed = push(&r1, &owner_client, &journal1, &scope, merge.clone())
        .await
        .unwrap_err();
    assert!(format!("{unreviewed:#}").contains("409"), "{unreviewed:#}");
    // Approving is its own scope: a session that can push (history:write) cannot
    // approve, and one that can approve (history:review) cannot push.
    let decision = json!({"target":{"branch":"main","candidate":b,"expected":{"commit":a,"generation":1}},"decision":"approve"});
    let refused = owner_client
        .post("history/reviews", decision.clone())
        .await
        .unwrap_err();
    assert!(format!("{refused:#}").contains("403"), "{refused:#}");
    let approver = device(
        &url,
        authority,
        project,
        7,
        &["history:read", "history:review"],
    );
    approver.post("history/reviews", decision).await.unwrap();
    assert!(push(&r1, &approver, &journal1, &scope, merge.clone())
        .await
        .is_err());
    let merged = push(&r1, &owner_client, &journal1, &scope, merge)
        .await
        .unwrap();
    assert_eq!(merged["head"]["generation"], 2);
    // One audit row per issuance, with no token material.
    let issued: Vec<String> = sqlx::query_scalar(
        "select detail::text from operation_audit where action='device.session_issued'",
    )
    .fetch_all(&runtime.pool)
    .await
    .unwrap();
    assert!(issued.len() >= 3 && issued.iter().all(|d| !d.contains("v4.local")));

    // Revoking the key ends this client; its renewal cannot succeed either.
    let owner_key_id = get_json(&url, "devices", &login).await["keys"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    post(
        &url,
        &format!("devices/{owner_key_id}/revoke"),
        &login,
        json!({}),
    )
    .await;
    let error = format!("{:#}", owner_client.head(&scope).await.unwrap_err());
    assert!(error.contains("401"), "{error}");
    let fresh = device(&url, authority, project, 7, &rw);
    assert!(fresh.authority().await.is_err());

    // Removing the member ends the contributor even with an unexpired token.
    sqlx::query("delete from space_member where space_id=$1 and identity_id=$2")
        .bind(project)
        .bind(contributor)
        .execute(&runtime.pool)
        .await
        .unwrap();
    let error = format!("{:#}", writer.head(&scope).await.unwrap_err());
    assert!(error.contains("403"), "{error}");
    assert!(device(&url, authority, project, 8, &rw)
        .authority()
        .await
        .is_err());
    server.abort();
    let _ = server.await;
    journal1.close().await;
    journal2.close().await;
    r1.close().await;
    r2.close().await;
    for path in [p1, p2, j1, j2] {
        remove(path).await;
    }
    runtime.close().await;
}

#[test]
fn credential_options_conflict_and_require_a_source_for_network_actions() {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        options: Options,
    }
    let parse = |extra: &[&str], action: &str| {
        let mut args = vec![
            "sync",
            "repo.sqlite",
            "11111111-1111-4111-8111-111111111111",
            "--remote",
            "remote.json",
            "--journal",
            "pins.sqlite",
            "--branch",
            "main",
        ];
        args.extend(extra);
        args.push(action);
        Cli::try_parse_from(args)
    };
    assert!(parse(&["--device-key", "k.der"], "fetch").is_ok());
    assert!(parse(&["--token-file", "a", "--refresh-token-file", "r"], "fetch").is_ok());
    assert!(parse(&["--device-key", "k", "--token-file", "a"], "fetch").is_err());
    assert!(parse(&["--device-key", "k", "--refresh-token-file", "r"], "fetch").is_err());
    // Rotation replaces both files, so they must be two files.
    let same = parse(
        &[
            "--token-file",
            "same.txt",
            "--refresh-token-file",
            "same.txt",
        ],
        "fetch",
    )
    .unwrap()
    .options;
    let error = credentials(
        &same,
        remote("https://example.test/".into(), Uuid::new_v4()),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("different files"), "{error}");
    // Offline tracking needs no credential; any network action does.
    let none = parse(&[], "fetch").unwrap().options;
    assert!(credentials(
        &none,
        remote("https://example.test/".into(), Uuid::new_v4())
    )
    .is_err());
    assert!(parse(&[], "tracking").is_ok());
}

#[tokio::test]
async fn hostile_token_lifetimes_neither_panic_nor_lose_the_rotated_secret() {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    let lifetime = Arc::new(AtomicU64::new(0));
    let rotations = Arc::new(AtomicUsize::new(0));
    let rotated = "cd".repeat(32);
    let (served, counted, successor) = (lifetime.clone(), rotations.clone(), rotated.clone());
    let router = Router::new()
        .route(
            "/auth/refresh",
            axum::routing::post(move || {
                counted.fetch_add(1, Ordering::Relaxed);
                let (successor, expires_in) = (successor.clone(), served.load(Ordering::Relaxed));
                async move {
                    Json(json!({
                        "access_token":"fresh-token",
                        "token_type":"Bearer",
                        "refresh_token":successor,
                        "expires_in":expires_in,
                    }))
                }
            }),
        )
        .route(
            "/projects/{id}/files",
            get(|headers: axum::http::HeaderMap| async move {
                let bearer = headers.get("authorization").and_then(|v| v.to_str().ok());
                if bearer == Some("Bearer fresh-token") {
                    Ok(Json(json!({"items":[]})))
                } else {
                    Err(axum::http::StatusCode::UNAUTHORIZED)
                }
            }),
        );
    let (url, server) = serve(router).await;
    let dir = scratch();
    let refresh_file = dir.join("refresh.txt");
    // Overflowing, absurd, zero and ordinary values: one rotation each, no panic,
    // the successor secret saved, and no renewal on the second request.
    for expires_in in [u64::MAX, u64::MAX / 2, 1 << 40, 0, 3600] {
        lifetime.store(expires_in, Ordering::Relaxed);
        std::fs::write(&refresh_file, "ab".repeat(32)).unwrap();
        let before = rotations.load(Ordering::Relaxed);
        let client = Client::with_credential(
            remote(url.clone(), Uuid::new_v4()),
            Uuid::new_v4(),
            Credential::Refresh {
                refresh_file: refresh_file.clone(),
                access_file: None,
            },
            None,
            true,
        )
        .unwrap();
        for _ in 0..2 {
            client
                .get::<Value>("files", &[], 1 << 16)
                .await
                .unwrap_or_else(|e| panic!("expires_in {expires_in}: {e:#}"));
        }
        assert_eq!(
            rotations.load(Ordering::Relaxed),
            before + 1,
            "{expires_in}"
        );
        assert_eq!(std::fs::read_to_string(&refresh_file).unwrap(), rotated);
        assert_eq!(entries(&dir), ["refresh.txt"]);
    }
    std::fs::remove_dir_all(dir).unwrap();
    server.abort();
    let _ = server.await;
}

async fn send(url: &str, method: &str, path: &str, login: &str, body: Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .request(method.parse().unwrap(), format!("{url}{path}"))
        .bearer_auth(login)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[test]
fn device_scopes_are_the_least_the_action_needs_and_never_include_review() {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        options: Options,
    }
    let scopes = |action: &[&str]| {
        let mut args = vec![
            "sync",
            "repo.sqlite",
            "11111111-1111-4111-8111-111111111111",
            "--remote",
            "remote.json",
            "--journal",
            "pins.sqlite",
            "--branch",
            "main",
            "--device-key",
            "key.der",
        ];
        args.extend(action);
        device_scopes(&Cli::try_parse_from(args).unwrap().options.action)
    };
    assert_eq!(scopes(&["fetch"]), ["history:read"]);
    assert_eq!(scopes(&["pull", "main"]), ["history:read"]);
    assert_eq!(scopes(&["plan", "ab", "--out", "p.json"]), ["history:read"]);
    assert_eq!(
        scopes(&["push", "plan.json"]),
        ["history:read", "history:write"]
    );
    assert_eq!(scopes(&["release", "list"]), ["history:read"]);
    assert_eq!(scopes(&["release", "show", "v1.0.0"]), ["history:read"]);
    assert_eq!(
        scopes(&[
            "release",
            "create",
            "v1.0.0",
            "--expected-commit",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ]),
        ["history:read", "history:write"]
    );
    for action in [
        &["fetch"][..],
        &["push", "plan.json"],
        &["plan", "ab", "--out", "p.json"],
        &["release", "list"],
        &["release", "show", "v1.0.0"],
        &[
            "release",
            "create",
            "v1.0.0",
            "--expected-commit",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
    ] {
        assert!(!scopes(action).iter().any(|s| s == "history:review"));
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_granted_key_signs_in_only_for_what_its_account_holder_granted(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (url, server) = api(&runtime.pool, None).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let project: Uuid = serde_json::from_value(
        post(&url, "projects", &login, json!({"name":"Granted"})).await["id"].clone(),
    )
    .unwrap();
    let (_, key_id) = enroll_granted(&url, &login, owner, 7).await;
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let grant = format!("devices/{key_id}/projects/{project}");

    // Possession of the key file alone is not enough, and the message says where
    // to look.
    let reader = device(&url, authority, project, 7, &["history:read"]);
    let error = format!("{:#}", reader.authority().await.unwrap_err());
    assert!(
        error.contains("403") && error.contains("granted"),
        "{error}"
    );

    // Only the signed-in account holder can grant; the grant is read-only.
    let (code, _) = send(
        &url,
        "PUT",
        &grant,
        &login,
        json!({"scopes":["history:read"]}),
    )
    .await;
    assert_eq!(code, 200);
    reader.authority().await.unwrap();
    let writer = device(
        &url,
        authority,
        project,
        7,
        &["history:read", "history:write"],
    );
    assert!(writer.authority().await.is_err());
    let reviewer = device(
        &url,
        authority,
        project,
        7,
        &["history:read", "history:review"],
    );
    assert!(reviewer.authority().await.is_err());

    // Widening is picked up by the next sign-in; narrowing and revocation by the
    // next request of a live session (the client does not retry a 403).
    let (code, _) = send(
        &url,
        "PUT",
        &grant,
        &login,
        json!({"scopes":["history:read","history:write"]}),
    )
    .await;
    assert_eq!(code, 200);
    writer.authority().await.unwrap();
    assert!(reader.head(&scope).await.is_ok());
    let (code, _) = send(&url, "DELETE", &grant, &login, Value::Null).await;
    assert_eq!(code, 200);
    for client in [&reader, &writer] {
        let error = format!("{:#}", client.head(&scope).await.unwrap_err());
        assert!(error.contains("403"), "{error}");
    }
    // The key cannot undo it: a device-session token is no account login.
    let (code, _) = send(&url, "GET", "devices", &login, Value::Null).await;
    assert_eq!(code, 200);
    server.abort();
    let _ = server.await;
    runtime.close().await;
}

// ---- receipt-authority epochs (docs/REF-AUTHORITY-ROTATION.md) -------------------

fn hexkey(seed: u8) -> String {
    hex::encode(key(seed).public_key().as_ref())
}
async fn api_with(pool: &PgPool, signer: Option<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let mut api = AppState::new(
        pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    api.ref_signer = signer.map(|seed| Arc::new(key(seed)));
    serve(app(api)).await
}
/// A statement for the database as it is now (operator view, writers stopped).
async fn operator_statement(
    pool: &PgPool,
    kind: engine_core::repository::authority_epoch::Kind,
    old: u8,
    new: u8,
) -> engine_core::repository::authority_epoch::SignedTransition {
    use engine_core::repository::authority_epoch::{Kind, SignedTransition, Transition};
    let state = engine_core::repository::server_authority::state(pool)
        .await
        .unwrap();
    let transition = Transition {
        version: 1,
        kind,
        authority: state.authority,
        from_epoch: state.epoch,
        to_epoch: state.epoch + 1,
        old_key: hexkey(old),
        new_key: hexkey(new),
        sealed: state.sealed,
        reason: match kind {
            Kind::Recovery => "private key lost".into(),
            Kind::Rotation => String::new(),
        },
        declared_at_ms: 1_700_000_000_000,
    };
    match kind {
        Kind::Rotation => SignedTransition::sign_rotation(transition, &key(old), &key(new)),
        Kind::Recovery => SignedTransition::sign_recovery(transition, &key(new)),
    }
    .unwrap()
}
async fn new_project(url: &str, pool: &PgPool, login: &str, owner: Uuid) -> (Uuid, Uuid) {
    let project: Uuid = serde_json::from_value(
        post(url, "projects", login, json!({"name":"Epochs"})).await["id"].clone(),
    )
    .unwrap();
    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('Report',$1,$2) returning id",
    )
    .bind(owner)
    .bind(project)
    .fetch_one(pool)
    .await
    .unwrap();
    (project, doc)
}

#[sqlx::test(migrations = "../../migrations")]
async fn sync_clients_follow_a_planned_rotation_and_refuse_retired_key_receipts(pool: PgPool) {
    use engine_core::repository::{authority_epoch::Kind, server_authority};
    let authority = server_authority::install(&pool, &hexkey(99)).await.unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (url, server) = api_with(&runtime.pool, Some(99)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (project, doc) = new_project(&url, &runtime.pool, &login, owner).await;
    let owner_key = enroll(&url, &login, owner, 7).await;
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let a = commit(&r1, doc, &owner_key, vec![], "base").await;
    let approved = plan(&r1, &client, &journal1, &scope, a.verify().unwrap(), true)
        .await
        .unwrap();
    assert_eq!(
        push(&r1, &client, &journal1, &scope, approved)
            .await
            .unwrap()["head"]["generation"],
        1
    );
    // A second journal pins generation 1 under the epoch-1 key.
    let (j2, journal2) = journal().await;
    let reader = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    let head1 = reader.head(&scope).await.unwrap().unwrap();
    track(&reader, &journal2, &scope, head1.clone())
        .await
        .unwrap();
    assert_eq!(
        journal2.pin(&scope).await.unwrap().unwrap().trusted_key(),
        hexkey(99)
    );

    // Operator: writers stopped, rotate, mount the new key.
    server.abort();
    let _ = server.await;
    let rotation = operator_statement(&pool, Kind::Rotation, 99, 98).await;
    server_authority::install_rotation(&pool, &rotation)
        .await
        .unwrap();
    let (url2, server2) = api_with(&runtime.pool, Some(98)).await;

    // The independently configured epoch-1 key still anchors trust.
    let client = Client::new(remote(url2.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let b = commit(
        &r1,
        doc,
        &owner_key,
        vec![a.verify().unwrap()],
        "after rotation",
    )
    .await;
    let approved = plan(&r1, &client, &journal1, &scope, b.verify().unwrap(), true)
        .await
        .unwrap();
    let pushed = push(&r1, &client, &journal1, &scope, approved)
        .await
        .unwrap();
    assert_eq!(pushed["head"]["generation"], 2);
    let pin = journal1.pin(&scope).await.unwrap().unwrap();
    assert_eq!(pin.trusted_key(), hexkey(98));
    assert_eq!(pin.receipt().receipt.head.generation, 2);
    assert_eq!(journal1.statements().await.unwrap(), vec![rotation.clone()]);

    // The reader pinned before the rotation catches up through the statement.
    let reader = Client::new(remote(url2.clone(), authority), project, &login, true).unwrap();
    reader.authority().await.unwrap();
    let head2 = reader.head(&scope).await.unwrap().unwrap();
    assert_eq!(head2.receipt.issuer_key, hexkey(98));
    track(&reader, &journal2, &scope, head2.clone())
        .await
        .unwrap();
    let caught = journal2.pin(&scope).await.unwrap().unwrap();
    assert_eq!(caught.receipt(), &head2);
    assert_eq!(caught.trusted_key(), hexkey(98));
    assert_eq!(journal2.statements().await.unwrap().len(), 1);
    // The old receipt still verifies by itself and a fresh journal follows the chain.
    head1.verify().unwrap();
    let (j3, journal3) = journal().await;
    track(&reader, &journal3, &scope, head2.clone())
        .await
        .unwrap();
    assert_eq!(
        journal3.pin(&scope).await.unwrap().unwrap().trusted_key(),
        hexkey(98)
    );
    // A configured key that is not on the server's chain is refused.
    let stranger = Remote {
        public_key: hexkey(55),
        ..remote(url2.clone(), authority)
    };
    assert!(Client::new(stranger, project, &login, true)
        .unwrap()
        .authority()
        .await
        .is_err());
    // A receipt minted later with the retired key cannot extend the new pin.
    let forged = SignedReceipt::sign(
        Receipt {
            version: 1,
            scope: scope.clone(),
            head: Head {
                commit: b.verify().unwrap(),
                generation: 3,
            },
            previous: Some(head2.verify().unwrap()),
            issued_at_ms: 1,
            issuer_key: String::new(),
        },
        &key(99),
    )
    .unwrap();
    assert!(journal2
        .advance_chain(
            &scope,
            &reader.server().await.unwrap().chain,
            std::slice::from_ref(&forged)
        )
        .await
        .is_err());
    assert!(track(&reader, &journal2, &scope, forged).await.is_err());
    assert_eq!(
        journal2
            .pin(&scope)
            .await
            .unwrap()
            .unwrap()
            .receipt()
            .receipt
            .head
            .generation,
        2
    );
    server2.abort();
    let _ = server2.await;
    for journal in [journal1, journal2, journal3] {
        journal.close().await;
    }
    r1.close().await;
    for path in [p1, j1, j2, j3] {
        remove(path).await;
    }
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn revocation_refuses_clients_and_only_an_explicit_repin_crosses_the_recorded_break(
    pool: PgPool,
) {
    use engine_core::repository::{authority_epoch::Kind, server_authority};
    let authority = server_authority::install(&pool, &hexkey(99)).await.unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let (url, server) = api_with(&runtime.pool, Some(99)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (project, doc) = new_project(&url, &runtime.pool, &login, owner).await;
    let owner_key = enroll(&url, &login, owner, 7).await;
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let a = commit(&r1, doc, &owner_key, vec![], "base").await;
    let approved = plan(&r1, &client, &journal1, &scope, a.verify().unwrap(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, approved)
        .await
        .unwrap();
    let head1 = client.head(&scope).await.unwrap().unwrap();
    // Two more readers pinned at generation 1.
    let (j2, journal2) = journal().await;
    let (j3, journal3) = journal().await;
    for journal in [&journal2, &journal3] {
        track(&client, journal, &scope, head1.clone())
            .await
            .unwrap();
    }

    // Compromise: marker recorded; the server and the clients both stop.
    server_authority::revoke(&pool, "signing key leaked", None, None)
        .await
        .unwrap();
    // The chain is fetched once per run, so every observation below is a new run.
    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    let message = format!("{:#}", client.authority().await.unwrap_err());
    assert!(message.contains("revoked"), "{message}");
    let b = commit(
        &r1,
        doc,
        &owner_key,
        vec![a.verify().unwrap()],
        "after recovery",
    )
    .await;
    let refused = plan(&r1, &client, &journal1, &scope, b.verify().unwrap(), true)
        .await
        .unwrap_err();
    assert!(format!("{refused:#}").contains("revoked"), "{refused:#}");
    assert!(
        journal1.pin(&scope).await.unwrap().unwrap().revoked(),
        "the marker on the pinned key's epoch revokes the local pin"
    );

    // Recovery: a recorded break to key 98, mounted by a restarted API.
    server.abort();
    let _ = server.await;
    let recovery = operator_statement(&pool, Kind::Recovery, 99, 98).await;
    server_authority::install_recovery(&pool, &recovery)
        .await
        .unwrap();
    let (url2, server2) = api_with(&runtime.pool, Some(98)).await;
    let with_key = |public_key: String| Remote {
        public_key,
        ..remote(url2.clone(), authority)
    };
    // The old configuration, a stranger key, and trusting the revoked epoch's
    // head as a fresh checkpoint are all refused.
    for seed in [99, 55] {
        let refused = Client::new(with_key(hexkey(seed)), project, &login, true).unwrap();
        assert!(refused.authority().await.is_err(), "key {seed}");
    }
    let fresh = Client::new(with_key(hexkey(98)), project, &login, true).unwrap();
    fresh.authority().await.unwrap();
    let revoked_head = fresh.head(&scope).await.unwrap().unwrap();
    let (j4, journal4) = journal().await;
    assert!(track(&fresh, &journal4, &scope, revoked_head)
        .await
        .is_err());
    assert!(journal4.pin(&scope).await.unwrap().is_none());
    let wrong = Client::new(with_key(hexkey(99)), project, &login, true)
        .unwrap()
        .accepting_break(hexkey(55))
        .unwrap();
    assert!(wrong.authority().await.is_err());

    // Explicit re-pin: the journal that holds the pinned receipt can plan and push
    // (an unchanged head trusts nothing new); the first new receipt must extend it.
    let explicit = Client::new(with_key(hexkey(99)), project, &login, true)
        .unwrap()
        .accepting_break(hexkey(98))
        .unwrap();
    explicit.authority().await.unwrap();
    let approved = plan(&r1, &explicit, &journal1, &scope, b.verify().unwrap(), true)
        .await
        .unwrap();
    let pushed = push(&r1, &explicit, &journal1, &scope, approved)
        .await
        .unwrap();
    assert_eq!(pushed["head"]["generation"], 2);
    let pin = journal1.pin(&scope).await.unwrap().unwrap();
    assert_eq!(pin.trusted_key(), hexkey(98));
    assert!(!pin.revoked());
    assert_eq!(journal1.statements().await.unwrap(), vec![recovery.clone()]);
    // From then on an ordinary client configured with the new key keeps tracking.
    let ordinary = Client::new(with_key(hexkey(98)), project, &login, true).unwrap();
    ordinary.authority().await.unwrap();
    let head2 = ordinary.head(&scope).await.unwrap().unwrap();
    track(&ordinary, &journal1, &scope, head2.clone())
        .await
        .unwrap();

    // The other readers: one through sync's explicit mode, one through the offline
    // bundle and `receipt accept-break`, which needs the explicit confirmation.
    track(&explicit, &journal2, &scope, head2.clone())
        .await
        .unwrap();
    assert_eq!(
        journal2.pin(&scope).await.unwrap().unwrap().trusted_key(),
        hexkey(98)
    );
    let bundle = std::env::temp_dir().join(format!("dynodoc-authority-{}.json", Uuid::new_v4()));
    let summary = authority_proof(&explicit, &journal3, &scope, &bundle)
        .await
        .unwrap();
    assert_eq!(summary["applied"], false);
    assert_eq!(summary["receipts_after_pin"], 1);
    let action = |confirm_break: bool| crate::receipt::Action::AcceptBreak {
        proof: bundle.clone(),
        new_key: hexkey(98),
        confirm_break,
    };
    assert!(
        crate::receipt::run(j3.clone(), scope.clone(), action(false))
            .await
            .is_err()
    );
    let wrong_key = crate::receipt::Action::AcceptBreak {
        proof: bundle.clone(),
        new_key: hexkey(55),
        confirm_break: true,
    };
    assert!(crate::receipt::run(j3.clone(), scope.clone(), wrong_key)
        .await
        .is_err());
    // The plain offline advance refuses the break and the revoked epoch.
    let advance = crate::receipt::Action::Advance {
        proof: bundle.clone(),
    };
    assert!(crate::receipt::run(j3.clone(), scope.clone(), advance)
        .await
        .is_err());
    assert!(journal3.pin(&scope).await.unwrap().unwrap().revoked());
    crate::receipt::run(j3.clone(), scope.clone(), action(true))
        .await
        .unwrap();
    let repinned = journal3.pin(&scope).await.unwrap().unwrap();
    assert_eq!(repinned.receipt(), &head2);
    assert_eq!(repinned.trusted_key(), hexkey(98));
    assert!(!repinned.revoked());
    assert!(journal3.statements().await.unwrap().contains(&recovery));
    // A fresh client accepts nothing signed by the retired key afterwards.
    let minted = SignedReceipt::sign(
        Receipt {
            version: 1,
            scope: scope.clone(),
            head: Head {
                commit: b.verify().unwrap(),
                generation: 3,
            },
            previous: Some(head2.verify().unwrap()),
            issued_at_ms: 1,
            issuer_key: String::new(),
        },
        &key(99),
    )
    .unwrap();
    assert!(journal3
        .advance_chain(&scope, &ordinary.server().await.unwrap().chain, &[minted])
        .await
        .is_err());
    server2.abort();
    let _ = server2.await;
    for journal in [journal1, journal2, journal3, journal4] {
        journal.close().await;
    }
    r1.close().await;
    let _ = std::fs::remove_file(&bundle);
    for path in [p1, j1, j2, j3, j4] {
        remove(path).await;
    }
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn release_create_success_and_idempotent_retry(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let mut api_state = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    api_state.ref_signer = Some(Arc::new(key(99)));
    let (url, server) = serve(app(api_state)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (project, doc) = new_project(&url, &runtime.pool, &login, owner).await;
    let owner_key = enroll(&url, &login, owner, 7).await;

    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let first = commit(&r1, doc, &owner_key, vec![], "initial commit").await;
    let head = first.verify().unwrap();
    let approved = plan(&r1, &client, &journal1, &scope, head.clone(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, approved)
        .await
        .unwrap();

    // Create release v1.0.0 targeting accepted head
    let created = client.create_release("v1.0.0", &head).await.unwrap();
    assert_eq!(created.project_id, project);
    assert_eq!(created.name, "v1.0.0");
    assert_eq!(created.commit, head.as_str());

    // Idempotent retry with same name and same commit succeeds
    let retried = client.create_release("v1.0.0", &head).await.unwrap();
    assert_eq!(retried.project_id, project);
    assert_eq!(retried.name, "v1.0.0");
    assert_eq!(retried.commit, head.as_str());
    assert_eq!(retried.created_at, created.created_at);

    server.abort();
    let _ = server.await;
    journal1.close().await;
    r1.close().await;
    remove(p1).await;
    remove(j1).await;
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn release_create_conflict_409_and_stale_head_400(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let mut api_state = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    api_state.ref_signer = Some(Arc::new(key(99)));
    let (url, server) = serve(app(api_state)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (project, doc) = new_project(&url, &runtime.pool, &login, owner).await;
    let owner_key = enroll(&url, &login, owner, 7).await;

    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let first = commit(&r1, doc, &owner_key, vec![], "initial commit").await;
    let head1 = first.verify().unwrap();
    let approved1 = plan(&r1, &client, &journal1, &scope, head1.clone(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, approved1)
        .await
        .unwrap();

    // Create release v1.0.0 targeting head1
    client.create_release("v1.0.0", &head1).await.unwrap();

    // Advance main to head2
    let second = commit(&r1, doc, &owner_key, vec![head1.clone()], "second commit").await;
    let head2 = second.verify().unwrap();
    let approved2 = plan(&r1, &client, &journal1, &scope, head2.clone(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, approved2)
        .await
        .unwrap();

    // 1. Attempt to create v1.0.0 targeting head2 (different commit) -> 409 Conflict
    let err_conflict = client.create_release("v1.0.0", &head2).await.unwrap_err();
    assert!(
        err_conflict.to_string().contains("409"),
        "expected 409 conflict error, got: {err_conflict}"
    );

    // 2. Attempt to create v2.0.0 targeting head1 (stale, main is at head2) -> 400 Bad Request
    let err_stale = client.create_release("v2.0.0", &head1).await.unwrap_err();
    assert!(
        err_stale.to_string().contains("400"),
        "expected 400 bad request error, got: {err_stale}"
    );

    server.abort();
    let _ = server.await;
    journal1.close().await;
    r1.close().await;
    remove(p1).await;
    remove(j1).await;
    runtime.close().await;
}

#[tokio::test]
async fn release_create_malformed_name_rejected_locally() {
    let dummy_auth = Uuid::new_v4();
    let dummy_proj = Uuid::new_v4();
    let client = Client::new(
        remote("http://127.0.0.1:9/".into(), dummy_auth),
        dummy_proj,
        "token",
        true,
    )
    .unwrap();
    let dummy_commit = Address::try_from(
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    )
    .unwrap();

    let invalid_names = [
        "",
        "-bad-start",
        ".bad-start",
        "_bad-start",
        "has space",
        "has/slash",
        "has\\backslash",
        "has?question",
        "has#hash",
    ];
    for bad in invalid_names {
        assert!(!http::valid_release_name(bad), "expected invalid: {bad}");
        let err = client.create_release(bad, &dummy_commit).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid release name"),
            "got: {err}"
        );
        let err_show = client.show_release(bad).await.unwrap_err();
        assert!(
            err_show.to_string().contains("invalid release name"),
            "got: {err_show}"
        );
    }
    let too_long = "a".repeat(101);
    assert!(!http::valid_release_name(&too_long));
    let err = client
        .create_release(&too_long, &dummy_commit)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid release name"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn release_show_success_and_not_found_404(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let mut api_state = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    api_state.ref_signer = Some(Arc::new(key(99)));
    let (url, server) = serve(app(api_state)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (project, doc) = new_project(&url, &runtime.pool, &login, owner).await;
    let owner_key = enroll(&url, &login, owner, 7).await;

    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let first = commit(&r1, doc, &owner_key, vec![], "initial commit").await;
    let head = first.verify().unwrap();
    let approved = plan(&r1, &client, &journal1, &scope, head.clone(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, approved)
        .await
        .unwrap();

    client.create_release("v1.0.0", &head).await.unwrap();

    // Show existing release
    let details = client
        .show_release("v1.0.0")
        .await
        .unwrap()
        .expect("release exists");
    assert_eq!(details.project_id, project);
    assert_eq!(details.name, "v1.0.0");
    assert_eq!(details.commit, head.as_str());
    assert_eq!(details.actor, owner);
    assert_eq!(details.scope, vec![doc]);

    // Show non-existent release returns Ok(None)
    let absent = client.show_release("v9.9.9").await.unwrap();
    assert!(absent.is_none());

    // CLI release_show returns Err on absent release
    let err = release_show(&client, "v9.9.9", false).await.unwrap_err();
    assert!(err.to_string().contains("not found"));

    server.abort();
    let _ = server.await;
    journal1.close().await;
    r1.close().await;
    remove(p1).await;
    remove(j1).await;
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn release_list_single_page_and_all_pagination(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let mut api_state = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    api_state.ref_signer = Some(Arc::new(key(99)));
    let (url, server) = serve(app(api_state)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (project, doc) = new_project(&url, &runtime.pool, &login, owner).await;
    let owner_key = enroll(&url, &login, owner, 7).await;

    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let first = commit(&r1, doc, &owner_key, vec![], "initial commit").await;
    let head = first.verify().unwrap();
    let approved = plan(&r1, &client, &journal1, &scope, head.clone(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, approved)
        .await
        .unwrap();

    // Create 3 releases with alphabetical names
    client.create_release("v1.0", &head).await.unwrap();
    client.create_release("v1.1", &head).await.unwrap();
    client.create_release("v2.0", &head).await.unwrap();

    // 1. Single page with limit=2
    let page1 = client.list_releases(None, Some(2)).await.unwrap();
    assert_eq!(page1.items.len(), 2);
    assert_eq!(page1.items[0].name, "v1.0");
    assert_eq!(page1.items[1].name, "v1.1");
    assert_eq!(page1.next_cursor.as_deref(), Some("v1.1"));

    // 2. Next page with after="v1.1"
    let page2 = client.list_releases(Some("v1.1"), Some(2)).await.unwrap();
    assert_eq!(page2.items.len(), 1);
    assert_eq!(page2.items[0].name, "v2.0");
    assert_eq!(page2.next_cursor.as_deref(), Some("v2.0"));

    // 3. Exhaustive pagination with all=true
    let all_out = release_list(&client, None, None, true, true).await.unwrap();
    match all_out {
        SyncOutput::Json(val) => {
            let names: Vec<&str> = val["releases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["name"].as_str().unwrap())
                .collect();
            assert_eq!(names, vec!["v1.0", "v1.1", "v2.0"]);
            assert_eq!(val["count"], 3);
        }
        SyncOutput::Text(_) => panic!("expected json output"),
    }

    server.abort();
    let _ = server.await;
    journal1.close().await;
    r1.close().await;
    remove(p1).await;
    remove(j1).await;
    runtime.close().await;
}

#[tokio::test]
async fn release_list_cursor_loop_and_out_of_order_rejection() {
    let dummy_auth = Uuid::new_v4();
    let dummy_proj = Uuid::new_v4();
    let dummy_commit = "0000000000000000000000000000000000000000000000000000000000000000";

    // Router serving out-of-order items
    let out_of_order_router = Router::new()
        .route(
            "/history/authority",
            get({
                let a = dummy_auth;
                move || async move { Json(epoch_one(a)) }
            }),
        )
        .route(
            &format!("/projects/{dummy_proj}/history/releases"),
            get(move || async move {
                Json(json!({
                    "items": [
                        {
                            "name": "v2.0",
                            "commit": dummy_commit,
                            "actor": Uuid::new_v4(),
                            "created_at": chrono::Utc::now(),
                        },
                        {
                            "name": "v1.0",
                            "commit": dummy_commit,
                            "actor": Uuid::new_v4(),
                            "created_at": chrono::Utc::now(),
                        }
                    ],
                    "next_cursor": null
                }))
            }),
        );
    let (url1, server1) = serve(out_of_order_router).await;
    let client1 = Client::new(remote(url1, dummy_auth), dummy_proj, "token", true).unwrap();
    let err_order = client1.list_releases(None, None).await.unwrap_err();
    assert!(
        err_order.to_string().contains("out-of-order"),
        "expected out-of-order error, got: {err_order}"
    );
    server1.abort();
    let _ = server1.await;

    // Router serving a pagination cursor loop (next_cursor doesn't progress)
    let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = call_count.clone();
    let loop_router = Router::new()
        .route(
            "/history/authority",
            get({
                let a = dummy_auth;
                move || async move { Json(epoch_one(a)) }
            }),
        )
        .route(
            &format!("/projects/{dummy_proj}/history/releases"),
            get(move || {
                let cc = cc.clone();
                async move {
                    let n = cc.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        Json(json!({
                            "items": [
                                {
                                    "name": "v2.0",
                                    "commit": dummy_commit,
                                    "actor": Uuid::new_v4(),
                                    "created_at": chrono::Utc::now(),
                                }
                            ],
                            "next_cursor": "v2.0"
                        }))
                    } else {
                        // Returns previous cursor or backward progress
                        Json(json!({
                            "items": [
                                {
                                    "name": "v1.0",
                                    "commit": dummy_commit,
                                    "actor": Uuid::new_v4(),
                                    "created_at": chrono::Utc::now(),
                                }
                            ],
                            "next_cursor": "v1.0"
                        }))
                    }
                }
            }),
        );
    let (url2, server2) = serve(loop_router).await;
    let client2 = Client::new(remote(url2, dummy_auth), dummy_proj, "token", true).unwrap();
    let err_loop = release_list(&client2, None, None, true, false)
        .await
        .unwrap_err();
    assert!(
        err_loop.to_string().contains("cursor loop")
            || err_loop.to_string().contains("out-of-order"),
        "expected loop/order error, got: {err_loop}"
    );
    server2.abort();
    let _ = server2.await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn release_permission_denial_403(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let mut api_state = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    api_state.ref_signer = Some(Arc::new(key(99)));
    let (url, server) = serve(app(api_state)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (_stranger, stranger_login) = actor(&runtime.pool, "stranger").await;
    let (project, doc) = new_project(&url, &runtime.pool, &login, owner).await;
    let owner_key = enroll(&url, &login, owner, 7).await;

    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let first = commit(&r1, doc, &owner_key, vec![], "initial commit").await;
    let head = first.verify().unwrap();
    let approved = plan(&r1, &client, &journal1, &scope, head.clone(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, approved)
        .await
        .unwrap();

    // 1. Stranger (not member of project) attempts to create release -> 403 Forbidden
    let stranger_client = Client::new(
        remote(url.clone(), authority),
        project,
        &stranger_login,
        true,
    )
    .unwrap();
    let err_stranger = stranger_client
        .create_release("v1.0.0", &head)
        .await
        .unwrap_err();
    assert!(
        err_stranger.to_string().contains("403"),
        "expected 403 forbidden for non-member, got: {err_stranger}"
    );

    // 2. Device key with only history:read scope attempts create_release -> 403 Forbidden
    enroll(&url, &login, owner, 8).await;
    let read_only_device = device(&url, authority, project, 8, &["history:read"]);
    let err_scope = read_only_device
        .create_release("v1.0.0", &head)
        .await
        .unwrap_err();
    assert!(
        err_scope.to_string().contains("403"),
        "expected 403 forbidden for read-only device session, got: {err_scope}"
    );

    server.abort();
    let _ = server.await;
    journal1.close().await;
    r1.close().await;
    remove(p1).await;
    remove(j1).await;
    runtime.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn release_cli_options_execution_and_local_state_untouched(pool: PgPool) {
    let authority = engine_core::repository::server_authority::install(
        &pool,
        &hex::encode(key(99).public_key().as_ref()),
    )
    .await
    .unwrap();
    let runtime = common::RuntimeDatabase::new(pool.clone()).await;
    let mut api_state = AppState::new(
        runtime.pool.clone(),
        AuthConfig {
            paseto_key: TOKEN_KEY,
            service_key: None,
            token_ttl_seconds: 3600,
            public_base_url: "http://test.local".into(),
        },
    );
    api_state.ref_signer = Some(Arc::new(key(99)));
    let (url, server) = serve(app(api_state)).await;
    let (owner, login) = actor(&runtime.pool, "owner").await;
    let (project, doc) = new_project(&url, &runtime.pool, &login, owner).await;
    let owner_key = enroll(&url, &login, owner, 7).await;

    let client = Client::new(remote(url.clone(), authority), project, &login, true).unwrap();
    client.authority().await.unwrap();
    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let (p1, r1) = repo(project).await;
    let (j1, journal1) = journal().await;
    let first = commit(&r1, doc, &owner_key, vec![], "initial commit").await;
    let head = first.verify().unwrap();
    let approved = plan(&r1, &client, &journal1, &scope, head.clone(), true)
        .await
        .unwrap();
    push(&r1, &client, &journal1, &scope, approved)
        .await
        .unwrap();
    client.create_release("v1.0.0", &head).await.unwrap();

    // Prepare files for sync::run
    let tmp = scratch();
    let remote_path = tmp.join("remote.json");
    let token_path = tmp.join("token.txt");
    std::fs::write(
        &remote_path,
        serde_json::to_vec(&remote(url.clone(), authority)).unwrap(),
    )
    .unwrap();
    std::fs::write(&token_path, &login).unwrap();

    // Snapshot repo and journal state
    let head_before = r1.head("main").await.unwrap();
    let pin_before = journal1.pin(&scope).await.unwrap();
    journal1.close().await;
    r1.close().await;
    let p1_bytes_before = std::fs::read(&p1).unwrap();
    let j1_bytes_before = std::fs::read(&j1).unwrap();

    // Run sync release list via run
    let options_list = Options {
        repository: p1.clone(),
        project,
        remote: remote_path.clone(),
        token_file: Some(token_path.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: j1.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Release {
            action: ReleaseAction::List {
                after: None,
                limit: None,
                all: false,
                json: true,
            },
        },
    };
    run(options_list).await.unwrap();

    // Run sync release show via run
    let options_show = Options {
        repository: p1.clone(),
        project,
        remote: remote_path.clone(),
        token_file: Some(token_path.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: j1.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Release {
            action: ReleaseAction::Show {
                name: "v1.0.0".into(),
                json: false,
            },
        },
    };
    run(options_show).await.unwrap();

    // Verify DB file contents are unchanged
    assert_eq!(std::fs::read(&p1).unwrap(), p1_bytes_before);
    assert_eq!(std::fs::read(&j1).unwrap(), j1_bytes_before);

    // Reopen and verify repo and journal states are untouched
    let r1_after = LocalRepository::open(&p1, project).await.unwrap();
    let journal1_after = ReceiptJournal::open(&j1).await.unwrap();
    assert_eq!(r1_after.head("main").await.unwrap(), head_before);
    assert_eq!(journal1_after.pin(&scope).await.unwrap(), pin_before);

    server.abort();
    let _ = server.await;
    journal1_after.close().await;
    r1_after.close().await;
    remove(p1).await;
    remove(j1).await;
    let _ = std::fs::remove_dir_all(&tmp);
    runtime.close().await;
}

#[tokio::test]
async fn remote_history_log_single_page_default_and_formatting() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let a0 = Address::try_from("1".repeat(64)).unwrap();
    let a1 = Address::try_from("2".repeat(64)).unwrap();

    let served_project = project;
    let served_a0 = a0.clone();
    let served_a1 = a1.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/log",
            get(
                move |axum::extract::Query(params): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| {
                    let p = served_project;
                    let c0 = served_a0.clone();
                    let c1 = served_a1.clone();
                    async move {
                        assert_eq!(params.get("head").unwrap(), c1.as_str());
                        assert_eq!(params.get("cursor"), None);
                        Json(json!({
                            "project": p,
                            "head": c1,
                            "entries": [
                                {
                                    "address": c1,
                                    "parents": [c0],
                                    "author_key": "author_key_1",
                                    "authored_at_ms": 2000,
                                    "message": "feat: second commit"
                                },
                                {
                                    "address": c0,
                                    "parents": [],
                                    "author_key": "author_key_0",
                                    "authored_at_ms": 1000,
                                    "message": "initial commit"
                                }
                            ],
                            "next_cursor": null,
                            "more": false
                        }))
                    }
                },
            ),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    let result = log(&client, Some(&a1), None, None, false, false, None)
        .await
        .unwrap();
    assert_eq!(result.project, project);
    assert_eq!(result.head, a1);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].address, a1);
    assert_eq!(result.entries[0].parents, vec![a0.clone()]);
    assert_eq!(result.entries[1].address, a0);
    assert!(result.entries[1].parents.is_empty());
    assert!(!result.more);
    assert_eq!(result.next_cursor, None);

    let text = format_log_text(&result);
    assert!(text.contains(&format!(
        "First-parent history for project {project} at commit {}:",
        a1.as_str()
    )));
    assert!(text.contains(&format!("commit {}", a1.as_str())));
    assert!(text.contains(&format!("Parent: {}", a0.as_str())));
    assert!(text.contains("Author: author_key_1"));
    assert!(text.contains("Date:   2000"));
    assert!(text.contains("    feat: second commit"));
    assert!(text.contains(&format!("commit {}", a0.as_str())));
    assert!(text.contains("Author: author_key_0"));
    assert!(text.contains("    initial commit"));
    assert!(text.contains("Note: First-parent history is not an exhaustive DAG traversal or independent proof of completeness."));

    let json_val = format_log_json(&result).unwrap();
    assert_eq!(json_val["first_parent_history"], true);
    assert_eq!(
        json_val["disclaimer"],
        "First-parent history is not an exhaustive DAG traversal or independent proof of completeness."
    );
    assert_eq!(json_val["entries"].as_array().unwrap().len(), 2);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_history_log_multi_page_all_and_cursor_continuation() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let a0 = Address::try_from("1".repeat(64)).unwrap();
    let a1 = Address::try_from("2".repeat(64)).unwrap();
    let a2 = Address::try_from("3".repeat(64)).unwrap();

    let served_project = project;
    let served_a0 = a0.clone();
    let served_a1 = a1.clone();
    let served_a2 = a2.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/log",
            get(
                move |axum::extract::Query(params): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| {
                    let p = served_project;
                    let c0 = served_a0.clone();
                    let c1 = served_a1.clone();
                    let c2 = served_a2.clone();
                    async move {
                        match params.get("cursor").map(|s| s.as_str()) {
                            None => Json(json!({
                                "project": p,
                                "head": c2,
                                "entries": [
                                    {
                                        "address": c2,
                                        "parents": [c1],
                                        "author_key": "author_key_2",
                                        "authored_at_ms": 3000,
                                        "message": "c2"
                                    }
                                ],
                                "next_cursor": "cursor_p2",
                                "more": true
                            })),
                            Some("cursor_p2") => Json(json!({
                                "project": p,
                                "head": c2,
                                "entries": [
                                    {
                                        "address": c1,
                                        "parents": [c0],
                                        "author_key": "author_key_1",
                                        "authored_at_ms": 2000,
                                        "message": "c1"
                                    },
                                    {
                                        "address": c0,
                                        "parents": [],
                                        "author_key": "author_key_0",
                                        "authored_at_ms": 1000,
                                        "message": "c0"
                                    }
                                ],
                                "next_cursor": null,
                                "more": false
                            })),
                            Some(other) => panic!("unexpected cursor {other}"),
                        }
                    }
                },
            ),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    // 1. Single page without --all stops after page 1 with next_cursor
    let page1 = log(&client, Some(&a2), None, None, false, false, None)
        .await
        .unwrap();
    assert_eq!(page1.entries.len(), 1);
    assert_eq!(page1.entries[0].address, a2);
    assert!(page1.more);
    assert_eq!(page1.next_cursor.as_deref(), Some("cursor_p2"));

    // 2. Fetch page 2 directly using cursor
    let page2 = log(&client, None, None, Some("cursor_p2"), false, false, None)
        .await
        .unwrap();
    assert_eq!(page2.head, a2);
    assert_eq!(page2.entries.len(), 2);
    assert_eq!(page2.entries[0].address, a1);
    assert_eq!(page2.entries[1].address, a0);
    assert!(!page2.more);
    assert_eq!(page2.next_cursor, None);

    // 3. Multi-page fetch using --all
    let all = log(&client, Some(&a2), None, None, true, false, None)
        .await
        .unwrap();
    assert_eq!(all.head, a2);
    assert_eq!(all.entries.len(), 3);
    assert_eq!(all.entries[0].address, a2);
    assert_eq!(all.entries[1].address, a1);
    assert_eq!(all.entries[2].address, a0);
    assert!(!all.more);
    assert_eq!(all.next_cursor, None);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_history_log_merge_commit_and_omitted_message() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let a0 = Address::try_from("1".repeat(64)).unwrap();
    let a_side = Address::try_from("8".repeat(64)).unwrap();
    let a_merge = Address::try_from("9".repeat(64)).unwrap();

    let served_project = project;
    let served_merge = a_merge.clone();
    let served_a0 = a0.clone();
    let served_side = a_side.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let p = served_project;
                let m = served_merge.clone();
                let c0 = served_a0.clone();
                let cs = served_side.clone();
                async move {
                    Json(json!({
                        "project": p,
                        "head": m,
                        "entries": [
                            {
                                "address": m,
                                "parents": [c0, cs],
                                "author_key": "author_merge",
                                "authored_at_ms": 5000,
                                "message": {
                                    "omitted": true,
                                    "bytes": 2048,
                                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                }
                            }
                        ],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    let result = log(&client, Some(&a_merge), None, None, false, false, None)
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].parents.len(), 2);

    let text = format_log_text(&result);
    assert!(text.contains(&format!("Merge: {} {}", a0.as_str(), a_side.as_str())));
    assert!(text.contains("[omitted: 2048 bytes, sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]"));

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_history_log_cursor_loop_rejection() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let a0 = Address::try_from("1".repeat(64)).unwrap();

    let served_project = project;
    let served_a0 = a0.clone();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let c = counter.clone();
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let p = served_project;
                let c0 = served_a0.clone();
                let count = c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async move {
                    let addr = Address::try_from(format!("{:064x}", count + 1)).unwrap();
                    Json(json!({
                        "project": p,
                        "head": c0,
                        "entries": [
                            {
                                "address": addr,
                                "parents": [],
                                "author_key": "author",
                                "authored_at_ms": 1000,
                                "message": "msg"
                            }
                        ],
                        // Same cursor repeated causes cursor loop detection
                        "next_cursor": "repeated_cursor",
                        "more": true
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    let err = log(&client, Some(&a0), None, None, true, false, None)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("cursor loop detected in remote history log"));

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_history_log_mismatch_rejections() {
    let project = Uuid::new_v4();
    let other_project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let a0 = Address::try_from("1".repeat(64)).unwrap();
    let a1 = Address::try_from("2".repeat(64)).unwrap();
    let other_head = Address::try_from("9".repeat(64)).unwrap();

    // 1. Project mismatch
    let p_proj = project;
    let p_a0 = a0.clone();
    let router_proj = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let _ = p_proj;
                let c0 = p_a0.clone();
                async move {
                    Json(json!({
                        "project": other_project,
                        "head": c0,
                        "entries": [],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );
    let (url_proj, server_proj) = serve(router_proj).await;
    let client_proj = Client::new(remote(url_proj, authority), project, "token", true).unwrap();
    let err_proj = log(&client_proj, Some(&a0), None, None, false, false, None)
        .await
        .unwrap_err();
    assert!(err_proj
        .to_string()
        .contains("remote report project mismatch"));
    server_proj.abort();

    // 2. Head mismatch
    let h_other = other_head.clone();
    let router_head = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let oth = h_other.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": oth,
                        "entries": [],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );
    let (url_head, server_head) = serve(router_head).await;
    let client_head = Client::new(remote(url_head, authority), project, "token", true).unwrap();
    let err_head = log(&client_head, Some(&a0), None, None, false, false, None)
        .await
        .unwrap_err();
    assert!(err_head.to_string().contains("remote report head mismatch"));
    server_head.abort();

    // 3. Duplicate commit address across pages
    let d_a0 = a0.clone();
    let d_a1 = a1.clone();
    let router_dup = Router::new()
        .route("/projects/{id}/history/authority", get(move || async move { Json(epoch_one(authority)) }))
        .route("/projects/{id}/history/log", get(move |axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>| {
            let c0 = d_a0.clone();
            let c1 = d_a1.clone();
            async move {
                if !params.contains_key("cursor") {
                    Json(json!({
                        "project": project,
                        "head": c1,
                        "entries": [{ "address": c1, "parents": [c0], "author_key": "k", "authored_at_ms": 1, "message": "m" }],
                        "next_cursor": "cur2",
                        "more": true
                    }))
                } else {
                    // Page 2 erroneously includes c1 again
                    Json(json!({
                        "project": project,
                        "head": c1,
                        "entries": [{ "address": c1, "parents": [], "author_key": "k", "authored_at_ms": 1, "message": "m" }],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }
        }));
    let (url_dup, server_dup) = serve(router_dup).await;
    let client_dup = Client::new(remote(url_dup, authority), project, "token", true).unwrap();
    let err_dup = log(&client_dup, Some(&a1), None, None, true, false, None)
        .await
        .unwrap_err();
    assert!(err_dup
        .to_string()
        .contains("duplicate commit address encountered across pages"));
    server_dup.abort();
}

#[tokio::test]
async fn remote_history_log_permission_loss_403() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let a0 = Address::try_from("1".repeat(64)).unwrap();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || async move { axum::http::StatusCode::FORBIDDEN }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    let err = log(&client, Some(&a0), None, None, false, false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("403"));

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_history_log_cli_options_execution_and_local_state_untouched() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (repo_path, repo) = repo(project).await;
    let (pin_path, journal) = journal().await;
    let a0 = Address::try_from("1".repeat(64)).unwrap();

    let served_project = project;
    let served_a0 = a0.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let p = served_project;
                let c0 = served_a0.clone();
                async move {
                    Json(json!({
                        "project": p,
                        "head": c0,
                        "entries": [
                            {
                                "address": c0,
                                "parents": [],
                                "author_key": "author_0",
                                "authored_at_ms": 1000,
                                "message": "genesis"
                            }
                        ],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;

    let remote_file = std::env::temp_dir().join(format!("remote-{}.json", Uuid::new_v4()));
    std::fs::write(
        &remote_file,
        serde_json::to_vec(&remote(url, authority)).unwrap(),
    )
    .unwrap();
    let token_file = std::env::temp_dir().join(format!("token-{}.txt", Uuid::new_v4()));
    std::fs::write(&token_file, "valid-token").unwrap();

    let options_json = Options {
        repository: repo_path.clone(),
        project,
        remote: remote_file.clone(),
        token_file: Some(token_file.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: pin_path.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Log {
            head: Some(a0.clone()),
            limit: None,
            cursor: None,
            all: false,
            verify: false,
            expect_tip: None,
            json: true,
        },
    };
    run(options_json).await.unwrap();

    let options_text = Options {
        repository: repo_path.clone(),
        project,
        remote: remote_file.clone(),
        token_file: Some(token_file.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: pin_path.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Log {
            head: Some(a0.clone()),
            limit: None,
            cursor: None,
            all: false,
            verify: false,
            expect_tip: None,
            json: false,
        },
    };
    run(options_text).await.unwrap();

    // Verify local repository branches and journal pins were not touched
    let head = repo.head("main").await.unwrap();
    assert!(
        head.is_none(),
        "local repository branches must remain untouched"
    );

    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let pin = journal.pin(&scope).await.unwrap();
    assert!(pin.is_none(), "journal pin must remain untouched");

    server.abort();
    let _ = server.await;
    repo.close().await;
    journal.close().await;
    remove(repo_path).await;
    remove(pin_path).await;
    let _ = std::fs::remove_file(remote_file);
    let _ = std::fs::remove_file(token_file);
}

fn make_test_commit(
    project: Uuid,
    parents: Vec<Address>,
    message: &str,
    authored_at_ms: i64,
    signer: &Ed25519KeyPair,
) -> SignedCommit {
    SignedCommit::sign(
        engine_core::repository::Commit {
            version: 1,
            project,
            parents,
            files: BTreeMap::new(),
            author_key: String::new(),
            authored_at_ms,
            message: message.to_string(),
            recovery: None,
            same_file_resolutions: Vec::new(),
        },
        signer,
    )
    .unwrap()
}

fn commit_to_log_entry(signed: &SignedCommit) -> serde_json::Value {
    let address = signed.verify().unwrap();
    let msg = match engine_core::repository::log::BoundedMessage::new(&signed.commit.message) {
        engine_core::repository::log::BoundedMessage::Value(v) => json!(v),
        engine_core::repository::log::BoundedMessage::Omitted(o) => json!(o),
    };
    json!({
        "address": address,
        "parents": signed.commit.parents,
        "author_key": signed.commit.author_key,
        "authored_at_ms": signed.commit.authored_at_ms,
        "message": msg,
    })
}

#[tokio::test]
async fn verify_remote_history_valid_multi_page_and_merge() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let c0 = make_test_commit(project, vec![], "genesis", 1000, &key(1));
    let a0 = c0.verify().unwrap();
    let c1 = make_test_commit(project, vec![a0.clone()], "feature 1", 2000, &key(2));
    let a1 = c1.verify().unwrap();
    let c_side = make_test_commit(project, vec![a0.clone()], "side work", 2500, &key(3));
    let a_side = c_side.verify().unwrap();
    let c2 = make_test_commit(
        project,
        vec![a1.clone(), a_side.clone()],
        "merge feature",
        3000,
        &key(4),
    );
    let a2 = c2.verify().unwrap();

    let mut commit_map = std::collections::HashMap::new();
    commit_map.insert(a0.clone(), c0.clone());
    commit_map.insert(a1.clone(), c1.clone());
    commit_map.insert(a_side.clone(), c_side.clone());
    commit_map.insert(a2.clone(), c2.clone());
    let commits = Arc::new(commit_map);

    let store = Arc::clone(&commits);
    let e0 = commit_to_log_entry(&c0);
    let e1 = commit_to_log_entry(&c1);
    let e2 = commit_to_log_entry(&c2);

    let p_a2 = a2.clone();
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let s = Arc::clone(&store);
                    async move {
                        if let Ok(addr) = Address::try_from(address) {
                            if let Some(signed) = s.get(&addr) {
                                return (axum::http::StatusCode::OK, Json(json!(signed)))
                                    .into_response();
                            }
                        }
                        (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(
                move |axum::extract::Query(params): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| {
                    let head = p_a2.clone();
                    let entry2 = e2.clone();
                    let entry1 = e1.clone();
                    let entry0 = e0.clone();
                    async move {
                        if !params.contains_key("cursor") {
                            Json(json!({
                                "project": project,
                                "head": head,
                                "entries": [entry2],
                                "next_cursor": "page2",
                                "more": true
                            }))
                        } else if params.get("cursor").map(|s| s.as_str()) == Some("page2") {
                            Json(json!({
                                "project": project,
                                "head": head,
                                "entries": [entry1, entry0],
                                "next_cursor": null,
                                "more": false
                            }))
                        } else {
                            Json(json!({
                                "project": project,
                                "head": head,
                                "entries": [],
                                "next_cursor": null,
                                "more": false
                            }))
                        }
                    }
                },
            ),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    // 1. Single page verification
    let single_page = log(&client, Some(&a2), None, None, false, true, Some(&a2))
        .await
        .unwrap();
    assert!(single_page.verified);
    assert_eq!(single_page.verified_tip.as_ref(), Some(&a2));
    assert_eq!(single_page.entries.len(), 1);
    assert_eq!(single_page.entries[0].address, a2);
    assert!(single_page.more);
    assert_eq!(single_page.next_cursor.as_deref(), Some("page2"));

    // 2. Multi page complete verification across pages
    let all_pages = log(&client, Some(&a2), None, None, true, true, Some(&a2))
        .await
        .unwrap();
    assert!(all_pages.verified);
    assert_eq!(all_pages.verified_tip.as_ref(), Some(&a2));
    assert_eq!(all_pages.entries.len(), 3);
    assert_eq!(all_pages.entries[0].address, a2);
    assert_eq!(all_pages.entries[1].address, a1);
    assert_eq!(all_pages.entries[2].address, a0);
    assert!(!all_pages.more);
    assert_eq!(all_pages.next_cursor, None);

    // 3. Output formatting verification
    let text = format_log_text(&all_pages);
    assert!(text.contains(&format!("verified against expected tip {}", a2.as_str())));
    assert!(text.contains("Notice: Verified against signed commit envelopes. Proves consistency with selected first-parent tip; does not prove human authorship, independent timestamps, all second-parent work, or server freshness."));

    let json_val = format_log_json(&all_pages).unwrap();
    assert_eq!(json_val["verified"], true);
    assert_eq!(json_val["verified_tip"], a2.as_str());
    assert!(json_val["verification_notice"]
        .as_str()
        .unwrap()
        .contains("Verified against signed commit envelopes"));

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn verify_remote_history_wrong_tip_rejected() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let c0 = make_test_commit(project, vec![], "genesis", 1000, &key(1));
    let a0 = c0.verify().unwrap();
    let c1 = make_test_commit(project, vec![a0.clone()], "feature 1", 2000, &key(2));
    let a1 = c1.verify().unwrap();

    let mut commit_map = std::collections::HashMap::new();
    commit_map.insert(a0.clone(), c0.clone());
    commit_map.insert(a1.clone(), c1.clone());
    let store = Arc::new(commit_map);

    let e1 = commit_to_log_entry(&c1);
    let p_a1 = a1.clone();
    let store_c1 = Arc::clone(&store);
    let e1_c1 = e1.clone();
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let s = Arc::clone(&store_c1);
                    async move {
                        if let Ok(addr) = Address::try_from(address) {
                            if let Some(signed) = s.get(&addr) {
                                return (axum::http::StatusCode::OK, Json(json!(signed)))
                                    .into_response();
                            }
                        }
                        (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let head = p_a1.clone();
                let entry1 = e1_c1.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": head,
                        "entries": [entry1],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    // Caller expects a0, but server returned a1 as first commit
    let err = log(&client, Some(&a1), None, None, false, true, Some(&a0))
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("--head and --expect-tip must match"));

    // Head omitted, expect_tip a0; server reports head a1
    let err2 = log(&client, None, None, None, false, true, Some(&a0))
        .await
        .unwrap_err();
    assert!(err2.to_string().contains("remote report head mismatch"));

    // Server reports head a0, but entries[0] has a1 (discontinuity)
    let p_a0 = a0.clone();
    let entry_a1 = e1.clone();
    let store_c2 = Arc::clone(&store);
    let router_disc = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let s = Arc::clone(&store_c2);
                    async move {
                        if let Ok(addr) = Address::try_from(address) {
                            if let Some(signed) = s.get(&addr) {
                                return (axum::http::StatusCode::OK, Json(json!(signed)))
                                    .into_response();
                            }
                        }
                        (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let head = p_a0.clone();
                let ent = entry_a1.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": head,
                        "entries": [ent],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );
    let (url_disc, server_disc) = serve(router_disc).await;
    let client_disc = Client::new(remote(url_disc, authority), project, "token", true).unwrap();
    let err_disc = log(&client_disc, None, None, None, false, true, Some(&a0))
        .await
        .unwrap_err();
    assert!(err_disc
        .to_string()
        .contains("history chain discontinuity: expected commit"));
    server_disc.abort();

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn verify_remote_history_skipped_or_reordered_commit_rejected() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let c0 = make_test_commit(project, vec![], "genesis", 1000, &key(1));
    let a0 = c0.verify().unwrap();
    let c1 = make_test_commit(project, vec![a0.clone()], "feature 1", 2000, &key(2));
    let a1 = c1.verify().unwrap();
    let c2 = make_test_commit(project, vec![a1.clone()], "feature 2", 3000, &key(3));
    let a2 = c2.verify().unwrap();

    let mut commit_map = std::collections::HashMap::new();
    commit_map.insert(a0.clone(), c0.clone());
    commit_map.insert(a1.clone(), c1.clone());
    commit_map.insert(a2.clone(), c2.clone());
    let store = Arc::new(commit_map);

    let e0 = commit_to_log_entry(&c0);
    let e1 = commit_to_log_entry(&c1);
    let e2 = commit_to_log_entry(&c2);

    // Case 1: Skipped commit (c2 then c0 directly, skipping c1)
    let s1 = Arc::clone(&store);
    let p_a2 = a2.clone();
    let e2_skip = e2.clone();
    let e0_skip = e0.clone();
    let router_skip = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let s = Arc::clone(&s1);
                    async move {
                        if let Ok(addr) = Address::try_from(address) {
                            if let Some(signed) = s.get(&addr) {
                                return (axum::http::StatusCode::OK, Json(json!(signed)))
                                    .into_response();
                            }
                        }
                        (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let head = p_a2.clone();
                let entry2 = e2_skip.clone();
                let entry0 = e0_skip.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": head,
                        "entries": [entry2, entry0],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );
    let (url_skip, server_skip) = serve(router_skip).await;
    let client_skip = Client::new(remote(url_skip, authority), project, "token", true).unwrap();
    let err_skip = log(&client_skip, Some(&a2), None, None, false, true, Some(&a2))
        .await
        .unwrap_err();
    assert!(err_skip
        .to_string()
        .contains("history chain discontinuity: expected commit"));
    server_skip.abort();

    // Case 2: Reordered commits (c2, c0, c1)
    let s2 = Arc::clone(&store);
    let p_a2_ro = a2.clone();
    let e2_ro = e2.clone();
    let e1_ro = e1.clone();
    let e0_ro = e0.clone();
    let router_ro = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let s = Arc::clone(&s2);
                    async move {
                        if let Ok(addr) = Address::try_from(address) {
                            if let Some(signed) = s.get(&addr) {
                                return (axum::http::StatusCode::OK, Json(json!(signed)))
                                    .into_response();
                            }
                        }
                        (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let head = p_a2_ro.clone();
                let entry2 = e2_ro.clone();
                let entry1 = e1_ro.clone();
                let entry0 = e0_ro.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": head,
                        "entries": [entry2, entry0, entry1],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );
    let (url_ro, server_ro) = serve(router_ro).await;
    let client_ro = Client::new(remote(url_ro, authority), project, "token", true).unwrap();
    let err_ro = log(&client_ro, Some(&a2), None, None, false, true, Some(&a2))
        .await
        .unwrap_err();
    assert!(err_ro
        .to_string()
        .contains("history chain discontinuity: expected commit"));
    server_ro.abort();
}

#[tokio::test]
async fn verify_remote_history_tampered_envelope_or_signature_rejected() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let c0 = make_test_commit(project, vec![], "genesis", 1000, &key(1));
    let a0 = c0.verify().unwrap();
    let mut c1_tampered = make_test_commit(project, vec![a0.clone()], "feature 1", 2000, &key(2));
    let a1 = c1_tampered.verify().unwrap();
    c1_tampered.signature = "00".repeat(64);

    let e0 = commit_to_log_entry(&c0);
    let e1 = json!({
        "address": a1,
        "parents": [a0],
        "author_key": c1_tampered.commit.author_key,
        "authored_at_ms": 2000,
        "message": "feature 1",
    });

    let a0_route = a0.clone();
    let a1_route = a1.clone();
    let a1_log = a1.clone();
    let head = a1.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let c0_clone = c0.clone();
                    let c1_t = c1_tampered.clone();
                    let a0_c = a0_route.clone();
                    let a1_c = a1_route.clone();
                    async move {
                        if address == a0_c.as_str() {
                            (axum::http::StatusCode::OK, Json(json!(c0_clone))).into_response()
                        } else if address == a1_c.as_str() {
                            (axum::http::StatusCode::OK, Json(json!(c1_t))).into_response()
                        } else {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                        }
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let h = a1_log.clone();
                let entry1 = e1.clone();
                let entry0 = e0.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": h,
                        "entries": [entry1, entry0],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = log(&client, Some(&head), None, None, false, true, Some(&head))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("invalid signature")
            || err.to_string().contains("commit signature")
            || err.to_string().contains("invalid signed commit envelope")
    );
    server.abort();
}

#[tokio::test]
async fn verify_remote_history_cross_project_envelope_rejected() {
    let project = Uuid::new_v4();
    let other_project = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let c0_other = make_test_commit(other_project, vec![], "genesis", 1000, &key(1));
    let a0 = c0_other.verify().unwrap();
    let c1 = make_test_commit(project, vec![a0.clone()], "feature 1", 2000, &key(2));
    let a1 = c1.verify().unwrap();

    let e0 = commit_to_log_entry(&c0_other);
    let e1 = commit_to_log_entry(&c1);

    let a0_route = a0.clone();
    let a1_route = a1.clone();
    let a1_log = a1.clone();
    let head = a1.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let c0_c = c0_other.clone();
                    let c1_c = c1.clone();
                    let a0_c = a0_route.clone();
                    let a1_c = a1_route.clone();
                    async move {
                        if address == a0_c.as_str() {
                            (axum::http::StatusCode::OK, Json(json!(c0_c))).into_response()
                        } else if address == a1_c.as_str() {
                            (axum::http::StatusCode::OK, Json(json!(c1_c))).into_response()
                        } else {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                        }
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let h = a1_log.clone();
                let entry1 = e1.clone();
                let entry0 = e0.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": h,
                        "entries": [entry1, entry0],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = log(&client, Some(&head), None, None, false, true, Some(&head))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("remote commit address/project mismatch")
            || err.to_string().contains("signed commit project mismatch")
    );
    server.abort();
}

#[tokio::test]
async fn verify_remote_history_claimed_end_without_genesis_rejected() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let c0 = make_test_commit(project, vec![], "genesis", 1000, &key(1));
    let a0 = c0.verify().unwrap();
    let c1 = make_test_commit(project, vec![a0.clone()], "feature 1", 2000, &key(2));
    let a1 = c1.verify().unwrap();

    let e1 = commit_to_log_entry(&c1);

    let a1_route = a1.clone();
    let a1_log = a1.clone();
    let head = a1.clone();

    // Server claims log ends at c1 (more: false, next_cursor: null), but c1 has parent a0
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let c1_c = c1.clone();
                    let a1_c = a1_route.clone();
                    async move {
                        if address == a1_c.as_str() {
                            (axum::http::StatusCode::OK, Json(json!(c1_c))).into_response()
                        } else {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                        }
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let h = a1_log.clone();
                let entry1 = e1.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": h,
                        "entries": [entry1],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    // 1. Single page: claims end without genesis
    let err_single = log(&client, Some(&head), None, None, false, true, Some(&head))
        .await
        .unwrap_err();
    assert!(err_single
        .to_string()
        .contains("log claims to have reached genesis (end of history), but last commit"));

    // 2. Multi page: claims end without genesis
    let err_all = log(&client, Some(&head), None, None, true, true, Some(&head))
        .await
        .unwrap_err();
    assert!(err_all
        .to_string()
        .contains("log claims to have reached genesis (end of history), but last commit"));

    server.abort();
}

#[tokio::test]
async fn verify_remote_history_untrusted_metadata_mismatch_rejected() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let c0 = make_test_commit(project, vec![], "genesis", 1000, &key(1));
    let a0 = c0.verify().unwrap();

    // Server tampers with message in log page
    let mut e0_tampered = commit_to_log_entry(&c0);
    e0_tampered["message"] = json!("malicious modified message");

    let a0_route = a0.clone();
    let a0_log = a0.clone();
    let head = a0.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let c0_c = c0.clone();
                    let a0_c = a0_route.clone();
                    async move {
                        if address == a0_c.as_str() {
                            (axum::http::StatusCode::OK, Json(json!(c0_c))).into_response()
                        } else {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                        }
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let h = a0_log.clone();
                let entry0 = e0_tampered.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": h,
                        "entries": [entry0],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = log(&client, Some(&head), None, None, false, true, Some(&head))
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("untrusted metadata message mismatch"));
    server.abort();
}

#[tokio::test]
async fn verify_remote_history_missing_envelope_rejected() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let c0 = make_test_commit(project, vec![], "genesis", 1000, &key(1));
    let a0 = c0.verify().unwrap();
    let e0 = commit_to_log_entry(&c0);

    let a0_log = a0.clone();
    let head = a0.clone();

    // Server returns 404 for commits/{address}
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(|| async { (axum::http::StatusCode::NOT_FOUND, "missing").into_response() }),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let h = a0_log.clone();
                let entry0 = e0.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "head": h,
                        "entries": [entry0],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = log(&client, Some(&head), None, None, false, true, Some(&head))
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("missing signed commit envelope for"));
    server.abort();
}

#[tokio::test]
async fn verify_remote_history_cli_options_execution_and_local_state_untouched() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (repo_path, repo) = repo(project).await;
    let (pin_path, journal) = journal().await;

    let c0 = make_test_commit(project, vec![], "genesis commit", 1000, &key(1));
    let a0 = c0.verify().unwrap();
    let e0 = commit_to_log_entry(&c0);

    let served_project = project;
    let served_a0 = a0.clone();
    let c0_for_server = c0.clone();

    let a0_route = served_a0.clone();
    let a0_log = served_a0.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(
                move |axum::extract::Path((_id, address)): axum::extract::Path<(Uuid, String)>| {
                    let c = c0_for_server.clone();
                    let a = a0_route.clone();
                    async move {
                        if address == a.as_str() {
                            (axum::http::StatusCode::OK, Json(json!(c))).into_response()
                        } else {
                            (axum::http::StatusCode::NOT_FOUND, "not found").into_response()
                        }
                    }
                },
            ),
        )
        .route(
            "/projects/{id}/history/log",
            get(move || {
                let p = served_project;
                let c0_addr = a0_log.clone();
                let entry0 = e0.clone();
                async move {
                    Json(json!({
                        "project": p,
                        "head": c0_addr,
                        "entries": [entry0],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;

    let remote_file = std::env::temp_dir().join(format!("remote-{}.json", Uuid::new_v4()));
    std::fs::write(
        &remote_file,
        serde_json::to_vec(&remote(url, authority)).unwrap(),
    )
    .unwrap();
    let token_file = std::env::temp_dir().join(format!("token-{}.txt", Uuid::new_v4()));
    std::fs::write(&token_file, "valid-token").unwrap();

    let options_json = Options {
        repository: repo_path.clone(),
        project,
        remote: remote_file.clone(),
        token_file: Some(token_file.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: pin_path.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Log {
            head: None,
            limit: None,
            cursor: None,
            all: false,
            verify: true,
            expect_tip: Some(served_a0.clone()),
            json: true,
        },
    };
    run(options_json).await.unwrap();

    let options_text = Options {
        repository: repo_path.clone(),
        project,
        remote: remote_file.clone(),
        token_file: Some(token_file.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: pin_path.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Log {
            head: Some(served_a0.clone()),
            limit: None,
            cursor: None,
            all: false,
            verify: true,
            expect_tip: Some(served_a0.clone()),
            json: false,
        },
    };
    run(options_text).await.unwrap();

    // Verify local repository branches and journal pins were not touched
    let head = repo.head("main").await.unwrap();
    assert!(
        head.is_none(),
        "local repository branches must remain untouched"
    );

    let scope = Scope {
        authority,
        project,
        branch: "main".into(),
    };
    let pin = journal.pin(&scope).await.unwrap();
    assert!(pin.is_none(), "journal pin must remain untouched");

    server.abort();
    let _ = server.await;
    repo.close().await;
    journal.close().await;
    remove(repo_path).await;
    remove(pin_path).await;
    let _ = std::fs::remove_file(remote_file);
    let _ = std::fs::remove_file(token_file);
}

#[tokio::test]
async fn remote_compare_multi_page_success_and_local_state_unchanged() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (repo_path, repo) = repo(project).await;
    let (pin_path, journal) = journal().await;
    let scope = Scope {
        project,
        authority,
        branch: "main".into(),
    };
    let initial_heads = repo.head("main").await.unwrap();
    let initial_pin = journal.pin(&scope).await.unwrap();

    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();
    let doc1 = Uuid::new_v4();
    let doc2 = Uuid::new_v4();
    let doc3 = Uuid::new_v4();
    let a1 = Address::try_from("a".repeat(64)).unwrap();
    let a2 = Address::try_from("b".repeat(64)).unwrap();

    let served_project = project;
    let served_from = from.clone();
    let served_to = to.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare",
            get(move |Query(params): Query<HashMap<String, String>>| {
                let p = served_project;
                let f = served_from.clone();
                let t = served_to.clone();
                let a1 = a1.clone();
                let a2 = a2.clone();
                async move {
                    assert_eq!(params.get("from").unwrap(), f.as_str());
                    assert_eq!(params.get("to").unwrap(), t.as_str());
                    let cursor = params.get("cursor").cloned();
                    if cursor.is_none() {
                        Json(json!({
                            "project": p,
                            "from": f,
                            "to": t,
                            "totals": {
                                "added": 1,
                                "removed": 1,
                                "modified": 1,
                                "unchanged": 0,
                                "total_changes": 3
                            },
                            "changes": [
                                {
                                    "path": "a.txt",
                                    "kind": "added",
                                    "to": { "document": doc1, "state": a1 }
                                },
                                {
                                    "path": "b.txt",
                                    "kind": "modified",
                                    "from": { "document": doc2, "state": a1 },
                                    "to": { "document": doc2, "state": a2 }
                                }
                            ],
                            "next_cursor": "cursor_page2",
                            "more": true
                        }))
                    } else if cursor.as_deref() == Some("cursor_page2") {
                        Json(json!({
                            "project": p,
                            "from": f,
                            "to": t,
                            "totals": {
                                "added": 1,
                                "removed": 1,
                                "modified": 1,
                                "unchanged": 0,
                                "total_changes": 3
                            },
                            "changes": [
                                {
                                    "path": "c.txt",
                                    "kind": "removed",
                                    "from": { "document": doc3, "state": a1 }
                                }
                            ],
                            "next_cursor": null,
                            "more": false
                        }))
                    } else {
                        panic!("unexpected cursor: {:?}", cursor);
                    }
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "synthetic", true).unwrap();

    let report = compare(&client, &from, &to).await.unwrap();
    assert_eq!(report.project, project);
    assert_eq!(report.from, from);
    assert_eq!(report.to, to);
    assert_eq!(report.totals.total_changes, 3);
    assert_eq!(report.changes.len(), 3);
    assert_eq!(report.changes[0].path, "a.txt");
    assert_eq!(report.changes[1].path, "b.txt");
    assert_eq!(report.changes[2].path, "c.txt");

    let text = format_compare_text(&report);
    assert!(text.contains("Server-produced metadata (unverified by receipt journal)"));
    assert!(text.contains("+ a.txt"));
    assert!(text.contains("~ b.txt"));
    assert!(text.contains("- c.txt"));
    assert!(text.contains("Totals:  3 change(s) (1 added, 1 removed, 1 modified, 0 unchanged)"));

    let json_val = format_compare_json(&report).unwrap();
    assert_eq!(json_val["server_metadata"], true);
    assert!(json_val["disclaimer"]
        .as_str()
        .unwrap()
        .contains("Server-produced metadata"));

    // Verify local repository and receipt journal are untouched
    assert_eq!(repo.head("main").await.unwrap(), initial_heads);
    assert_eq!(journal.pin(&scope).await.unwrap(), initial_pin);

    server.abort();
    let _ = server.await;
    repo.close().await;
    journal.close().await;
    remove(repo_path).await;
    remove(pin_path).await;
}

#[tokio::test]
async fn remote_compare_mid_run_401_with_one_allowed_refresh() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();
    let doc1 = Uuid::new_v4();
    let doc2 = Uuid::new_v4();
    let a1 = Address::try_from("a".repeat(64)).unwrap();

    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let refresh_calls_clone = refresh_calls.clone();

    let f_served = from.clone();
    let t_served = to.clone();
    let router = Router::new()
        .route(
            "/auth/refresh",
            axum::routing::post(move |Json(body): Json<Value>| {
                let calls = refresh_calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(body["refresh_token"], "1111111111222222222233333333334444444444555555555566666666667777");
                    Json(json!({
                        "access_token": "token_renewed",
                        "refresh_token": "8888888888999999999900000000001111111111222222222233333333334444",
                        "expires_in": 3600
                    }))
                }
            }),
        )
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare",
            get(move |headers: HeaderMap, Query(params): Query<HashMap<String, String>>| {
                let f = f_served.clone();
                let t = t_served.clone();
                let a1 = a1.clone();
                async move {
                    let auth = headers.get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
                    let cursor = params.get("cursor").cloned();
                    if cursor.is_none() {
                        // First page succeeds with initial token
                        assert_eq!(auth, "Bearer token_initial");
                        (
                            StatusCode::OK,
                            Json(json!({
                                "project": project,
                                "from": f,
                                "to": t,
                                "totals": { "added": 2, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 2 },
                                "changes": [
                                    { "path": "1.txt", "kind": "added", "to": { "document": doc1, "state": a1 } }
                                ],
                                "next_cursor": "p2",
                                "more": true
                            })),
                        ).into_response()
                    } else if auth == "Bearer token_initial" {
                        // Page 2 fails with 401 when using initial token
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({ "error": "token expired" })),
                        ).into_response()
                    } else if auth == "Bearer token_renewed" && cursor.as_deref() == Some("p2") {
                        // Page 2 succeeds with renewed token
                        (
                            StatusCode::OK,
                            Json(json!({
                                "project": project,
                                "from": f,
                                "to": t,
                                "totals": { "added": 2, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 2 },
                                "changes": [
                                    { "path": "2.txt", "kind": "added", "to": { "document": doc2, "state": a1 } }
                                ],
                                "next_cursor": null,
                                "more": false
                            })),
                        ).into_response()
                    } else {
                        (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid state"}))).into_response()
                    }
                }
            }),
        );

    let (url, server) = serve(router).await;

    let refresh_file = std::env::temp_dir().join(format!("dynodoc-ref-{}.txt", Uuid::new_v4()));
    let access_file = std::env::temp_dir().join(format!("dynodoc-acc-{}.txt", Uuid::new_v4()));
    crate::private_file::write_private_test(
        &refresh_file,
        b"1111111111222222222233333333334444444444555555555566666666667777\n",
    )
    .unwrap();
    crate::private_file::write_private_test(&access_file, b"token_initial\n").unwrap();

    let client = Client::with_credential(
        remote(url, authority),
        project,
        Credential::Refresh {
            refresh_file: refresh_file.clone(),
            access_file: Some(access_file.clone()),
        },
        Some("token_initial"),
        true,
    )
    .unwrap();

    let report = compare(&client, &from, &to).await.unwrap();
    assert_eq!(report.changes.len(), 2);
    assert_eq!(refresh_calls.load(Ordering::Relaxed), 1);

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_file(refresh_file);
    let _ = std::fs::remove_file(access_file);
}

#[tokio::test]
async fn remote_compare_mid_run_403_and_unauthorized_loss() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare",
            get(|| async { (StatusCode::FORBIDDEN, Json(json!({"error": "denied"}))) }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(
        remote(url, authority),
        project,
        "my_secret_token_12345",
        true,
    )
    .unwrap();

    let err = compare(&client, &from, &to).await.unwrap_err().to_string();
    assert!(err.contains("403"));
    assert!(
        !err.contains("my_secret_token_12345"),
        "must never log bearer token"
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_compare_integrity_checks_and_error_handling() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();

    // 1. Cursor loop
    let f1 = from.clone();
    let t1 = to.clone();
    let loop_calls = Arc::new(AtomicUsize::new(0));
    let lc = loop_calls.clone();
    let router = Router::new()
        .route("/projects/{id}/history/authority", get(move || async move { Json(epoch_one(authority)) }))
        .route("/projects/{id}/history/compare", get(move || {
            let f = f1.clone();
            let t = t1.clone();
            let lc = lc.clone();
            async move {
                let call = lc.fetch_add(1, Ordering::Relaxed);
                let path = if call == 0 { "a.txt" } else { "b.txt" };
                Json(json!({
                    "project": project,
                    "from": f,
                    "to": t,
                    "totals": { "added": 2, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 2 },
                    "changes": [{ "path": path, "kind": "added" }],
                    "next_cursor": "loop_cursor",
                    "more": true
                }))
            }
        }));
    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = compare(&client, &from, &to).await.unwrap_err().to_string();
    assert!(
        err.contains("cursor loop"),
        "expected cursor loop error, got: {err}"
    );
    server.abort();
    let _ = server.await;

    // 2. Out of order changes
    let f2 = from.clone();
    let t2 = to.clone();
    let router = Router::new()
        .route("/projects/{id}/history/authority", get(move || async move { Json(epoch_one(authority)) }))
        .route("/projects/{id}/history/compare", get(move || {
            let f = f2.clone();
            let t = t2.clone();
            async move {
                Json(json!({
                    "project": project,
                    "from": f,
                    "to": t,
                    "totals": { "added": 2, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 2 },
                    "changes": [
                        { "path": "z.txt", "kind": "added" },
                        { "path": "a.txt", "kind": "added" }
                    ],
                    "next_cursor": null,
                    "more": false
                }))
            }
        }));
    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = compare(&client, &from, &to).await.unwrap_err().to_string();
    assert!(
        err.contains("out of order"),
        "expected out of order error, got: {err}"
    );
    server.abort();
    let _ = server.await;

    // 3. Foreign address / mismatch
    let foreign = Address::try_from("9".repeat(64)).unwrap();
    let t3 = to.clone();
    let router = Router::new()
        .route("/projects/{id}/history/authority", get(move || async move { Json(epoch_one(authority)) }))
        .route("/projects/{id}/history/compare", get(move || {
            let f = foreign.clone();
            let t = t3.clone();
            async move {
                Json(json!({
                    "project": project,
                    "from": f,
                    "to": t,
                    "totals": { "added": 1, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 1 },
                    "changes": [{ "path": "a.txt", "kind": "added" }],
                    "next_cursor": null,
                    "more": false
                }))
            }
        }));
    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = compare(&client, &from, &to).await.unwrap_err().to_string();
    assert!(
        err.contains("from-address mismatch"),
        "expected from-address mismatch, got: {err}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_compare_cli_options_execution() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (repo_path, repo) = repo(project).await;
    let (pin_path, journal) = journal().await;
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();

    let from_served = from.clone();
    let to_served = to.clone();
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare",
            get(move || {
                let f = from_served.clone();
                let t = to_served.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "from": f,
                        "to": t,
                        "totals": { "added": 1, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 1 },
                        "changes": [{ "path": "doc.txt", "kind": "added" }],
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let remote_file = std::env::temp_dir().join(format!("dynodoc-remote-{}.json", Uuid::new_v4()));
    let token_file = std::env::temp_dir().join(format!("dynodoc-tok-{}.txt", Uuid::new_v4()));
    std::fs::write(
        &remote_file,
        serde_json::to_vec(&remote(url, authority)).unwrap(),
    )
    .unwrap();
    crate::private_file::write_private_test(&token_file, b"token_test\n").unwrap();

    // Run with json: true
    let options_json = Options {
        repository: repo_path.clone(),
        project,
        remote: remote_file.clone(),
        token_file: Some(token_file.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: pin_path.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Compare {
            from: from.clone(),
            to: to.clone(),
            path: None,
            json: true,
        },
    };
    run(options_json).await.unwrap();

    // Run with json: false (text)
    let options_text = Options {
        repository: repo_path.clone(),
        project,
        remote: remote_file.clone(),
        token_file: Some(token_file.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: pin_path.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Compare {
            from: from.clone(),
            to: to.clone(),
            path: None,
            json: false,
        },
    };
    run(options_text).await.unwrap();

    server.abort();
    let _ = server.await;
    repo.close().await;
    journal.close().await;
    remove(repo_path).await;
    remove(pin_path).await;
    let _ = std::fs::remove_file(remote_file);
    let _ = std::fs::remove_file(token_file);
}

#[tokio::test]
async fn remote_file_compare_multi_page_success_and_local_state_unchanged() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (repo_path, repo) = repo(project).await;
    let (pin_path, journal) = journal().await;
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();
    let root1 = Address::try_from("a".repeat(64)).unwrap();
    let root2 = Address::try_from("b".repeat(64)).unwrap();
    let doc_id = Uuid::new_v4();

    let served_project = project;
    let served_from = from.clone();
    let served_to = to.clone();
    let r1 = root1.clone();
    let r2 = root2.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare/file",
            get(move |Query(params): Query<HashMap<String, String>>| {
                let p = served_project;
                let f = served_from.clone();
                let t = served_to.clone();
                let r1 = r1.clone();
                let r2 = r2.clone();
                async move {
                    assert_eq!(params.get("from").unwrap(), f.as_str());
                    assert_eq!(params.get("to").unwrap(), t.as_str());
                    assert_eq!(params.get("path").unwrap(), "doc.txt");
                    let cursor = params.get("cursor").cloned();
                    if cursor.is_none() {
                        Json(json!({
                            "project": p,
                            "from": f,
                            "to": t,
                            "path": "doc.txt",
                            "kind": "modified",
                            "from_file": { "document": doc_id, "state": r1 },
                            "to_file": { "document": doc_id, "state": r2 },
                            "document_replaced": false,
                            "node_diff": {
                                "document_id": doc_id,
                                "from_root": r1,
                                "to_root": r2,
                                "whole_state_identical": false,
                                "totals": { "added": 1, "removed": 1, "modified": 1, "unchanged": 0, "total_changes": 3 },
                                "components": {
                                    "comments_changed": true,
                                    "comments_from_count": 0,
                                    "comments_to_count": 2,
                                    "suggestions_changed": false,
                                    "suggestions_from_count": 0,
                                    "suggestions_to_count": 0,
                                    "removed_choices_changed": false,
                                    "removed_choices_from_count": 0,
                                    "removed_choices_to_count": 0
                                },
                                "changes": [
                                    {
                                        "node_id": "node_01",
                                        "kind": "modified",
                                        "from": { "id": "node_01", "node_type": "paragraph", "pos": "a0", "deleted": false },
                                        "to": { "id": "node_01", "node_type": "paragraph", "pos": "a0", "deleted": false },
                                        "field_changes": [
                                            {
                                                "field": "content",
                                                "from": { "omitted": true, "bytes": 10000, "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" },
                                                "to": "small"
                                            }
                                        ]
                                    },
                                    {
                                        "node_id": "node_02",
                                        "kind": "removed",
                                        "from": { "id": "node_02", "node_type": "paragraph", "pos": "a1", "deleted": false },
                                        "to": null,
                                        "field_changes": []
                                    }
                                ],
                                "next_cursor": "page2",
                                "more": true,
                                "limits": "finite limits"
                            },
                            "next_cursor": "page2",
                            "more": true
                        }))
                    } else if cursor.as_deref() == Some("page2") {
                        Json(json!({
                            "project": p,
                            "from": f,
                            "to": t,
                            "path": "doc.txt",
                            "kind": "modified",
                            "from_file": { "document": doc_id, "state": r1 },
                            "to_file": { "document": doc_id, "state": r2 },
                            "document_replaced": false,
                            "node_diff": {
                                "document_id": doc_id,
                                "from_root": r1,
                                "to_root": r2,
                                "whole_state_identical": false,
                                "totals": { "added": 1, "removed": 1, "modified": 1, "unchanged": 0, "total_changes": 3 },
                                "components": {
                                    "comments_changed": true,
                                    "comments_from_count": 0,
                                    "comments_to_count": 2,
                                    "suggestions_changed": false,
                                    "suggestions_from_count": 0,
                                    "suggestions_to_count": 0,
                                    "removed_choices_changed": false,
                                    "removed_choices_from_count": 0,
                                    "removed_choices_to_count": 0
                                },
                                "changes": [
                                    {
                                        "node_id": "node_03",
                                        "kind": "added",
                                        "from": null,
                                        "to": { "id": "node_03", "node_type": "paragraph", "pos": "a2", "deleted": false },
                                        "field_changes": [
                                            {
                                                "field": "content",
                                                "from": null,
                                                "to": "new node"
                                            }
                                        ]
                                    }
                                ],
                                "next_cursor": null,
                                "more": false,
                                "limits": "finite limits"
                            },
                            "next_cursor": null,
                            "more": false
                        }))
                    } else {
                        panic!("unexpected cursor: {:?}", cursor);
                    }
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    let report = compare_file(&client, &from, &to, "doc.txt").await.unwrap();
    assert_eq!(report.project, project);
    assert_eq!(report.from, from);
    assert_eq!(report.to, to);
    assert_eq!(report.path, "doc.txt");
    assert_eq!(report.kind, DiffKind::Modified);
    assert!(!report.document_replaced);

    let nd = report.node_diff.as_ref().unwrap();
    assert_eq!(nd.changes.len(), 3);
    assert_eq!(nd.changes[0].node_id.0, "node_01");
    assert_eq!(nd.changes[1].node_id.0, "node_02");
    assert_eq!(nd.changes[2].node_id.0, "node_03");

    // Text output verification
    let text = format_file_compare_text(&report);
    assert!(text.contains("Server-produced metadata"));
    assert!(text.contains("doc.txt"));
    assert!(text.contains("[omitted: 10000 bytes"));
    assert!(text.contains("comments (from: 0, to: 2, changed: true)"));

    // JSON output verification
    let json_val = format_file_compare_json(&report).unwrap();
    assert_eq!(json_val["server_metadata"], true);
    assert!(json_val["disclaimer"].is_string());

    server.abort();
    let _ = server.await;
    repo.close().await;
    journal.close().await;
    remove(repo_path).await;
    remove(pin_path).await;
}

#[tokio::test]
async fn remote_file_compare_replaced_and_added_and_removed() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();
    let doc1 = Uuid::new_v4();
    let doc2 = Uuid::new_v4();
    let root1 = Address::try_from("a".repeat(64)).unwrap();
    let root2 = Address::try_from("b".repeat(64)).unwrap();

    let p_c = project;
    let f_c = from.clone();
    let t_c = to.clone();
    let r1 = root1.clone();
    let r2 = root2.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare/file",
            get(move |Query(params): Query<HashMap<String, String>>| {
                let p = p_c;
                let f = f_c.clone();
                let t = t_c.clone();
                let r1 = r1.clone();
                let r2 = r2.clone();
                async move {
                    let path = params.get("path").unwrap().as_str();
                    match path {
                        "replaced.txt" => Json(json!({
                            "project": p,
                            "from": f,
                            "to": t,
                            "path": "replaced.txt",
                            "kind": "modified",
                            "from_file": { "document": doc1, "state": r1 },
                            "to_file": { "document": doc2, "state": r2 },
                            "document_replaced": true,
                            "node_diff": null,
                            "next_cursor": null,
                            "more": false
                        })),
                        "added.txt" => Json(json!({
                            "project": p,
                            "from": f,
                            "to": t,
                            "path": "added.txt",
                            "kind": "added",
                            "from_file": null,
                            "to_file": { "document": doc1, "state": r1 },
                            "document_replaced": false,
                            "node_diff": null,
                            "next_cursor": null,
                            "more": false
                        })),
                        "removed.txt" => Json(json!({
                            "project": p,
                            "from": f,
                            "to": t,
                            "path": "removed.txt",
                            "kind": "removed",
                            "from_file": { "document": doc1, "state": r1 },
                            "to_file": null,
                            "document_replaced": false,
                            "node_diff": null,
                            "next_cursor": null,
                            "more": false
                        })),
                        other => panic!("unexpected path: {other}"),
                    }
                }
            }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();

    let rep_replaced = compare_file(&client, &from, &to, "replaced.txt")
        .await
        .unwrap();
    assert_eq!(rep_replaced.kind, DiffKind::Modified);
    assert!(rep_replaced.document_replaced);
    assert!(format_file_compare_text(&rep_replaced).contains("Document: replaced"));

    let rep_added = compare_file(&client, &from, &to, "added.txt")
        .await
        .unwrap();
    assert_eq!(rep_added.kind, DiffKind::Added);
    assert!(!rep_added.document_replaced);

    let rep_removed = compare_file(&client, &from, &to, "removed.txt")
        .await
        .unwrap();
    assert_eq!(rep_removed.kind, DiffKind::Removed);
    assert!(!rep_removed.document_replaced);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_file_compare_mid_run_401_with_one_allowed_refresh() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();
    let doc = Uuid::new_v4();
    let r1 = Address::try_from("a".repeat(64)).unwrap();
    let r2 = Address::try_from("b".repeat(64)).unwrap();

    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let refresh_calls_clone = refresh_calls.clone();

    let f_served = from.clone();
    let t_served = to.clone();
    let router = Router::new()
        .route(
            "/auth/refresh",
            axum::routing::post(move |Json(body): Json<Value>| {
                let calls = refresh_calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(body["refresh_token"], "1111111111222222222233333333334444444444555555555566666666667777");
                    Json(json!({
                        "access_token": "token_renewed",
                        "refresh_token": "8888888888999999999900000000001111111111222222222233333333334444",
                        "expires_in": 3600
                    }))
                }
            }),
        )
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare/file",
            get(move |headers: HeaderMap, Query(params): Query<HashMap<String, String>>| {
                let f = f_served.clone();
                let t = t_served.clone();
                let r1 = r1.clone();
                let r2 = r2.clone();
                async move {
                    let cursor = params.get("cursor").cloned();
                    let auth = headers.get("authorization").and_then(|h| h.to_str().ok());

                    if cursor.is_none() {
                        assert_eq!(auth, Some("Bearer token_initial"));
                        (
                            StatusCode::OK,
                            Json(json!({
                                "project": project,
                                "from": f,
                                "to": t,
                                "path": "doc.txt",
                                "kind": "modified",
                                "from_file": { "document": doc, "state": r1 },
                                "to_file": { "document": doc, "state": r2 },
                                "document_replaced": false,
                                "node_diff": {
                                    "document_id": doc,
                                    "from_root": r1,
                                    "to_root": r2,
                                    "whole_state_identical": false,
                                    "totals": { "added": 2, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 2 },
                                    "components": {
                                        "comments_changed": false,
                                        "comments_from_count": 0,
                                        "comments_to_count": 0,
                                        "suggestions_changed": false,
                                        "suggestions_from_count": 0,
                                        "suggestions_to_count": 0,
                                        "removed_choices_changed": false,
                                        "removed_choices_from_count": 0,
                                        "removed_choices_to_count": 0
                                    },
                                    "changes": [{ "node_id": "node_01", "kind": "added" }],
                                    "next_cursor": "page2",
                                    "more": true,
                                    "limits": "limits"
                                },
                                "next_cursor": "page2",
                                "more": true
                            })),
                        )
                    } else if cursor.as_deref() == Some("page2") {
                        if auth == Some("Bearer token_initial") {
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({"code": "unauthorized", "details": {"reason": "expired"}})),
                            )
                        } else if auth == Some("Bearer token_renewed") {
                            (
                                StatusCode::OK,
                                Json(json!({
                                    "project": project,
                                    "from": f,
                                    "to": t,
                                    "path": "doc.txt",
                                    "kind": "modified",
                                    "from_file": { "document": doc, "state": r1 },
                                    "to_file": { "document": doc, "state": r2 },
                                    "document_replaced": false,
                                    "node_diff": {
                                        "document_id": doc,
                                        "from_root": r1,
                                        "to_root": r2,
                                        "whole_state_identical": false,
                                        "totals": { "added": 2, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 2 },
                                        "components": {
                                            "comments_changed": false,
                                            "comments_from_count": 0,
                                            "comments_to_count": 0,
                                            "suggestions_changed": false,
                                            "suggestions_from_count": 0,
                                            "suggestions_to_count": 0,
                                            "removed_choices_changed": false,
                                            "removed_choices_from_count": 0,
                                            "removed_choices_to_count": 0
                                        },
                                        "changes": [{ "node_id": "node_02", "kind": "added" }],
                                        "next_cursor": null,
                                        "more": false,
                                        "limits": "limits"
                                    },
                                    "next_cursor": null,
                                    "more": false
                                })),
                            )
                        } else {
                            panic!("unexpected auth header: {:?}", auth);
                        }
                    } else {
                        panic!("unexpected cursor: {:?}", cursor);
                    }
                }
            }),
        );

    let (url, server) = serve(router).await;
    let refresh_file = std::env::temp_dir().join(format!("dynodoc-ref-{}.txt", Uuid::new_v4()));
    let access_file = std::env::temp_dir().join(format!("dynodoc-acc-{}.txt", Uuid::new_v4()));
    crate::private_file::write_private_test(
        &refresh_file,
        b"1111111111222222222233333333334444444444555555555566666666667777\n",
    )
    .unwrap();
    crate::private_file::write_private_test(&access_file, b"token_initial\n").unwrap();

    let client = Client::with_credential(
        remote(url, authority),
        project,
        Credential::Refresh {
            refresh_file: refresh_file.clone(),
            access_file: Some(access_file.clone()),
        },
        Some("token_initial"),
        true,
    )
    .unwrap();

    let report = compare_file(&client, &from, &to, "doc.txt").await.unwrap();
    assert_eq!(report.node_diff.unwrap().changes.len(), 2);
    assert_eq!(refresh_calls.load(Ordering::Relaxed), 1);

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_file(refresh_file);
    let _ = std::fs::remove_file(access_file);
}

#[tokio::test]
async fn remote_file_compare_integrity_checks_and_error_handling() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();
    let doc = Uuid::new_v4();
    let r1 = Address::try_from("a".repeat(64)).unwrap();
    let r2 = Address::try_from("b".repeat(64)).unwrap();

    // 1. Cursor loop
    let f1 = from.clone();
    let t1 = to.clone();
    let r1_c = r1.clone();
    let r2_c = r2.clone();
    let loop_calls = Arc::new(AtomicUsize::new(0));
    let lc = loop_calls.clone();
    let router = Router::new()
        .route("/projects/{id}/history/authority", get(move || async move { Json(epoch_one(authority)) }))
        .route("/projects/{id}/history/compare/file", get(move || {
            let f = f1.clone();
            let t = t1.clone();
            let r1 = r1_c.clone();
            let r2 = r2_c.clone();
            let lc = lc.clone();
            async move {
                let call = lc.fetch_add(1, Ordering::Relaxed);
                let node_id = if call == 0 { "node_01" } else { "node_02" };
                Json(json!({
                    "project": project,
                    "from": f,
                    "to": t,
                    "path": "doc.txt",
                    "kind": "modified",
                    "from_file": { "document": doc, "state": r1 },
                    "to_file": { "document": doc, "state": r2 },
                    "document_replaced": false,
                    "node_diff": {
                        "document_id": doc,
                        "from_root": r1,
                        "to_root": r2,
                        "whole_state_identical": false,
                        "totals": { "added": 2, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 2 },
                        "components": {
                            "comments_changed": false,
                            "comments_from_count": 0,
                            "comments_to_count": 0,
                            "suggestions_changed": false,
                            "suggestions_from_count": 0,
                            "suggestions_to_count": 0,
                            "removed_choices_changed": false,
                            "removed_choices_from_count": 0,
                            "removed_choices_to_count": 0
                        },
                        "changes": [{ "node_id": node_id, "kind": "added" }],
                        "next_cursor": "loop_cursor",
                        "more": true,
                        "limits": "limits"
                    },
                    "next_cursor": "loop_cursor",
                    "more": true
                }))
            }
        }));
    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = compare_file(&client, &from, &to, "doc.txt")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cursor loop"),
        "expected cursor loop error, got: {err}"
    );
    server.abort();
    let _ = server.await;

    // 2. Out of order node IDs
    let f2 = from.clone();
    let t2 = to.clone();
    let r1_c = r1.clone();
    let r2_c = r2.clone();
    let router = Router::new()
        .route("/projects/{id}/history/authority", get(move || async move { Json(epoch_one(authority)) }))
        .route("/projects/{id}/history/compare/file", get(move || {
            let f = f2.clone();
            let t = t2.clone();
            let r1 = r1_c.clone();
            let r2 = r2_c.clone();
            async move {
                Json(json!({
                    "project": project,
                    "from": f,
                    "to": t,
                    "path": "doc.txt",
                    "kind": "modified",
                    "from_file": { "document": doc, "state": r1 },
                    "to_file": { "document": doc, "state": r2 },
                    "document_replaced": false,
                    "node_diff": {
                        "document_id": doc,
                        "from_root": r1,
                        "to_root": r2,
                        "whole_state_identical": false,
                        "totals": { "added": 2, "removed": 0, "modified": 0, "unchanged": 0, "total_changes": 2 },
                        "components": {
                            "comments_changed": false,
                            "comments_from_count": 0,
                            "comments_to_count": 0,
                            "suggestions_changed": false,
                            "suggestions_from_count": 0,
                            "suggestions_to_count": 0,
                            "removed_choices_changed": false,
                            "removed_choices_from_count": 0,
                            "removed_choices_to_count": 0
                        },
                        "changes": [
                            { "node_id": "node_z", "kind": "added" },
                            { "node_id": "node_a", "kind": "added" }
                        ],
                        "next_cursor": null,
                        "more": false,
                        "limits": "limits"
                    },
                    "next_cursor": null,
                    "more": false
                }))
            }
        }));
    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = compare_file(&client, &from, &to, "doc.txt")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("node changes out of order"),
        "expected out of order error, got: {err}"
    );
    server.abort();
    let _ = server.await;

    // 3. Path mismatch
    let f3 = from.clone();
    let t3 = to.clone();
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare/file",
            get(move || {
                let f = f3.clone();
                let t = t3.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "from": f,
                        "to": t,
                        "path": "different.txt",
                        "kind": "added",
                        "from_file": null,
                        "to_file": null,
                        "document_replaced": false,
                        "node_diff": null,
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );
    let (url, server) = serve(router).await;
    let client = Client::new(remote(url, authority), project, "token", true).unwrap();
    let err = compare_file(&client, &from, &to, "doc.txt")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("path mismatch"),
        "expected path mismatch, got: {err}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn remote_file_compare_cli_options_execution() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (repo_path, repo) = repo(project).await;
    let (pin_path, journal) = journal().await;
    let from = Address::try_from("1".repeat(64)).unwrap();
    let to = Address::try_from("2".repeat(64)).unwrap();

    let from_served = from.clone();
    let to_served = to.clone();
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/compare/file",
            get(move || {
                let f = from_served.clone();
                let t = to_served.clone();
                async move {
                    Json(json!({
                        "project": project,
                        "from": f,
                        "to": t,
                        "path": "doc.txt",
                        "kind": "added",
                        "from_file": null,
                        "to_file": null,
                        "document_replaced": false,
                        "node_diff": null,
                        "next_cursor": null,
                        "more": false
                    }))
                }
            }),
        );

    let (url, server) = serve(router).await;
    let remote_file = std::env::temp_dir().join(format!("dynodoc-remote-{}.json", Uuid::new_v4()));
    let token_file = std::env::temp_dir().join(format!("dynodoc-tok-{}.txt", Uuid::new_v4()));
    std::fs::write(
        &remote_file,
        serde_json::to_vec(&remote(url, authority)).unwrap(),
    )
    .unwrap();
    crate::private_file::write_private_test(&token_file, b"token_test\n").unwrap();

    // Run with json: true
    let options_json = Options {
        repository: repo_path.clone(),
        project,
        remote: remote_file.clone(),
        token_file: Some(token_file.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: pin_path.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Compare {
            from: from.clone(),
            to: to.clone(),
            path: Some("doc.txt".into()),
            json: true,
        },
    };
    run(options_json).await.unwrap();

    // Run with json: false (text)
    let options_text = Options {
        repository: repo_path.clone(),
        project,
        remote: remote_file.clone(),
        token_file: Some(token_file.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: pin_path.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::Compare {
            from: from.clone(),
            to: to.clone(),
            path: Some("doc.txt".into()),
            json: false,
        },
    };
    run(options_text).await.unwrap();

    server.abort();
    let _ = server.await;
    repo.close().await;
    journal.close().await;
    remove(repo_path).await;
    remove(pin_path).await;
    let _ = std::fs::remove_file(remote_file);
    let _ = std::fs::remove_file(token_file);
}

#[tokio::test]
async fn export_file_equivalence_with_local_export_and_leaves_local_repo_unmodified() {
    use engine_core::repository::state_export::StateExportEnvelope;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (p1, r1) = repo(project).await;
    let doc = Uuid::new_v4();
    let signed = commit(
        &r1,
        doc,
        &key(7),
        vec![],
        "Equivalence verification content",
    )
    .await;
    let commit_addr = signed.verify().unwrap();

    let local_out = std::env::temp_dir().join(format!("test-local-export-{}.json", Uuid::new_v4()));
    let local_state = r1
        .read_state(DocumentId(doc), &signed.commit.files["Report.docx"].state)
        .await
        .unwrap();
    let local_envelope =
        StateExportEnvelope::new("Report.docx".into(), signed.clone(), local_state);
    local_envelope.write_to_path(&local_out).unwrap();

    let source = r1.clone();
    let signed_commit = signed.clone();
    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(move || {
                let c = signed_commit.clone();
                async move { Json(json!(c)) }
            }),
        )
        .route(
            "/projects/{id}/history/commits/{commit}/objects/{doc}/{address}",
            get(
                move |axum::extract::Path((_id, _commit, _doc, object)): axum::extract::Path<(
                    String,
                    String,
                    String,
                    String,
                )>| {
                    let source = source.clone();
                    async move {
                        let bytes = source
                            .object(&ObjectKey {
                                document: DocumentId(doc),
                                address: Address::try_from(object.clone()).unwrap(),
                            })
                            .await
                            .unwrap()
                            .bytes;
                        Json(json!({"address": object, "bytes": STANDARD.encode(bytes)}))
                    }
                },
            ),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url.clone(), authority), project, "synthetic", true).unwrap();

    // 1. Direct transfer::export_file check
    let remote_out =
        std::env::temp_dir().join(format!("test-remote-export-{}.json", Uuid::new_v4()));
    transfer::export_file(&client, project, &commit_addr, "Report.docx", &remote_out)
        .await
        .unwrap();

    assert!(remote_out.exists());
    #[cfg(unix)]
    {
        let perms = std::fs::metadata(&remote_out).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    let remote_bytes = std::fs::read(&remote_out).unwrap();
    let remote_envelope: StateExportEnvelope = serde_json::from_slice(&remote_bytes).unwrap();
    assert_eq!(local_envelope, remote_envelope);

    // 2. CLI options integration test: verify sync run works and leaves repo/journal untouched
    let (p2, r2) = repo(project).await;
    let (j2, journal2) = journal().await;
    let remote_json_path = std::env::temp_dir().join(format!("remote-{}.json", Uuid::new_v4()));
    std::fs::write(
        &remote_json_path,
        serde_json::to_vec(&remote(url.clone(), authority)).unwrap(),
    )
    .unwrap();
    let token_path = std::env::temp_dir().join(format!("token-{}.txt", Uuid::new_v4()));
    std::fs::write(&token_path, "synthetic").unwrap();

    let cli_out = std::env::temp_dir().join(format!("test-cli-export-{}.json", Uuid::new_v4()));
    let opts = Options {
        repository: p2.clone(),
        project,
        remote: remote_json_path.clone(),
        token_file: Some(token_path.clone()),
        refresh_token_file: None,
        device_key: None,
        journal: j2.clone(),
        branch: "main".into(),
        allow_loopback_http: true,
        accept_authority_break: None,
        action: Action::ExportFile {
            commit: commit_addr.as_str().to_string(),
            path: "Report.docx".into(),
            out: cli_out.clone(),
        },
    };

    run(opts).await.unwrap();
    assert!(cli_out.exists());
    let cli_bytes = std::fs::read(&cli_out).unwrap();
    let cli_envelope: StateExportEnvelope = serde_json::from_slice(&cli_bytes).unwrap();
    assert_eq!(local_envelope, cli_envelope);

    // Verify both local and remote export files via state_export_verify CLI entrypoint
    super::super::state_export_verify(
        local_out.clone(),
        project,
        commit_addr.as_str().to_string(),
        "Report.docx".into(),
    )
    .await
    .unwrap();

    super::super::state_export_verify(
        cli_out.clone(),
        project,
        commit_addr.as_str().to_string(),
        "Report.docx".into(),
    )
    .await
    .unwrap();

    // Assert r2 and journal2 remain completely empty (no commits, no objects, no pins)
    assert!(r2.commit(&commit_addr).await.is_err());
    assert!(r2.head("main").await.unwrap().is_none());
    assert!(journal2
        .pin(&Scope {
            authority,
            project,
            branch: "main".into(),
        })
        .await
        .unwrap()
        .is_none());

    server.abort();
    let _ = server.await;
    r1.close().await;
    r2.close().await;
    journal2.close().await;
    let _ = std::fs::remove_file(&local_out);
    let _ = std::fs::remove_file(&remote_out);
    let _ = std::fs::remove_file(&cli_out);
    let _ = std::fs::remove_file(&remote_json_path);
    let _ = std::fs::remove_file(&token_path);
    remove(p1).await;
    remove(p2).await;
    remove(j2).await;
}

#[tokio::test]
async fn export_file_malicious_object_or_address_fails_and_cleans_up() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (p1, r1) = repo(project).await;
    let doc = Uuid::new_v4();
    let signed = commit(&r1, doc, &key(7), vec![], "Malicious response test").await;
    let commit_addr = signed.verify().unwrap();

    let signed_commit = signed.clone();
    // Mode 1: address mismatch in object response
    // Mode 2: hash mismatch (corrupt bytes) in object response
    use std::sync::atomic::{AtomicU8, Ordering};
    let mode = Arc::new(AtomicU8::new(1));
    let mode_clone = mode.clone();

    let router = Router::new()
        .route(
            "/projects/{id}/history/authority",
            get(move || async move { Json(epoch_one(authority)) }),
        )
        .route(
            "/projects/{id}/history/commits/{address}",
            get(move || {
                let c = signed_commit.clone();
                async move { Json(json!(c)) }
            }),
        )
        .route(
            "/projects/{id}/history/commits/{commit}/objects/{doc}/{address}",
            get(
                move |axum::extract::Path((_id, _commit, _doc, object)): axum::extract::Path<(
                    String,
                    String,
                    String,
                    String,
                )>| {
                    let m = mode_clone.load(Ordering::Relaxed);
                    async move {
                        if m == 1 {
                            // Mismatched address in packet
                            let fake_address = "f".repeat(64);
                            Json(json!({"address": fake_address, "bytes": STANDARD.encode(b"some content")}))
                        } else {
                            // Corrupt bytes (hash mismatch)
                            Json(json!({"address": object, "bytes": STANDARD.encode(b"completely corrupted bytes")}))
                        }
                    }
                },
            ),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url.clone(), authority), project, "synthetic", true).unwrap();

    // Mode 1: address mismatch
    mode.store(1, Ordering::Relaxed);
    let out1 = std::env::temp_dir().join(format!("test-out-malicious-1-{}.json", Uuid::new_v4()));
    let err1 = transfer::export_file(&client, project, &commit_addr, "Report.docx", &out1)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err1.contains("object response address mismatch"),
        "expected address mismatch, got: {err1}"
    );
    assert!(!out1.exists(), "output file should not exist after failure");

    // Mode 2: corrupt hash
    mode.store(2, Ordering::Relaxed);
    let out2 = std::env::temp_dir().join(format!("test-out-malicious-2-{}.json", Uuid::new_v4()));
    let _err2 = transfer::export_file(&client, project, &commit_addr, "Report.docx", &out2)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        !out2.exists(),
        "output file should not exist after corruption failure"
    );

    server.abort();
    let _ = server.await;
    r1.close().await;
    remove(p1).await;
}

#[tokio::test]
async fn export_file_cross_project_redirect_and_scope_denial_fail() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (p1, r1) = repo(project).await;
    let doc = Uuid::new_v4();
    let _signed = commit(&r1, doc, &key(7), vec![], "Cross-project test").await;

    // 1. Cross-project commit response: commit has different project
    let other_project = Uuid::new_v4();
    let (p_other, r_other) = repo(other_project).await;
    let signed_other = commit(&r_other, doc, &key(7), vec![], "Other project").await;
    let commit_other_addr = signed_other.verify().unwrap();

    let router = Router::new()
        .route(
            "/projects/{id}/history/commits/{address}",
            get(move || {
                let c = signed_other.clone();
                async move { Json(json!(c)) }
            }),
        )
        .route(
            "/projects/{id}/redirect",
            get(|| async { axum::response::Redirect::temporary("/other-project") }),
        )
        .route(
            "/projects/{id}/denied",
            get(|| async { (axum::http::StatusCode::FORBIDDEN, "scope denial") }),
        );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url.clone(), authority), project, "synthetic", true).unwrap();

    // Cross-project mismatch
    let out = std::env::temp_dir().join(format!("test-out-crossproj-{}.json", Uuid::new_v4()));
    let err = transfer::export_file(&client, project, &commit_other_addr, "Report.docx", &out)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("project mismatch") || err.contains("commit does not match requested project"),
        "got: {err}"
    );
    assert!(!out.exists());

    // Redirect rejected
    let redirect_client =
        Client::new(remote(url.clone(), authority), project, "synthetic", true).unwrap();
    let err_red = redirect_client
        .get::<Value>("redirect", &[], 1024)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err_red.contains("307"),
        "expected 307 redirect error, got: {err_red}"
    );

    // Scope denial (403)
    let err_denied = redirect_client
        .get::<Value>("denied", &[], 1024)
        .await
        .unwrap_err()
        .to_string();
    assert!(err_denied.contains("403"));

    server.abort();
    let _ = server.await;
    r1.close().await;
    r_other.close().await;
    remove(p1).await;
    remove(p_other).await;
}

#[tokio::test]
async fn export_file_missing_path_absent_commit_and_overwrite_refusal_fail() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (p1, r1) = repo(project).await;
    let doc = Uuid::new_v4();
    let signed = commit(&r1, doc, &key(7), vec![], "Missing path test").await;
    let commit_addr = signed.verify().unwrap();

    let signed_commit = signed.clone();
    let router = Router::new().route(
        "/projects/{id}/history/commits/{address}",
        get(
            move |axum::extract::Path((_id, address)): axum::extract::Path<(String, String)>| {
                let signed = signed_commit.clone();
                async move {
                    if address == signed.verify().unwrap().as_str() {
                        (axum::http::StatusCode::OK, Json(json!(signed)))
                    } else {
                        (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(json!({"error": "not found"})),
                        )
                    }
                }
            },
        ),
    );

    let (url, server) = serve(router).await;
    let client = Client::new(remote(url.clone(), authority), project, "synthetic", true).unwrap();

    // 1. Missing path in commit
    let out1 = std::env::temp_dir().join(format!("test-out-missing-path-{}.json", Uuid::new_v4()));
    let err1 = transfer::export_file(&client, project, &commit_addr, "NonExistent.docx", &out1)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err1.contains("path 'NonExistent.docx' not found"),
        "got: {err1}"
    );
    assert!(!out1.exists());

    // 2. Absent commit (404)
    let absent_commit = Address::try_from("0".repeat(64)).unwrap();
    let out2 = std::env::temp_dir().join(format!("test-out-absent-commit-{}.json", Uuid::new_v4()));
    let err2 = transfer::export_file(&client, project, &absent_commit, "Report.docx", &out2)
        .await
        .unwrap_err()
        .to_string();
    assert!(err2.contains("not found"), "got: {err2}");
    assert!(!out2.exists());

    // 3. Overwrite refusal
    let existing_out = std::env::temp_dir().join(format!("test-existing-{}.json", Uuid::new_v4()));
    std::fs::write(&existing_out, b"pre-existing content").unwrap();
    let err3 = transfer::export_file(&client, project, &commit_addr, "Report.docx", &existing_out)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err3.contains("already exists; refusing overwrite"),
        "got: {err3}"
    );
    assert_eq!(
        std::fs::read(&existing_out).unwrap(),
        b"pre-existing content"
    );

    server.abort();
    let _ = server.await;
    r1.close().await;
    let _ = std::fs::remove_file(&existing_out);
    remove(p1).await;
}

#[tokio::test]
async fn export_file_expired_access_and_oversized_graph_fail() {
    let project = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let (p1, r1) = repo(project).await;
    let doc = Uuid::new_v4();
    let signed = commit(&r1, doc, &key(7), vec![], "Expired access and limits test").await;
    let commit_addr = signed.verify().unwrap();

    // Router simulating 401 Unauthorized
    let router_401 = Router::new().route(
        "/projects/{id}/history/commits/{address}",
        get(|| async { (axum::http::StatusCode::UNAUTHORIZED, "expired token") }),
    );

    let (url_401, server_401) = serve(router_401).await;
    let client_401 = Client::new(remote(url_401, authority), project, "synthetic", true).unwrap();
    let out_401 = std::env::temp_dir().join(format!("test-out-401-{}.json", Uuid::new_v4()));
    let err_401 =
        transfer::export_file(&client_401, project, &commit_addr, "Report.docx", &out_401)
            .await
            .unwrap_err()
            .to_string();
    assert!(
        err_401.contains("401") || err_401.contains("expired token"),
        "got: {err_401}"
    );
    assert!(!out_401.exists());
    server_401.abort();
    let _ = server_401.await;

    // Router returning oversized payload
    let signed_commit = signed.clone();
    let router_large = Router::new()
        .route(
            "/projects/{id}/history/commits/{address}",
            get(move || {
                let c = signed_commit.clone();
                async move { Json(json!(c)) }
            }),
        )
        .route(
            "/projects/{id}/history/commits/{commit}/objects/{doc}/{address}",
            get(|| async {
                Json(json!({"address": "0".repeat(64), "bytes": STANDARD.encode(vec![0u8; 2_000_000])}))
            }),
        );

    let (url_large, server_large) = serve(router_large).await;
    let client_large =
        Client::new(remote(url_large, authority), project, "synthetic", true).unwrap();
    let out_large = std::env::temp_dir().join(format!("test-out-large-{}.json", Uuid::new_v4()));
    let _err_large = transfer::export_file(
        &client_large,
        project,
        &commit_addr,
        "Report.docx",
        &out_large,
    )
    .await
    .unwrap_err();
    assert!(!out_large.exists());

    server_large.abort();
    let _ = server_large.await;
    r1.close().await;
    remove(p1).await;
}
