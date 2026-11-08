//! Horizon apply, verify, archive and rehydration on real SQLite repositories,
//! including the trust boundaries: signatures over horizon records, refusal of any
//! release the policy does not select, and crash safety at every stage.

use super::horizon_apply::Stage;
use super::tests::{cleanup, path, state};
use super::*;
use crate::repository::{
    horizon::{
        self, archive,
        plan::PlanOptions,
        policy::{LoadOptions, Policy},
        Envelope, Error as HorizonError, Invariant, Role, Signature,
    },
    tests::signed,
    FileEntry,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn policy(keep: u32, signatures: u32, archive: bool) -> Policy {
    let archive = if archive {
        r#","archive":{"required":true,"destination":"file:///archives/{project}/{sequence}.dynarc"}"#
    } else {
        ""
    };
    Policy::load(
        format!(
            r#"{{"version":1,"id":"keep-{keep}","tier":"history","window":{{"keep_last_commits":{keep}}},"protect":{{"branch_heads":true}},"signatures":{{"required":{signatures}}}{archive}}}"#
        )
        .as_bytes(),
        LoadOptions::default(),
    )
    .unwrap()
}

struct Fixture {
    repo: LocalRepository,
    file: std::path::PathBuf,
    report: DocumentId,
    commits: Vec<Address>,
    /// Report state of each commit.
    roots: Vec<Address>,
}

/// c0..c7 on `main`, each with its own Report state and a shared Notes state.
async fn linear() -> Fixture {
    let file = path();
    let repo = LocalRepository::open(&file, uuid::Uuid::new_v4())
        .await
        .unwrap();
    let report = DocumentId(uuid::Uuid::new_v4());
    let notes = DocumentId(uuid::Uuid::new_v4());
    let (notes_root, _) = repo.write_state(notes, &state("notes")).await.unwrap();
    let mut commits: Vec<Address> = Vec::new();
    let mut roots = Vec::new();
    for i in 0..8 {
        let (root, _) = repo
            .write_state(report, &state(&format!("report {i}")))
            .await
            .unwrap();
        let files = BTreeMap::from([
            (
                "Report.docx".to_string(),
                FileEntry {
                    document: report,
                    state: root.clone(),
                },
            ),
            (
                "Notes.docx".to_string(),
                FileEntry {
                    document: notes,
                    state: notes_root.clone(),
                },
            ),
        ]);
        let parents = commits.last().cloned().into_iter().collect();
        let address = repo
            .import_commit(&signed(repo.project(), parents, files, &format!("c{i}")))
            .await
            .unwrap();
        commits.push(address);
        roots.push(root);
    }
    repo.compare_and_swap("main", None, &commits[7])
        .await
        .unwrap();
    Fixture {
        repo,
        file,
        report,
        commits,
        roots,
    }
}

async fn draft(
    f: &Fixture,
    policy: &Policy,
    archive: Option<&std::path::Path>,
) -> (horizon::HorizonRecord, String) {
    let plan = f
        .repo
        .horizon_plan(policy, &PlanOptions::default())
        .await
        .unwrap();
    let record = f
        .repo
        .horizon_draft(
            policy,
            &PlanOptions::default(),
            &plan.plan_hash,
            1_791_000_000_000,
            archive,
        )
        .await
        .unwrap();
    (record, plan.plan_hash)
}

fn signed_by(record: &horizon::HorizonRecord, keys: &[(Role, &Ed25519KeyPair)]) -> Envelope {
    let signatures = keys
        .iter()
        .map(|(role, key)| horizon::sign(record, *role, key).unwrap())
        .collect();
    Envelope::assemble(record.clone(), signatures).unwrap()
}

/// `document, address, bytes, codec, size` of one stored object row.
type ObjectRow = (String, String, Vec<u8>, i64, Option<i64>);

/// Every commit body and every object's logical bytes, in key order.
async fn dump(repo: &LocalRepository) -> (Vec<(String, Vec<u8>)>, Vec<(String, String, Vec<u8>)>) {
    let mut connection = repo.pool.acquire().await.unwrap();
    let commits = sqlx::query_as("select address,body from commits order by address")
        .fetch_all(&mut *connection)
        .await
        .unwrap();
    let rows: Vec<ObjectRow> = sqlx::query_as(
        "select document,address,bytes,codec,size from objects order by document,address",
    )
    .fetch_all(&mut *connection)
    .await
    .unwrap();
    let objects = rows
        .into_iter()
        .map(|(d, a, b, c, s)| (d, a, pack::unpack(c, b, s).unwrap()))
        .collect();
    (commits, objects)
}

async fn schema(repo: &LocalRepository) -> i64 {
    sqlx::query_scalar("select version from local_meta where singleton=1")
        .fetch_one(&repo.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn apply_releases_exactly_the_plan_keeps_topology_and_verifies() {
    let f = linear().await;
    let policy = policy(3, 1, false);
    let before_bases = f
        .repo
        .merge_bases(&f.commits[7], &f.commits[6])
        .await
        .unwrap();
    let (record, hash) = draft(&f, &policy, None).await;
    assert_eq!(record.counts.commits_released, 5);
    let envelope = signed_by(&record, &[(Role::Owner, &key(1))]);
    let report = f
        .repo
        .horizon_apply(&envelope, &policy, &PlanOptions::default(), &hash, None)
        .await
        .unwrap();
    assert!(report.applied);
    assert_eq!(report.released.commits, 5);
    assert_eq!(report.released.objects, record.counts.objects_released);
    assert_eq!(schema(&f.repo).await, 4);
    // Released bodies answer with their skeleton; retained ones are unchanged.
    match f.repo.commit(&f.commits[0]).await {
        Err(Error::HistoryPruned {
            horizon, height, ..
        }) => assert_eq!((horizon, height), (1, 0)),
        other => panic!("expected HistoryPruned, got {other:?}"),
    }
    f.repo.commit(&f.commits[5]).await.unwrap();
    // The first Report state is released; the shared Notes state is kept.
    match f.repo.read_state(f.report, &f.roots[0]).await {
        Err(Error::ContentPruned { horizon, .. }) => assert_eq!(horizon, 1),
        other => panic!("expected ContentPruned, got {other:?}"),
    }
    // Ancestry walks on through the skeleton.
    assert_eq!(
        f.repo
            .merge_bases(&f.commits[7], &f.commits[6])
            .await
            .unwrap(),
        before_bases
    );
    assert_eq!(
        f.repo
            .merge_bases(&f.commits[7], &f.commits[1])
            .await
            .unwrap(),
        vec![f.commits[1].clone()]
    );
    let verified = f.repo.horizon_verify().await.unwrap();
    assert_eq!((verified.horizons, verified.skeleton_entries), (1, 5));
    // Counters equal a recount (H9 inside verify), and gc still plans.
    f.repo.gc_plan(GcPlanOptions::default()).await.unwrap();
    // A replay of the same envelope changes nothing.
    let again = f
        .repo
        .horizon_apply(&envelope, &policy, &PlanOptions::default(), &hash, None)
        .await
        .unwrap();
    assert!(again.already_applied && !again.applied);
    // New work on top of the pruned history still imports and verifies.
    let head = f.repo.commit(&f.commits[7]).await.unwrap();
    let next = f
        .repo
        .import_commit(&signed(
            f.repo.project(),
            vec![f.commits[7].clone()],
            head.commit.files.clone(),
            "c8",
        ))
        .await
        .unwrap();
    f.repo
        .compare_and_swap("main", f.repo.head("main").await.unwrap().as_ref(), &next)
        .await
        .unwrap();
    f.repo.horizon_verify().await.unwrap();
    // A second horizon chains onto the first.
    let (second, hash) = draft(&f, &policy, None).await;
    assert_eq!((second.sequence, second.counts.commits_released), (2, 1));
    assert_eq!(second.previous, Some(envelope.horizon.address().unwrap()));
    let envelope = signed_by(&second, &[(Role::Device, &key(2))]);
    f.repo
        .horizon_apply(&envelope, &policy, &PlanOptions::default(), &hash, None)
        .await
        .unwrap();
    let shown = f.repo.horizons().await.unwrap();
    assert_eq!(shown.len(), 2);
    assert_eq!(f.repo.horizon_verify().await.unwrap().skeleton_entries, 6);
    cleanup(f.repo, &f.file).await;
}

#[tokio::test]
async fn signatures_over_the_record_are_required_and_bound_to_its_domain() {
    let f = linear().await;
    let one = policy(3, 1, false);
    let (record, hash) = draft(&f, &one, None).await;
    let apply = |envelope: Envelope, policy: Policy| {
        let repo = f.repo.clone();
        let hash = hash.clone();
        async move {
            repo.horizon_apply(&envelope, &policy, &PlanOptions::default(), &hash, None)
                .await
        }
    };
    let h2 = |result: Result<ApplyReport, HorizonError>| {
        assert!(
            matches!(result, Err(HorizonError::Violated(Invariant::H2, _))),
            "{result:?}"
        );
    };
    // No signature at all.
    h2(apply(
        Envelope {
            horizon: record.clone(),
            signatures: vec![],
        },
        one.clone(),
    )
    .await);
    // A signature over the bare address, and one in the commit signature domain.
    let address = record.address().unwrap();
    let signer = key(1);
    let public = crate::repository::hex(signer.public_key().as_ref());
    for message in [
        horizon::raw(&address).to_vec(),
        [
            b"dynodoc.project-commit-signature\0v1\0".as_slice(),
            &horizon::raw(&address),
        ]
        .concat(),
    ] {
        h2(apply(
            Envelope {
                horizon: record.clone(),
                signatures: vec![Signature {
                    role: Role::Owner,
                    key: public.clone(),
                    signature: crate::repository::hex(signer.sign(&message).as_ref()),
                }],
            },
            one.clone(),
        )
        .await);
    }
    // An authority role is not legal for a local horizon.
    h2(apply(
        signed_by(&record, &[(Role::Authority, &key(1))]),
        one.clone(),
    )
    .await);
    // Two distinct keys required, one given.
    let two = policy(3, 2, false);
    let (record2, hash2) = draft(&f, &two, None).await;
    let result = f
        .repo
        .horizon_apply(
            &signed_by(&record2, &[(Role::Owner, &key(1))]),
            &two,
            &PlanOptions::default(),
            &hash2,
            None,
        )
        .await;
    h2(result);
    // Nothing changed: schema 3, every commit present.
    assert_eq!(schema(&f.repo).await, 3);
    for commit in &f.commits {
        f.repo.commit(commit).await.unwrap();
    }
    // Owner and device together satisfy two.
    f.repo
        .horizon_apply(
            &signed_by(&record2, &[(Role::Owner, &key(1)), (Role::Device, &key(2))]),
            &two,
            &PlanOptions::default(),
            &hash2,
            None,
        )
        .await
        .unwrap();
    assert_eq!(f.repo.horizon_verify().await.unwrap().horizons, 1);
    cleanup(f.repo, &f.file).await;
}

#[tokio::test]
async fn a_release_the_policy_does_not_select_is_refused() {
    let f = linear().await;
    let lenient = policy(5, 1, false);
    let aggressive = policy(2, 1, false);
    // A record drafted under an aggressive policy, presented with the lenient one.
    let (record, hash) = draft(&f, &aggressive, None).await;
    let envelope = signed_by(&record, &[(Role::Owner, &key(1))]);
    let refused = f
        .repo
        .horizon_apply(&envelope, &lenient, &PlanOptions::default(), &hash, None)
        .await;
    assert!(matches!(refused, Err(HorizonError::Plan(_))), "{refused:?}");
    // The right policy but a record whose counts and roots claim more than the plan.
    let mut forged = record.clone();
    forged.counts.commits_released += 1;
    let refused = f
        .repo
        .horizon_apply(
            &signed_by(&forged, &[(Role::Owner, &key(1))]),
            &aggressive,
            &PlanOptions::default(),
            &hash,
            None,
        )
        .await;
    assert!(matches!(refused, Err(HorizonError::Plan(_))), "{refused:?}");
    // A branch moved after review: the plan hash is stale.
    let head = f.repo.commit(&f.commits[7]).await.unwrap();
    let next = f
        .repo
        .import_commit(&signed(
            f.repo.project(),
            vec![f.commits[7].clone()],
            head.commit.files,
            "late",
        ))
        .await
        .unwrap();
    f.repo
        .compare_and_swap("main", f.repo.head("main").await.unwrap().as_ref(), &next)
        .await
        .unwrap();
    let refused = f
        .repo
        .horizon_apply(&envelope, &aggressive, &PlanOptions::default(), &hash, None)
        .await;
    assert!(matches!(refused, Err(HorizonError::Plan(_))), "{refused:?}");
    assert_eq!(schema(&f.repo).await, 3);
    cleanup(f.repo, &f.file).await;
}

#[tokio::test]
async fn a_crash_at_any_stage_leaves_the_repository_as_it_was() {
    let f = linear().await;
    let policy = policy(3, 1, false);
    let (record, hash) = draft(&f, &policy, None).await;
    let envelope = signed_by(&record, &[(Role::Owner, &key(1))]);
    let before = dump(&f.repo).await;
    for stage in [
        Stage::Locked,
        Stage::Upgraded,
        Stage::Rows,
        Stage::Commits,
        Stage::Objects,
        Stage::Accounted,
        Stage::Verified,
    ] {
        let result = f
            .repo
            .horizon_apply_with(
                &envelope,
                &policy,
                &PlanOptions::default(),
                &hash,
                None,
                None,
                &mut |at| {
                    if at == stage {
                        Err(HorizonError::Repository("injected crash".into()))
                    } else {
                        Ok(())
                    }
                },
            )
            .await;
        assert!(result.is_err(), "{stage:?}");
        assert_eq!(schema(&f.repo).await, 3, "{stage:?}");
        assert_eq!(dump(&f.repo).await, before, "{stage:?}");
        f.repo.horizon_verify().await.unwrap();
    }
    f.repo
        .horizon_apply(&envelope, &policy, &PlanOptions::default(), &hash, None)
        .await
        .unwrap();
    cleanup(f.repo, &f.file).await;
}

#[tokio::test]
async fn archive_verifies_offline_and_rehydration_restores_identical_history() {
    let f = linear().await;
    let policy = policy(3, 1, true);
    let dir =
        std::env::temp_dir().join(format!("dynodoc-horizon-archive-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("1.dynarc");
    // The policy requires an archive.
    let plan = f
        .repo
        .horizon_plan(&policy, &PlanOptions::default())
        .await
        .unwrap();
    assert!(f
        .repo
        .horizon_draft(&policy, &PlanOptions::default(), &plan.plan_hash, 1, None)
        .await
        .is_err());
    let (record, hash) = draft(&f, &policy, Some(&file)).await;
    let summary = record.archive.clone().unwrap();
    assert_eq!(summary.commits, 5);
    let envelope = signed_by(&record, &[(Role::Owner, &key(1))]);
    // Offline: the archive alone and its signed record.
    assert_eq!(archive::verify(&file, &envelope).unwrap(), summary);
    // A flipped byte is refused offline and by the applier.
    let tampered = dir.join("tampered.dynarc");
    let mut bytes = std::fs::read(&file).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    std::fs::write(&tampered, &bytes).unwrap();
    assert!(archive::verify(&tampered, &envelope).is_err());
    assert!(f
        .repo
        .horizon_apply(
            &envelope,
            &policy,
            &PlanOptions::default(),
            &hash,
            Some(&tampered)
        )
        .await
        .is_err());
    let before = dump(&f.repo).await;
    f.repo
        .horizon_apply(
            &envelope,
            &policy,
            &PlanOptions::default(),
            &hash,
            Some(&file),
        )
        .await
        .unwrap();
    assert_ne!(dump(&f.repo).await, before);
    let report = f.repo.horizon_rehydrate(1, &file).await.unwrap();
    assert_eq!(report.commits, 5);
    assert_eq!(dump(&f.repo).await, before);
    let verified = f.repo.horizon_verify().await.unwrap();
    assert_eq!(
        (
            verified.horizons,
            verified.rehydrated,
            verified.skeleton_entries
        ),
        (1, 1, 0)
    );
    f.repo.commit(&f.commits[0]).await.unwrap();
    assert!(f.repo.horizon_rehydrate(1, &file).await.is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    cleanup(f.repo, &f.file).await;
}

#[tokio::test]
async fn truncation_outside_any_horizon_fails_verification() {
    let f = linear().await;
    let policy = policy(3, 1, false);
    let (record, hash) = draft(&f, &policy, None).await;
    f.repo
        .horizon_apply(
            &signed_by(&record, &[(Role::Owner, &key(1))]),
            &policy,
            &PlanOptions::default(),
            &hash,
            None,
        )
        .await
        .unwrap();
    // Someone with file access deletes a retained body (c5) behind the engine's back.
    let mut connection = f.repo.pool.acquire().await.unwrap();
    sqlx::raw_sql(&format!(
        "drop trigger commits_no_delete; delete from commits where address='{}';",
        f.commits[5].as_str()
    ))
    .execute(&mut *connection)
    .await
    .unwrap();
    drop(connection);
    let refused = f.repo.horizon_verify().await;
    assert!(
        matches!(
            refused,
            Err(HorizonError::Violated(Invariant::H3 | Invariant::H9, _))
        ),
        "{refused:?}"
    );
    cleanup(f.repo, &f.file).await;
}

#[tokio::test]
async fn a_shallow_replica_imports_retained_history_on_a_verified_remote_skeleton() {
    let source = linear().await;
    let policy = policy(3, 1, false);
    let (record, hash) = draft(&source, &policy, None).await;
    let envelope = signed_by(&record, &[(Role::Owner, &key(1))]);
    let plan = source
        .repo
        .horizon_plan(&policy, &PlanOptions::default())
        .await
        .unwrap();
    source
        .repo
        .horizon_apply(&envelope, &policy, &PlanOptions::default(), &hash, None)
        .await
        .unwrap();
    let file = path();
    let replica = LocalRepository::open(&file, source.repo.project())
        .await
        .unwrap();
    // A tampered skeleton (one height changed) does not reproduce the signed root.
    let mut forged = plan.sets.skeleton.clone();
    forged[0].height += 1;
    assert!(replica
        .import_remote_skeleton(&envelope, &forged)
        .await
        .is_err());
    let imported = replica
        .import_remote_skeleton(&envelope, &plan.sets.skeleton)
        .await
        .unwrap();
    assert_eq!(imported.stored, 5);
    // Copy every object, then the retained commits in order.
    let mut after = None;
    loop {
        let page = source.repo.inventory(after.as_ref(), 64).await.unwrap();
        let Some(last) = page.last().cloned() else {
            break;
        };
        let mut packets = Vec::new();
        for key in &page {
            packets.push(source.repo.object(key).await.unwrap());
        }
        replica.import_objects(&packets).await.unwrap();
        after = Some(last);
    }
    for commit in &source.commits[5..] {
        replica
            .import_commit(&source.repo.commit(commit).await.unwrap())
            .await
            .unwrap();
    }
    replica
        .compare_and_swap("main", None, &source.commits[7])
        .await
        .unwrap();
    assert_eq!(
        replica
            .merge_bases(&source.commits[7], &source.commits[2])
            .await
            .unwrap(),
        vec![source.commits[2].clone()]
    );
    let verified = replica.horizon_verify().await.unwrap();
    assert_eq!(verified.remote_skeleton_entries, 5);
    cleanup(replica, &file).await;
    cleanup(source.repo, &source.file).await;
}
