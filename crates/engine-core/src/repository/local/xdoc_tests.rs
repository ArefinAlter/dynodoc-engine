//! The worked example of the cross-document design (6.6) end to end in a local
//! repository: a split with an edit that follows the move, a rename with an edit
//! that follows the rename, the signed v4 record, import checks, `verify-merge`
//! and lineage; and the never-automatic cases and forged records.

use super::tests::{cleanup, path};
use super::*;
use crate::{
    materializer::MaterializedNode,
    merge_policy,
    repository::{
        plan_v2::plan_v2,
        project::{self, Class, Parent, ResolutionFile},
        relocation::{self, Destination, Kind, Source, Spec},
        Commit, FileEntry, SignedCommit,
    },
};
use engine_shared::NodeId;
use ring::signature::Ed25519KeyPair;
use serde_json::json;

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

fn n(id: &str) -> NodeId {
    NodeId(id.into())
}

fn node(id: &str, parent: Option<&str>, kind: &str, label: &str) -> MaterializedNode {
    MaterializedNode {
        id: n(id),
        parent_id: parent.map(n),
        node_type: kind.into(),
        pos: format!("p{id}"),
        current_fields: json!({ "label": label }),
        var_name: None,
        deleted: false,
    }
}

/// `Proposal.docx`: sections S1 to S3, S2 holds items n1 to n3.
fn proposal() -> DocumentState {
    let mut s = DocumentState::default();
    for (id, parent, kind) in [
        ("R", None, "form"),
        ("S1", Some("R"), "section"),
        ("S2", Some("R"), "section"),
        ("S3", Some("R"), "section"),
        ("n1", Some("S2"), "item"),
        ("n2", Some("S2"), "item"),
        ("n3", Some("S2"), "item"),
    ] {
        s.nodes.insert(n(id), node(id, parent, kind, id));
    }
    s
}

fn budget(cell: &str) -> DocumentState {
    let mut s = DocumentState::default();
    s.nodes.insert(n("B"), node("B", None, "form", "Budget"));
    let mut row = node("C4", Some("B"), "item", "row");
    row.current_fields["cell_3"] = json!(cell);
    s.nodes.insert(n("C4"), row);
    s
}

struct World {
    repo: LocalRepository,
    file: std::path::PathBuf,
    p: DocumentId,
    a: DocumentId,
    base: Address,
}

async fn commit(repo: &LocalRepository, mut c: Commit) -> Address {
    c.project = repo.project();
    repo.import_commit(&SignedCommit::sign(c, &key()).unwrap())
        .await
        .unwrap()
}

fn plain(parents: Vec<Address>, files: BTreeMap<String, FileEntry>, message: &str) -> Commit {
    Commit {
        version: 1,
        project: uuid::Uuid::nil(),
        parents,
        files,
        author_key: String::new(),
        authored_at_ms: 1_700_000_000_000,
        message: message.into(),
        recovery: None,
        same_file_resolutions: Vec::new(),
        sealed: None,
        project_resolutions: Vec::new(),
        relocations: Vec::new(),
        merge_policy: None,
    }
}

async fn world() -> World {
    let file = path();
    let repo = LocalRepository::open(&file, uuid::Uuid::new_v4())
        .await
        .unwrap();
    let (p, x, a) = (
        DocumentId(uuid::Uuid::from_u128(0xa1)),
        DocumentId(uuid::Uuid::from_u128(0xa3)),
        DocumentId(uuid::Uuid::from_u128(0xa2)),
    );
    let (ps, _) = repo.write_state(p, &proposal()).await.unwrap();
    let (xs, _) = repo.write_state(x, &budget("10")).await.unwrap();
    let files = BTreeMap::from([
        (
            "Proposal.docx".to_string(),
            FileEntry {
                document: p,
                state: ps,
            },
        ),
        (
            "Budget.xlsx".to_string(),
            FileEntry {
                document: x,
                state: xs,
            },
        ),
    ]);
    let base = commit(&repo, plain(vec![], files, "base")).await;
    World {
        repo,
        file,
        p,
        a,
        base,
    }
}

fn split_spec(w: &World) -> Spec {
    Spec {
        kind: Kind::Split,
        from: Source {
            document: w.p,
            roots: vec![n("S2")],
        },
        to: Destination {
            document: w.a,
            parent: n("R"),
            position: "a3".into(),
        },
    }
}

/// Left: split S2 into Appendix.docx, then rename Budget.xlsx.
async fn left(w: &World) -> Address {
    let paths = BTreeMap::from([(w.a.0, "Appendix.docx".to_string())]);
    let split = w
        .repo
        .relocate(
            &w.base,
            &[split_spec(w)],
            &paths,
            1_700_000_000_001,
            "split".into(),
        )
        .await
        .unwrap();
    assert_eq!(split.version, 4);
    let split = commit(&w.repo, split).await;
    let mut files = w.repo.commit(&split).await.unwrap().commit.files;
    let entry = files.remove("Budget.xlsx").unwrap();
    files.insert("Finance/Budget.xlsx".into(), entry);
    commit(&w.repo, plain(vec![split], files, "rename")).await
}

/// Right: edit n2, add n9 under S2, edit the budget cell (or other edits).
async fn right(w: &World, edit: impl Fn(&mut DocumentState)) -> Address {
    let base = w.repo.commit(&w.base).await.unwrap().commit;
    let mut files = base.files.clone();
    let mut p = proposal();
    edit(&mut p);
    let (ps, _) = w.repo.write_state(w.p, &p).await.unwrap();
    files.get_mut("Proposal.docx").unwrap().state = ps;
    let x = files["Budget.xlsx"].document;
    let (xs, _) = w.repo.write_state(x, &budget("12")).await.unwrap();
    files.get_mut("Budget.xlsx").unwrap().state = xs;
    commit(&w.repo, plain(vec![w.base.clone()], files, "right")).await
}

fn edit_moved(p: &mut DocumentState) {
    p.nodes.get_mut(&n("n2")).unwrap().current_fields["label"] = json!("n2 edited");
    p.nodes
        .insert(n("n9"), node("n9", Some("S2"), "item", "n9 new"));
}

#[tokio::test]
async fn split_rename_and_concurrent_edits_merge_follow_and_verify() {
    let w = world().await;
    let (l, r) = (left(&w).await, right(&w, edit_moved).await);
    // P0: the path planner alone cannot merge this; plan_v2 sees the rename.
    let (bc, lc, rc) = (
        w.repo.commit(&w.base).await.unwrap().commit,
        w.repo.commit(&l).await.unwrap().commit,
        w.repo.commit(&r).await.unwrap().commit,
    );
    let old = crate::repository::compare::plan(&bc, &lc, &rc).unwrap();
    assert!(old.conflicts.iter().any(|c| c.path == "Budget.xlsx"));
    let v2 = plan_v2(&bc, &lc, &rc).unwrap();
    assert_eq!(v2.renames.len(), 1);

    let policy = merge_policy::default::policy();
    let none = ResolutionFile::default();
    let merge = w
        .repo
        .prepare_project_merge(&l, &r, policy, &none, 1_700_000_000_010, "merge".into())
        .await
        .unwrap();
    assert!(
        merge.report.conflicts.is_empty(),
        "{:?}",
        merge.report.conflicts
    );
    let c = merge.commit.unwrap();
    assert_eq!(c.version, 4);
    let strategies: Vec<&str> = c
        .project_resolutions
        .iter()
        .map(|r| r.strategy.as_str())
        .collect();
    assert_eq!(
        strategies,
        [project::EDIT_FOLLOWS_MOVE, project::RENAME_FOLLOW]
    );
    let efm = &c.project_resolutions[0];
    assert_eq!(efm.follows, Some(Parent::Left));
    // The appendix has the right's edit and its new item under derived ids.
    let rid = split_spec(&w).id();
    let appendix = w
        .repo
        .read_state(w.a, &c.files["Appendix.docx"].state)
        .await
        .unwrap();
    let derived = |id: &str| relocation::dest_id(&rid, &n(id));
    assert_eq!(
        appendix.nodes[&derived("n2")].current_fields["label"],
        json!("n2 edited")
    );
    assert_eq!(
        appendix.nodes[&derived("n9")].parent_id,
        Some(derived("S2"))
    );
    // The proposal keeps S2 tombstoned; the budget follows the rename with the edit.
    let proposal = w
        .repo
        .read_state(w.p, &c.files["Proposal.docx"].state)
        .await
        .unwrap();
    assert!(proposal.nodes[&n("S2")].deleted && !proposal.nodes.contains_key(&n("n9")));
    let b = w
        .repo
        .read_state(
            c.files["Finance/Budget.xlsx"].document,
            &c.files["Finance/Budget.xlsx"].state,
        )
        .await
        .unwrap();
    assert_eq!(b.nodes[&n("C4")].current_fields["cell_3"], json!("12"));
    assert!(!c.files.contains_key("Budget.xlsx"));

    // The other orientation gives the same files.
    let swapped = w
        .repo
        .prepare_project_merge(&r, &l, policy, &none, 1_700_000_000_010, "merge".into())
        .await
        .unwrap()
        .commit
        .unwrap();
    assert_eq!(swapped.files, c.files);

    // Signed, imported, re-run by verify-merge; lineage leads back to the source.
    let address = commit(&w.repo, c.clone()).await;
    assert_eq!(
        w.repo.verify_project_resolutions(&address).await.unwrap(),
        2
    );
    let steps = w.repo.lineage(&address, w.a, &derived("n2")).await.unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(
        (steps[0].from_document, steps[0].from_node.clone()),
        (w.p, n("n2"))
    );

    // A forged record (a merged state the strategy does not produce) is signed
    // validly but fails `verify-merge`, and a wrong parent state fails import.
    let mut forged = c.clone();
    let wrong = w.repo.commit(&l).await.unwrap().commit.files["Appendix.docx"]
        .state
        .clone();
    forged.files.get_mut("Appendix.docx").unwrap().state = wrong.clone();
    forged.project_resolutions[0].merged = wrong;
    forged.message = "forged".into();
    let forged_address = commit(&w.repo, forged).await;
    assert!(w
        .repo
        .verify_project_resolutions(&forged_address)
        .await
        .is_err());
    let mut lying = c.clone();
    lying.project_resolutions[0].source.as_mut().unwrap().right =
        Some(lying.files["Proposal.docx"].state.clone());
    lying.project = w.repo.project();
    let signed = SignedCommit::sign(lying, &key()).unwrap();
    assert!(w.repo.import_commit(&signed).await.is_err());
    cleanup(w.repo, &w.file).await;
}

#[tokio::test]
async fn a_forged_relocation_record_is_refused_on_import() {
    let w = world().await;
    let paths = BTreeMap::from([(w.a.0, "Appendix.docx".to_string())]);
    let split = w
        .repo
        .relocate(&w.base, &[split_spec(&w)], &paths, 1, "split".into())
        .await
        .unwrap();
    // The destination claims the derived subtree but holds the source state.
    let mut forged = split.clone();
    let source = forged.files["Proposal.docx"].state.clone();
    forged.files.get_mut("Appendix.docx").unwrap().state = source.clone();
    forged.relocations[0].dest_state_after = source;
    let signed = SignedCommit::sign(forged, &key()).unwrap();
    let err = w.repo.import_commit(&signed).await.unwrap_err();
    assert!(err.to_string().contains("relocation"), "{err}");
    // More nodes than were moved.
    let mut forged = split.clone();
    forged.relocations[0].count += 1;
    assert!(w
        .repo
        .import_commit(&SignedCommit::sign(forged, &key()).unwrap())
        .await
        .is_err());
    // The honest commit imports.
    assert!(w
        .repo
        .import_commit(&SignedCommit::sign(split, &key()).unwrap())
        .await
        .is_ok());
    cleanup(w.repo, &w.file).await;
}

#[tokio::test]
async fn move_against_delete_and_two_splits_are_never_automatic() {
    let w = world().await;
    let l = left(&w).await;
    let r = right(&w, |p| {
        p.nodes.get_mut(&n("S2")).unwrap().deleted = true;
        for id in ["n1", "n2", "n3"] {
            p.nodes.get_mut(&n(id)).unwrap().deleted = true;
        }
    })
    .await;
    let policy = merge_policy::default::policy();
    let merge = w
        .repo
        .prepare_project_merge(&l, &r, policy, &ResolutionFile::default(), 2, "m".into())
        .await
        .unwrap();
    assert!(merge.commit.is_none());
    let classes: Vec<Class> = merge.report.conflicts.iter().map(|c| c.class).collect();
    assert_eq!(classes, [Class::MoveDelete]);
    // A person decides: keep the left's documents for the conflict.
    let choice = ResolutionFile {
        version: 2,
        choices: vec![project::Choice {
            conflict: merge.report.conflicts[0].id.clone(),
            take: "left".into(),
        }],
    };
    let decided = w
        .repo
        .prepare_project_merge(&l, &r, policy, &choice, 2, "m".into())
        .await
        .unwrap();
    let c = decided.commit.unwrap();
    // Only the rename-follow is automatic; the chosen documents carry no record.
    assert_eq!(c.project_resolutions.len(), 1);
    assert!(c.files.contains_key("Appendix.docx"));
    // An unknown conflict id is refused.
    let mut unknown = choice.clone();
    unknown.choices[0].conflict = "XD-R2:000000000000".into();
    assert!(w
        .repo
        .prepare_project_merge(&l, &r, policy, &unknown, 2, "m".into())
        .await
        .is_err());

    // Two different splits of one file.
    let other = DocumentId(uuid::Uuid::from_u128(0xb1));
    let mut spec = split_spec(&w);
    spec.to.document = other;
    spec.from.roots = vec![n("S3")];
    let paths = BTreeMap::from([(other.0, "Annex.docx".to_string())]);
    let second = w
        .repo
        .relocate(&w.base, &[spec], &paths, 3, "split 2".into())
        .await
        .unwrap();
    let second = commit(&w.repo, second).await;
    let both = w
        .repo
        .prepare_project_merge(
            &l,
            &second,
            policy,
            &ResolutionFile::default(),
            4,
            "m".into(),
        )
        .await
        .unwrap();
    assert!(both
        .report
        .conflicts
        .iter()
        .any(|c| c.class == Class::SplitSplit));
    assert!(both.commit.is_none());
    cleanup(w.repo, &w.file).await;
}
