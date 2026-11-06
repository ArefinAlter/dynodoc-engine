//! Commit-addressed project recovery. Apply a source delta (or its inverse) to
//! an explicit current commit. Recovery sources never become ancestry implicitly.
//! Same-file edits and shared path/identity constraints require explicit choices.
use super::{archive, compare, Commit, Error, FileEntry, SignedCommit};
use crate::shared_checkpoint::Address;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    CherryPick,
    Revert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictClass {
    ContentConflict,
    ModifyDelete,
    NamespaceCollision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictReport {
    pub path: String,
    pub classification: ConflictClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_state: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onto_state: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_state: Option<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModifiedPath {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<FileEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<FileEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPreflightReport {
    /// True only when there is no conflict and no required commit is missing from the
    /// destination: a report built on missing data is never clean.
    pub feasible: bool,
    /// No path conflicts, whatever the destination holds.
    pub conflict_free: bool,
    /// What the analysis rests on.
    pub evidence: String,
    pub kind: Kind,
    pub source: Address,
    pub onto: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mainline: Option<Address>,
    pub modified_paths: Vec<ModifiedPath>,
    pub conflicts: Vec<ConflictReport>,
    pub required_base_commits: Vec<Address>,
    pub missing_base_commits: Vec<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub kind: Kind,
    pub commit: Address,
    /// None only for a root commit. A merge requires an explicit chosen parent.
    pub mainline: Option<Address>,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub project: uuid::Uuid,
    pub onto: Address,
    pub source: Source,
    pub changes: compare::ProjectPlan,
}

/// The caller loads and verifies these commits. Mainline must be an actual
/// parent; only a root can use the empty-tree baseline. No ancestry search or
/// arbitrary first-parent choice is performed here.
pub fn plan(
    kind: Kind,
    source: &Commit,
    onto: &Commit,
    mainline: Option<&Commit>,
) -> Result<Plan, Error> {
    source.validate()?;
    onto.validate()?;
    if source.project != onto.project {
        return Err(Error::Invalid("recovery project scope"));
    }
    let mut empty = source.clone();
    empty.files.clear();
    let (baseline, parent) = match mainline {
        None if source.parents.is_empty() => (&empty, None),
        Some(parent) => {
            let address = parent.address()?;
            if parent.project != source.project || !source.parents.contains(&address) {
                return Err(Error::Invalid("recovery mainline is not a source parent"));
            }
            (parent, Some(address))
        }
        None => return Err(Error::Invalid("recovery source requires a mainline parent")),
    };
    let (before, after) = match kind {
        Kind::CherryPick => (baseline, source),
        Kind::Revert => (source, baseline),
    };
    Ok(Plan {
        project: source.project,
        onto: onto.address()?,
        source: Source {
            kind,
            commit: source.address()?,
            mainline: parent,
        },
        changes: compare::plan(before, onto, after)?,
    })
}

impl Plan {
    /// Only conflicting paths can differ from the deterministic plan. Importers
    /// recheck this against the verified source and current commits. A signed
    /// manifest cannot label unrelated edits as recovery of a different commit.
    pub fn validate_files(&self, files: &BTreeMap<String, FileEntry>) -> Result<(), Error> {
        let conflicts: BTreeSet<_> = self.changes.conflicts.iter().map(|c| &c.path).collect();
        for path in files.keys().chain(self.changes.files.keys()) {
            if !conflicts.contains(path) && files.get(path) != self.changes.files.get(path) {
                return Err(Error::Invalid("recovery changes an unconflicted path"));
            }
        }
        Ok(())
    }

    /// Each conflict needs an explicit value or null (delete). Unknown choices
    /// are rejected. Signing and branch publication remain separate operations.
    pub fn resolve(
        &self,
        resolutions: &BTreeMap<String, Option<FileEntry>>,
        authored_at_ms: i64,
        message: String,
    ) -> Result<Commit, Error> {
        if resolutions.len() != self.changes.conflicts.len()
            || self
                .changes
                .conflicts
                .iter()
                .any(|c| !resolutions.contains_key(&c.path))
        {
            return Err(Error::Invalid("resolve every conflict path exactly once"));
        }
        let mut files = self.changes.files.clone();
        for (path, choice) in resolutions {
            if let Some(file) = choice {
                files.insert(path.clone(), file.clone());
            }
        }
        self.validate_files(&files)?;
        let result = Commit {
            version: 2,
            project: self.project,
            parents: vec![self.onto.clone()],
            files,
            author_key: "00".repeat(32), // Filled by SignedCommit::sign.
            authored_at_ms,
            message,
            recovery: Some(self.source.clone()),
            same_file_resolutions: Vec::new(),
        };
        result.bytes()?; // Shared identity, namespace and size validation.
        Ok(result)
    }
}

/// A commit is evidence only if it hashes and verifies to the address it was looked up
/// by and belongs to this project, whoever supplied it.
pub fn verified(
    signed: SignedCommit,
    expected: &Address,
    project: uuid::Uuid,
) -> Result<SignedCommit, Error> {
    if signed.verify()? != *expected {
        return Err(Error::Invalid("commit does not match its address"));
    }
    if signed.commit.project != project {
        return Err(Error::Invalid("commit belongs to another project"));
    }
    Ok(signed)
}

/// Compute structured read-only preflight analysis for applying a recovery delta onto `onto`.
///
/// Evaluates feasibility, classified conflicts, modified paths, and required base commitments
/// without writing or creating any database records or modifying repository refs.
pub fn preflight_plan(
    kind: Kind,
    source: &Commit,
    onto: &Commit,
    mainline: Option<&Commit>,
    is_base_commit_present: impl Fn(&Address) -> bool,
) -> Result<RecoveryPreflightReport, Error> {
    let p = plan(kind, source, onto, mainline)?;
    let source_addr = source.address()?;
    let onto_addr = onto.address()?;
    let mainline_addr = match mainline {
        Some(m) => Some(m.address()?),
        None => None,
    };

    let mut required_base_commits = vec![source_addr.clone(), onto_addr.clone()];
    if let Some(ref m) = mainline_addr {
        if !required_base_commits.contains(m) {
            required_base_commits.push(m.clone());
        }
    }

    let missing_base_commits: Vec<Address> = required_base_commits
        .iter()
        .filter(|addr| !is_base_commit_present(addr))
        .cloned()
        .collect();

    let mut conflicts = Vec::new();
    for c in p.changes.conflicts {
        let classification = if c.left.is_some() && c.right.is_some() {
            ConflictClass::ContentConflict
        } else if c.left.is_none() && c.right.is_none() {
            ConflictClass::NamespaceCollision
        } else {
            ConflictClass::ModifyDelete
        };
        let base_state = c.base.as_ref().map(|f| f.state.clone());
        let onto_state = c.left.as_ref().map(|f| f.state.clone());
        let source_state = c.right.as_ref().map(|f| f.state.clone());
        conflicts.push(ConflictReport {
            path: c.path,
            classification,
            base_state,
            onto_state,
            source_state,
        });
    }

    let conflict_paths: BTreeSet<&String> = conflicts.iter().map(|c| &c.path).collect();
    let mut all_paths: BTreeSet<&String> = onto.files.keys().collect();
    for path in p.changes.files.keys() {
        all_paths.insert(path);
    }

    let mut modified_paths = Vec::new();
    for path in all_paths {
        if conflict_paths.contains(path) {
            continue;
        }
        let from = onto.files.get(path).cloned();
        let to = p.changes.files.get(path).cloned();
        if from != to {
            modified_paths.push(ModifiedPath {
                path: path.clone(),
                from,
                to,
            });
        }
    }

    let conflict_free = conflicts.is_empty();
    let feasible = conflict_free && missing_base_commits.is_empty();

    Ok(RecoveryPreflightReport {
        feasible,
        conflict_free,
        evidence: "commit frames only: addresses, signatures and project were checked; typed file states and recovery rules were not replayed".into(),
        kind,
        source: source_addr,
        onto: onto_addr,
        mainline: mainline_addr,
        modified_paths,
        conflicts,
        required_base_commits,
        missing_base_commits,
    })
}

/// Read-only preflight analysis for commit-addressed recovery directly against an archive stream.
///
/// Streams commits from `reader` up to `limits.max_commits`, resolves `source` and `mainline`
/// parents across the archive and optional target repository lookup, and returns structured
/// feasibility and conflict reports without any side effects on disk or database.
#[allow(clippy::too_many_arguments)]
pub fn preflight_archive_recovery<R: std::io::Read>(
    reader: R,
    limits: archive::ArchiveLimits,
    kind: Kind,
    source_addr: &Address,
    onto_addr: &Address,
    mainline_addr: Option<&Address>,
    target_repo_commits: impl Fn(&Address) -> Option<SignedCommit>,
    is_base_commit_present: impl Fn(&Address) -> bool,
) -> Result<RecoveryPreflightReport, Error> {
    let mut archive_reader = archive::ArchiveReader::new(reader, limits);
    let mut project = None;
    let mut commits_in_archive: HashMap<Address, SignedCommit> = HashMap::new();

    while let Some(entry) = archive_reader.next_entry().map_err(|e| match e {
        archive::ArchiveError::Limit(_) => {
            Error::Limit("archive limits exceeded during recovery preflight")
        }
        _ => Error::Invalid("malformed archive stream during recovery preflight"),
    })? {
        match entry {
            archive::ArchiveEntry::Header { project: p, .. } => project = Some(p.0),
            archive::ArchiveEntry::Commit {
                address, signed, ..
            } => {
                commits_in_archive.insert(address, signed);
            }
            _ => {}
        }
    }
    let project = project.ok_or(Error::Invalid("archive has no header"))?;

    let get_commit = |addr: &Address| -> Result<SignedCommit, Error> {
        let signed = commits_in_archive
            .get(addr)
            .cloned()
            .or_else(|| target_repo_commits(addr))
            .ok_or_else(|| Error::Missing(addr.clone()))?;
        verified(signed, addr, project)
    };

    let onto_signed = get_commit(onto_addr)?;
    let source_signed = get_commit(source_addr)?;
    let source_commit = &source_signed.commit;

    let baseline = match (mainline_addr, source_commit.parents.as_slice()) {
        (Some(chosen), parents) if parents.contains(chosen) => {
            let parent_signed = get_commit(chosen)?;
            Some(parent_signed.commit)
        }
        (Some(_), _) => return Err(Error::Invalid("recovery mainline is not a source parent")),
        (None, []) => None,
        (None, [parent]) => {
            let parent_signed = get_commit(parent)?;
            Some(parent_signed.commit)
        }
        (None, _) => {
            return Err(Error::Invalid(
                "merge recovery requires an explicit mainline",
            ))
        }
    };

    preflight_plan(
        kind,
        source_commit,
        &onto_signed.commit,
        baseline.as_ref(),
        is_base_commit_present,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{tests::signed, SignedCommit};
    use engine_shared::DocumentId;
    use ring::signature::Ed25519KeyPair;

    fn entry(id: u128, byte: &str) -> FileEntry {
        FileEntry {
            document: DocumentId(uuid::Uuid::from_u128(id)),
            state: Address::try_from(byte.repeat(64)).unwrap(),
        }
    }
    fn commit(parents: Vec<Address>, files: BTreeMap<String, FileEntry>) -> Commit {
        signed(uuid::Uuid::from_u128(1), parents, files, "test").commit
    }

    #[test]
    fn cherry_pick_and_revert_preserve_unrelated_later_work_and_only_add_current_parent() {
        let base = commit(
            vec![],
            BTreeMap::from([
                ("Report.docx".into(), entry(1, "a")),
                ("Budget.xlsx".into(), entry(2, "b")),
            ]),
        );
        let mut source = base.clone();
        source.parents = vec![base.address().unwrap()];
        source.files.get_mut("Report.docx").unwrap().state = entry(1, "c").state;
        let mut onto = base.clone();
        onto.parents = vec![base.address().unwrap()];
        onto.files.get_mut("Budget.xlsx").unwrap().state = entry(2, "d").state;
        let pick = plan(Kind::CherryPick, &source, &onto, Some(&base)).unwrap();
        let picked = pick
            .resolve(&BTreeMap::new(), 2, "Recover report edit".into())
            .unwrap();
        assert_eq!(picked.files["Report.docx"], source.files["Report.docx"]);
        assert_eq!(picked.files["Budget.xlsx"], onto.files["Budget.xlsx"]);
        assert_eq!(picked.parents, vec![onto.address().unwrap()]);
        assert_eq!(
            picked.dependencies(),
            vec![
                onto.address().unwrap(),
                source.address().unwrap(),
                base.address().unwrap()
            ]
        );
        let undo = plan(Kind::Revert, &source, &picked, Some(&base)).unwrap();
        let undone = undo
            .resolve(&BTreeMap::new(), 3, "Undo only the report edit".into())
            .unwrap();
        assert_eq!(undone.files, onto.files);
        // Repeating an already-applied delta is a content no-op, never a reset.
        let repeated = plan(Kind::CherryPick, &source, &picked, Some(&base)).unwrap();
        assert_eq!(
            repeated
                .resolve(&BTreeMap::new(), 4, "Already present".into())
                .unwrap()
                .files,
            picked.files
        );
    }

    #[test]
    fn competing_edit_or_delete_requires_complete_explicit_resolution() {
        let base = commit(
            vec![],
            BTreeMap::from([("a".into(), entry(1, "a")), ("b".into(), entry(2, "b"))]),
        );
        let mut source = base.clone();
        source.parents = vec![base.address().unwrap()];
        source.files.get_mut("a").unwrap().state = entry(1, "c").state;
        let mut onto = base.clone();
        onto.files.remove("a");
        let plan = plan(Kind::CherryPick, &source, &onto, Some(&base)).unwrap();
        assert_eq!(plan.changes.conflicts.len(), 1);
        assert!(plan
            .resolve(&BTreeMap::new(), 2, "Missing choice".into())
            .is_err());
        assert!(plan
            .resolve(
                &BTreeMap::from([("b".into(), None)]),
                2,
                "Wrong choice".into()
            )
            .is_err());
        let removed = plan
            .resolve(
                &BTreeMap::from([("a".into(), None)]),
                2,
                "Keep deletion".into(),
            )
            .unwrap();
        assert_eq!(removed.files, onto.files);
        let kept = plan
            .resolve(
                &BTreeMap::from([("a".into(), Some(entry(1, "c")))]),
                2,
                "Take recovered edit".into(),
            )
            .unwrap();
        assert_eq!(kept.files["a"], source.files["a"]);
        let mut forged = kept.files.clone();
        forged.remove("b");
        assert!(plan.validate_files(&forged).is_err());
        forged = kept.files;
        forged.insert("extra".into(), entry(3, "e"));
        assert!(plan.validate_files(&forged).is_err());
    }

    #[test]
    fn recovery_checks_shared_identity_and_path_constraints_after_resolution() {
        let base = commit(vec![], BTreeMap::from([("old".into(), entry(1, "a"))]));
        let source = commit(
            vec![base.address().unwrap()],
            BTreeMap::from([("renamed".into(), entry(1, "a"))]),
        );
        let onto = commit(
            vec![base.address().unwrap()],
            BTreeMap::from([("elsewhere".into(), entry(1, "a"))]),
        );
        let plan = plan(Kind::CherryPick, &source, &onto, Some(&base)).unwrap();
        assert_eq!(plan.changes.conflicts.len(), 2);
        assert!(plan
            .resolve(
                &BTreeMap::from([
                    ("renamed".into(), Some(entry(1, "a"))),
                    ("elsewhere".into(), Some(entry(1, "a"))),
                ]),
                2,
                "Invalid duplicate identity".into()
            )
            .is_err());
        let resolved = plan
            .resolve(
                &BTreeMap::from([
                    ("renamed".into(), Some(entry(1, "a"))),
                    ("elsewhere".into(), None),
                ]),
                2,
                "Choose rename".into(),
            )
            .unwrap();
        assert_eq!(resolved.files, source.files);
    }

    #[test]
    fn root_uses_empty_baseline_and_merge_requires_an_actual_selected_parent() {
        let empty = commit(vec![], BTreeMap::new());
        let root = commit(vec![], BTreeMap::from([("a".into(), entry(1, "a"))]));
        let added = plan(Kind::CherryPick, &root, &empty, None).unwrap();
        assert_eq!(
            added
                .resolve(&BTreeMap::new(), 2, "Initial recovery".into())
                .unwrap()
                .files,
            root.files
        );
        let removed = plan(Kind::Revert, &root, &root, None).unwrap();
        assert!(removed
            .resolve(&BTreeMap::new(), 3, "Undo initial".into())
            .unwrap()
            .files
            .is_empty());
        assert!(plan(Kind::Revert, &root, &root, Some(&empty)).is_err());
        let merge = commit(
            vec![root.address().unwrap(), empty.address().unwrap()],
            root.files.clone(),
        );
        assert!(plan(Kind::Revert, &merge, &merge, None).is_err());
        let against_root = plan(Kind::Revert, &merge, &merge, Some(&root)).unwrap();
        assert_eq!(against_root.changes.files, root.files);
        let against_empty = plan(Kind::Revert, &merge, &merge, Some(&empty)).unwrap();
        assert!(against_empty.changes.files.is_empty());
        let mut foreign = empty.clone();
        foreign.project = uuid::Uuid::from_u128(2);
        assert!(plan(Kind::Revert, &root, &foreign, None).is_err());
    }

    #[test]
    fn independent_v2_vector_binds_recovery_without_changing_v1() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/project-recovery-v2.json"
        ))
        .unwrap();
        let signed: SignedCommit = serde_json::from_value(fixture["signed"].clone()).unwrap();
        assert_eq!(
            signed.commit.bytes().unwrap(),
            fixture["canonical"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            signed.verify().unwrap().as_str(),
            fixture["address"].as_str().unwrap()
        );
        assert_eq!(
            SignedCommit::sign(
                signed.commit.clone(),
                &Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
            )
            .unwrap()
            .signature,
            signed.signature
        );
        let mut forged = signed.clone();
        forged.commit.recovery.as_mut().unwrap().kind = Kind::Revert;
        assert!(forged.verify().is_err());
        forged = signed.clone();
        forged.commit.recovery.as_mut().unwrap().mainline = None;
        assert!(forged.verify().is_err());
        forged = signed.clone();
        forged.commit.recovery.as_mut().unwrap().commit =
            Address::try_from("44".repeat(32)).unwrap();
        assert!(forged.verify().is_err());
        let mut bad = signed.commit.clone();
        bad.version = 1;
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.recovery = None;
        assert!(bad.validate().is_err());
        bad = signed.commit;
        bad.parents.clear();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_preflight_plan_clean_cherry_pick() {
        let base = commit(
            vec![],
            BTreeMap::from([
                ("Report.docx".into(), entry(1, "a")),
                ("Budget.xlsx".into(), entry(2, "b")),
            ]),
        );
        let mut source = base.clone();
        source.parents = vec![base.address().unwrap()];
        source.files.get_mut("Report.docx").unwrap().state = entry(1, "c").state;
        let mut onto = base.clone();
        onto.parents = vec![base.address().unwrap()];
        onto.files.get_mut("Budget.xlsx").unwrap().state = entry(2, "d").state;

        let report =
            preflight_plan(Kind::CherryPick, &source, &onto, Some(&base), |_| true).unwrap();
        assert!(report.feasible);
        assert!(report.conflicts.is_empty());
        assert_eq!(report.modified_paths.len(), 1);
        assert_eq!(report.modified_paths[0].path, "Report.docx");
        assert_eq!(report.modified_paths[0].from, Some(entry(1, "a")));
        assert_eq!(report.modified_paths[0].to, Some(entry(1, "c")));
        assert_eq!(
            report.required_base_commits,
            vec![
                source.address().unwrap(),
                onto.address().unwrap(),
                base.address().unwrap(),
            ]
        );
        assert!(report.missing_base_commits.is_empty());
    }

    #[test]
    fn test_preflight_plan_conflict_detection() {
        let base = commit(
            vec![],
            BTreeMap::from([("Report.docx".into(), entry(1, "a"))]),
        );
        let mut source = base.clone();
        source.parents = vec![base.address().unwrap()];
        source.files.get_mut("Report.docx").unwrap().state = entry(1, "b").state;

        // ContentConflict: both changed Report.docx differently
        let mut onto = base.clone();
        onto.parents = vec![base.address().unwrap()];
        onto.files.get_mut("Report.docx").unwrap().state = entry(1, "c").state;

        let report =
            preflight_plan(Kind::CherryPick, &source, &onto, Some(&base), |_| true).unwrap();
        assert!(!report.feasible);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflicts[0].path, "Report.docx");
        assert_eq!(
            report.conflicts[0].classification,
            ConflictClass::ContentConflict
        );
        assert_eq!(report.conflicts[0].base_state, Some(entry(1, "a").state));
        assert_eq!(report.conflicts[0].onto_state, Some(entry(1, "c").state));
        assert_eq!(report.conflicts[0].source_state, Some(entry(1, "b").state));

        // ModifyDelete: onto deleted Report.docx
        let mut onto_del = base.clone();
        onto_del.parents = vec![base.address().unwrap()];
        onto_del.files.clear();

        let report_del =
            preflight_plan(Kind::CherryPick, &source, &onto_del, Some(&base), |_| true).unwrap();
        assert!(!report_del.feasible);
        assert_eq!(report_del.conflicts.len(), 1);
        assert_eq!(report_del.conflicts[0].path, "Report.docx");
        assert_eq!(
            report_del.conflicts[0].classification,
            ConflictClass::ModifyDelete
        );
    }

    #[test]
    fn test_preflight_archive_recovery_absent_parent_refusal() {
        let project = DocumentId(uuid::Uuid::from_u128(1));
        let genesis_signed = signed(
            project.0,
            vec![],
            BTreeMap::from([("a".into(), entry(1, "a"))]),
            "genesis",
        );
        let genesis_addr = genesis_signed.commit.address().unwrap();

        let child_signed = signed(
            project.0,
            vec![genesis_addr.clone()],
            BTreeMap::from([("a".into(), entry(1, "a")), ("b".into(), entry(2, "b"))]),
            "child",
        );
        let child_addr = child_signed.commit.address().unwrap();

        let onto_signed = signed(
            project.0,
            vec![],
            BTreeMap::from([("c".into(), entry(3, "c"))]),
            "onto",
        );
        let onto_addr = onto_signed.commit.address().unwrap();

        // Create an archive containing ONLY child_signed, declaring genesis_addr as `since`
        let mut buf = Vec::new();
        let mut writer = archive::ArchiveWriter::new(&mut buf).unwrap();
        writer
            .write_header_with_since(1, project, child_addr.clone(), Some(genesis_addr.clone()))
            .unwrap();
        writer.write_commit(&child_signed).unwrap();
        writer.finish().unwrap();

        // Attempt preflight where parent genesis_addr is absent in archive and target_repo_commits returns None
        let err = preflight_archive_recovery(
            std::io::Cursor::new(&buf),
            archive::ArchiveLimits::default(),
            Kind::CherryPick,
            &child_addr,
            &onto_addr,
            None,
            |a| (a == &onto_addr).then(|| onto_signed.clone()),
            |_| false,
        )
        .unwrap_err();

        // Must refuse due to absent parent
        assert!(matches!(err, Error::Missing(addr) if addr == genesis_addr));
    }

    #[test]
    fn test_preflight_archive_recovery_success_with_archive_commits() {
        let project = DocumentId(uuid::Uuid::from_u128(1));
        let base_signed = signed(
            project.0,
            vec![],
            BTreeMap::from([("a".into(), entry(1, "a"))]),
            "base",
        );
        let base_addr = base_signed.commit.address().unwrap();

        let source_signed = signed(
            project.0,
            vec![base_addr.clone()],
            BTreeMap::from([("a".into(), entry(1, "a")), ("b".into(), entry(2, "b"))]),
            "source",
        );
        let source_addr = source_signed.commit.address().unwrap();

        let onto_signed = signed(
            project.0,
            vec![],
            BTreeMap::from([("a".into(), entry(1, "a"))]),
            "onto",
        );
        let onto_addr = onto_signed.commit.address().unwrap();

        let mut buf = Vec::new();
        let mut writer = archive::ArchiveWriter::new(&mut buf).unwrap();
        writer
            .write_header(1, project, source_addr.clone())
            .unwrap();
        writer.write_commit(&base_signed).unwrap();
        writer.write_commit(&source_signed).unwrap();
        writer.finish().unwrap();

        let preflight = |present: bool| {
            preflight_archive_recovery(
                std::io::Cursor::new(&buf),
                archive::ArchiveLimits::default(),
                Kind::CherryPick,
                &source_addr,
                &onto_addr,
                None,
                |a| (a == &onto_addr).then(|| onto_signed.clone()),
                move |_| present,
            )
            .unwrap()
        };

        // Nothing in a destination: the changes are conflict free, but the report is not
        // feasible while every required commit is missing there.
        let offline = preflight(false);
        assert!(offline.conflict_free && !offline.feasible);
        assert_eq!(offline.missing_base_commits.len(), 3);
        assert_eq!(offline.modified_paths.len(), 1);
        assert_eq!(offline.modified_paths[0].path, "b");
        assert!(offline.evidence.contains("not replayed"));

        let present = preflight(true);
        assert!(present.conflict_free && present.feasible);
        assert!(present.missing_base_commits.is_empty());
    }

    #[test]
    fn test_preflight_archive_recovery_refuses_unverified_callback_commits() {
        let project = DocumentId(uuid::Uuid::from_u128(1));
        let source_signed = signed(
            project.0,
            vec![],
            BTreeMap::from([("a".into(), entry(1, "a"))]),
            "source",
        );
        let source_addr = source_signed.commit.address().unwrap();
        let onto_signed = signed(
            project.0,
            vec![],
            BTreeMap::from([("b".into(), entry(2, "b"))]),
            "onto",
        );
        let onto_addr = onto_signed.commit.address().unwrap();
        let foreign_onto = signed(
            uuid::Uuid::from_u128(2),
            vec![],
            BTreeMap::from([("b".into(), entry(2, "b"))]),
            "onto",
        );
        let foreign_addr = foreign_onto.commit.address().unwrap();

        let mut buf = Vec::new();
        let mut writer = archive::ArchiveWriter::new(&mut buf).unwrap();
        writer
            .write_header(1, project, source_addr.clone())
            .unwrap();
        writer.write_commit(&source_signed).unwrap();
        writer.finish().unwrap();

        let preflight = |onto: &Address, supplied: SignedCommit| {
            preflight_archive_recovery(
                std::io::Cursor::new(&buf),
                archive::ArchiveLimits::default(),
                Kind::CherryPick,
                &source_addr,
                onto,
                None,
                |_| Some(supplied.clone()),
                |_| true,
            )
        };
        // Another project's commit under its own, correct address.
        let err = preflight(&foreign_addr, foreign_onto.clone()).unwrap_err();
        assert!(matches!(
            err,
            Error::Invalid("commit belongs to another project")
        ));
        // A genuine commit is accepted; a different one supplied under the requested address is not.
        assert!(preflight(&onto_addr, onto_signed).is_ok());
        let err = preflight(
            &foreign_addr,
            signed(
                project.0,
                vec![],
                BTreeMap::from([("z".into(), entry(9, "e"))]),
                "other",
            ),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Invalid("commit does not match its address")
        ));
    }
}
