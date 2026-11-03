//! First-parent history traversal and paged commit log.
//!
//! Traverses commit history along the first-parent spine (`parents[0]`),
//! ignoring secondary parents and recovery source references. Validates
//! each loaded commit's envelope, address and project scope, while enforcing
//! strict per-page limits on entry count, envelope transfer bytes and
//! output metadata size.

use super::{hex, Address, Error, SignedCommit};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const DEFAULT_LOG_PAGE_LIMIT: usize = 20;
pub const MAX_LOG_PAGE_LIMIT: usize = 50;
pub const MAX_PAGE_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PAGE_METADATA_BYTES: usize = 256 * 1024;
pub const MAX_LOG_MESSAGE_BYTES: usize = 512;

/// A loaded and decoded commit envelope with its raw byte size.
#[derive(Debug, Clone)]
pub struct LoadedEnvelope {
    pub signed: SignedCommit,
    pub bytes: usize,
}

impl LoadedEnvelope {
    pub fn new(signed: SignedCommit, bytes: usize) -> Self {
        Self { signed, bytes }
    }

    pub fn from_signed(signed: SignedCommit) -> Result<Self, Error> {
        let bytes = serde_json::to_vec(&signed)?.len();
        Ok(Self { signed, bytes })
    }
}

/// Abstract commit loader for verified commit retrieval.
pub trait CommitLoader {
    fn load(
        &mut self,
        address: &Address,
    ) -> impl std::future::Future<Output = Result<LoadedEnvelope, Error>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmittedMessage {
    pub omitted: bool,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BoundedMessage {
    Omitted(OmittedMessage),
    Value(String),
}

impl BoundedMessage {
    pub fn new(msg: &str) -> Self {
        if msg.len() > MAX_LOG_MESSAGE_BYTES {
            let hash = ring::digest::digest(&ring::digest::SHA256, msg.as_bytes());
            Self::Omitted(OmittedMessage {
                omitted: true,
                sha256: hex(hash.as_ref()),
                bytes: msg.len(),
            })
        } else {
            Self::Value(msg.to_string())
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Value(s) => Some(s.as_str()),
            Self::Omitted(_) => None,
        }
    }
}

impl std::fmt::Display for BoundedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(s) => write!(f, "{}", s),
            Self::Omitted(o) => {
                write!(f, "[omitted: {} bytes, sha256: {}]", o.bytes, o.sha256)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitLogEntry {
    pub address: Address,
    pub parents: Vec<Address>,
    pub author_key: String,
    pub authored_at_ms: i64,
    pub message: BoundedMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstParentLogOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for FirstParentLogOptions {
    fn default() -> Self {
        Self {
            limit: Some(DEFAULT_LOG_PAGE_LIMIT),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstParentLogPage {
    pub project: uuid::Uuid,
    pub head: Address,
    pub entries: Vec<CommitLogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_address: Option<Address>,
    pub more: bool,
}

/// Retrieve a bounded page of first-parent commit history starting at `head`.
pub async fn first_parent_log<L: CommitLoader + ?Sized>(
    loader: &mut L,
    project: uuid::Uuid,
    head: &Address,
    options: FirstParentLogOptions,
) -> Result<FirstParentLogPage, Error> {
    let limit = match options.limit {
        Some(0) => return Err(Error::Limit("history log limit cannot be zero")),
        Some(l) if l > MAX_LOG_PAGE_LIMIT => {
            return Err(Error::Limit("history log limit exceeds maximum of 50"));
        }
        Some(l) => l,
        None => DEFAULT_LOG_PAGE_LIMIT,
    };

    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total_envelope_bytes = 0usize;
    let mut current_address = head.clone();
    let mut next_address = None;

    while entries.len() < limit {
        if !seen.insert(current_address.clone()) {
            return Err(Error::Invalid("cycle or repeated address in history"));
        }

        let envelope = loader.load(&current_address).await?;

        // Envelope byte limit
        total_envelope_bytes = total_envelope_bytes
            .checked_add(envelope.bytes)
            .ok_or(Error::Limit("history log envelope bytes overflow"))?;
        if total_envelope_bytes > MAX_PAGE_ENVELOPE_BYTES {
            return Err(Error::Limit("history log envelope bytes exceeded"));
        }

        // Validate envelope, scope, address, signature
        if envelope.signed.commit.project != project {
            return Err(Error::Invalid("history commit project mismatch"));
        }
        let verified_address = envelope.signed.verify()?;
        if verified_address != current_address {
            return Err(Error::Invalid("history commit address mismatch"));
        }
        envelope.signed.commit.validate()?;

        let commit = &envelope.signed.commit;
        let entry = CommitLogEntry {
            address: current_address.clone(),
            parents: commit.parents.clone(),
            author_key: commit.author_key.clone(),
            authored_at_ms: commit.authored_at_ms,
            message: BoundedMessage::new(&commit.message),
        };
        entries.push(entry);

        // First parent traversal
        if commit.parents.is_empty() {
            // Genesis commit reached
            next_address = None;
            break;
        }

        let first_parent = commit.parents[0].clone();
        if entries.len() == limit {
            // Page is full, continuation starts at first_parent
            next_address = Some(first_parent);
            break;
        }

        current_address = first_parent;
    }

    let more = next_address.is_some();
    let page = FirstParentLogPage {
        project,
        head: head.clone(),
        entries,
        next_address,
        more,
    };

    // Output metadata byte limit
    let metadata_bytes = serde_json::to_vec(&page)?.len();
    if metadata_bytes > MAX_PAGE_METADATA_BYTES {
        return Err(Error::Limit("history log metadata bytes exceeded"));
    }

    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{recovery, Commit};
    use ring::signature::Ed25519KeyPair;
    use std::collections::BTreeMap;

    fn key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
    }

    fn make_commit(
        project: uuid::Uuid,
        parents: Vec<Address>,
        message: &str,
        recovery: Option<recovery::Source>,
    ) -> (SignedCommit, Address) {
        let version = if recovery.is_some() { 2 } else { 1 };
        let signed = SignedCommit::sign(
            Commit {
                version,
                project,
                parents,
                files: BTreeMap::new(),
                author_key: String::new(),
                authored_at_ms: 1_700_000_000_000,
                message: message.into(),
                recovery,
                same_file_resolutions: Vec::new(),
            },
            &key(),
        )
        .unwrap();
        let addr = signed.verify().unwrap();
        (signed, addr)
    }

    struct MemoryLoader {
        commits: BTreeMap<Address, LoadedEnvelope>,
    }

    impl MemoryLoader {
        fn new() -> Self {
            Self {
                commits: BTreeMap::new(),
            }
        }
        fn insert(&mut self, signed: SignedCommit, address: Address) {
            let bytes = serde_json::to_vec(&signed).unwrap().len();
            self.commits
                .insert(address, LoadedEnvelope::new(signed, bytes));
        }
    }

    impl CommitLoader for MemoryLoader {
        async fn load(&mut self, address: &Address) -> Result<LoadedEnvelope, Error> {
            self.commits
                .get(address)
                .cloned()
                .ok_or_else(|| Error::Missing(address.clone()))
        }
    }

    #[tokio::test]
    async fn test_genesis_and_linear_history_and_exact_continuation() {
        let project = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();

        let (c0, a0) = make_commit(project, vec![], "genesis", None);
        let (c1, a1) = make_commit(project, vec![a0.clone()], "commit 1", None);
        let (c2, a2) = make_commit(project, vec![a1.clone()], "commit 2", None);
        let (c3, a3) = make_commit(project, vec![a2.clone()], "commit 3", None);

        loader.insert(c0, a0.clone());
        loader.insert(c1, a1.clone());
        loader.insert(c2, a2.clone());
        loader.insert(c3, a3.clone());

        // Genesis only
        let page_gen = first_parent_log(
            &mut loader,
            project,
            &a0,
            FirstParentLogOptions { limit: Some(10) },
        )
        .await
        .unwrap();
        assert_eq!(page_gen.entries.len(), 1);
        assert_eq!(page_gen.entries[0].address, a0);
        assert!(page_gen.entries[0].parents.is_empty());
        assert_eq!(page_gen.next_address, None);
        assert!(!page_gen.more);

        // Page 1: limit 2
        let p1 = first_parent_log(
            &mut loader,
            project,
            &a3,
            FirstParentLogOptions { limit: Some(2) },
        )
        .await
        .unwrap();
        assert_eq!(p1.entries.len(), 2);
        assert_eq!(p1.entries[0].address, a3);
        assert_eq!(p1.entries[1].address, a2);
        assert_eq!(p1.next_address, Some(a1.clone()));
        assert!(p1.more);

        // Page 2: exact continuation from next_address
        let p2 = first_parent_log(
            &mut loader,
            project,
            &p1.next_address.unwrap(),
            FirstParentLogOptions { limit: Some(2) },
        )
        .await
        .unwrap();
        assert_eq!(p2.entries.len(), 2);
        assert_eq!(p2.entries[0].address, a1);
        assert_eq!(p2.entries[1].address, a0);
        assert_eq!(p2.next_address, None);
        assert!(!p2.more);
    }

    #[tokio::test]
    async fn test_two_parent_merges_metadata_and_first_parent_following() {
        let project = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();

        let (c0, a0) = make_commit(project, vec![], "root", None);
        let (c_left, a_left) = make_commit(project, vec![a0.clone()], "left", None);
        let (c_right, a_right) = make_commit(project, vec![a0.clone()], "right", None);
        let (c_merge, a_merge) = make_commit(
            project,
            vec![a_left.clone(), a_right.clone()],
            "merge commit",
            None,
        );

        loader.insert(c0, a0.clone());
        loader.insert(c_left, a_left.clone());
        loader.insert(c_right, a_right.clone());
        loader.insert(c_merge, a_merge.clone());

        let page = first_parent_log(
            &mut loader,
            project,
            &a_merge,
            FirstParentLogOptions { limit: Some(10) },
        )
        .await
        .unwrap();

        assert_eq!(page.entries.len(), 3);
        // Merge entry has both parents recorded in metadata
        assert_eq!(page.entries[0].address, a_merge);
        assert_eq!(
            page.entries[0].parents,
            vec![a_left.clone(), a_right.clone()]
        );
        // Followed first parent only: a_left, then a0
        assert_eq!(page.entries[1].address, a_left);
        assert_eq!(page.entries[2].address, a0);
        assert_eq!(page.next_address, None);
        assert!(!page.more);
    }

    #[tokio::test]
    async fn test_recovery_refs_are_not_followed() {
        let project = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();

        let (c0, a0) = make_commit(project, vec![], "root", None);
        let (c1, a1) = make_commit(project, vec![a0.clone()], "c1", None);
        let (_c_orphaned, a_orphaned) = make_commit(project, vec![], "recovery source", None);

        let (c2, a2) = make_commit(
            project,
            vec![a1.clone()],
            "recovery commit",
            Some(recovery::Source {
                kind: recovery::Kind::Revert,
                commit: a_orphaned.clone(),
                mainline: None,
            }),
        );

        loader.insert(c0, a0.clone());
        loader.insert(c1, a1.clone());
        // Deliberately do NOT insert c_orphaned into loader
        loader.insert(c2, a2.clone());

        // Traversal succeeds because recovery source is never fetched
        let page = first_parent_log(
            &mut loader,
            project,
            &a2,
            FirstParentLogOptions { limit: Some(10) },
        )
        .await
        .unwrap();

        assert_eq!(page.entries.len(), 3);
        assert_eq!(page.entries[0].address, a2);
        assert_eq!(page.entries[1].address, a1);
        assert_eq!(page.entries[2].address, a0);
    }

    #[tokio::test]
    async fn test_oversized_messages_capped_with_omitted_marker_and_hash() {
        let project = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();

        let long_message = "M".repeat(1000);
        let (c0, a0) = make_commit(project, vec![], &long_message, None);
        loader.insert(c0, a0.clone());

        let page = first_parent_log(
            &mut loader,
            project,
            &a0,
            FirstParentLogOptions { limit: Some(10) },
        )
        .await
        .unwrap();

        assert_eq!(page.entries.len(), 1);
        let entry = &page.entries[0];
        assert_eq!(entry.address, a0);
        match &entry.message {
            BoundedMessage::Omitted(omitted) => {
                assert!(omitted.omitted);
                assert_eq!(omitted.bytes, 1000);
                let expected_hash =
                    ring::digest::digest(&ring::digest::SHA256, long_message.as_bytes());
                assert_eq!(omitted.sha256, hex(expected_hash.as_ref()));
            }
            BoundedMessage::Value(_) => panic!("expected omitted message for >512 byte string"),
        }
        let display = format!("{}", entry.message);
        assert!(display.starts_with("[omitted: 1000 bytes, sha256: "));
        assert_eq!(entry.message.as_str(), None);
    }

    #[tokio::test]
    async fn test_missing_parent_fails_atomically() {
        let project = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();

        let (_c0, a0) = make_commit(project, vec![], "missing parent", None);
        let (c1, a1) = make_commit(project, vec![a0.clone()], "c1", None);
        loader.insert(c1, a1.clone());

        let err = first_parent_log(
            &mut loader,
            project,
            &a1,
            FirstParentLogOptions { limit: Some(10) },
        )
        .await
        .unwrap_err();

        match err {
            Error::Missing(missing_addr) => assert_eq!(missing_addr, a0),
            other => panic!("expected Error::Missing({a0:?}), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_commit_address_mismatch() {
        let project = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();

        let (c0, a0) = make_commit(project, vec![], "c0", None);
        let (_c1, a1) = make_commit(project, vec![a0.clone()], "c1", None);
        // Loader returns c0 when a1 was requested
        loader.insert(c0, a1.clone());

        let err = first_parent_log(
            &mut loader,
            project,
            &a1,
            FirstParentLogOptions { limit: Some(10) },
        )
        .await
        .unwrap_err();

        match err {
            Error::Invalid(msg) => assert_eq!(msg, "history commit address mismatch"),
            other => panic!("expected Error::Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_corrupt_signature_fails() {
        let project = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();

        let (mut c0, a0) = make_commit(project, vec![], "c0", None);
        c0.signature = "00".repeat(64);
        loader.insert(c0, a0.clone());

        let err = first_parent_log(
            &mut loader,
            project,
            &a0,
            FirstParentLogOptions { limit: Some(10) },
        )
        .await
        .unwrap_err();

        assert!(matches!(err, Error::Invalid("commit signature")));
    }

    #[tokio::test]
    async fn test_project_mismatch_fails() {
        let project1 = uuid::Uuid::new_v4();
        let project2 = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();

        let (c0, a0) = make_commit(project1, vec![], "proj1", None);
        loader.insert(c0, a0.clone());

        let err = first_parent_log(
            &mut loader,
            project2,
            &a0,
            FirstParentLogOptions { limit: Some(10) },
        )
        .await
        .unwrap_err();

        match err {
            Error::Invalid(msg) => assert_eq!(msg, "history commit project mismatch"),
            other => panic!("expected Error::Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_limit_validation_and_budget_exhaustion() {
        let project = uuid::Uuid::new_v4();
        let mut loader = MemoryLoader::new();
        let (c0, a0) = make_commit(project, vec![], "c0", None);
        loader.insert(c0, a0.clone());

        // Limit = 0 fails
        let err0 = first_parent_log(
            &mut loader,
            project,
            &a0,
            FirstParentLogOptions { limit: Some(0) },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err0,
            Error::Limit("history log limit cannot be zero")
        ));

        // Limit = 51 fails
        let err51 = first_parent_log(
            &mut loader,
            project,
            &a0,
            FirstParentLogOptions { limit: Some(51) },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err51,
            Error::Limit("history log limit exceeds maximum of 50")
        ));

        // Envelope budget exhaustion
        let mut huge_loader = MemoryLoader::new();
        let (c_huge, a_huge) = make_commit(project, vec![], "huge", None);
        // Artificially large envelope byte count
        huge_loader.commits.insert(
            a_huge.clone(),
            LoadedEnvelope::new(c_huge, 17 * 1024 * 1024),
        );
        let err_budget = first_parent_log(
            &mut huge_loader,
            project,
            &a_huge,
            FirstParentLogOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err_budget,
            Error::Limit("history log envelope bytes exceeded")
        ));
    }
}
