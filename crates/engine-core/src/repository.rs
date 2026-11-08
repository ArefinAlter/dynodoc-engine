//! Portable project history, separate from centralized per-file event sequences.
//! Local signatures prove control of a key, not a verified Dynodoc account or
//! permission. Servers must authorize object exchange, actors and ref publication.

use crate::shared_checkpoint::{Address, Error as ObjectError};
use engine_shared::DocumentId;
#[cfg(feature = "persistence")]
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "persistence")]
pub mod archive;
#[cfg(feature = "persistence")]
pub mod attestation;
#[cfg(feature = "persistence")]
pub mod authority_epoch;
#[cfg(feature = "persistence")]
pub mod compare;
#[cfg(feature = "persistence")]
pub mod constraints;
#[cfg(feature = "persistence")]
pub mod convergence;
pub mod device;
#[cfg(feature = "persistence")]
pub mod device_session;
#[cfg(feature = "persistence")]
pub mod horizon;
#[cfg(feature = "persistence")]
pub mod local;
#[cfg(feature = "persistence")]
pub mod log;
#[cfg(feature = "persistence")]
pub mod plan_v2;
#[cfg(feature = "persistence")]
pub mod private_fs;
#[cfg(feature = "persistence")]
pub mod project;
#[cfg(feature = "persistence")]
pub mod project_merge;
#[cfg(feature = "persistence")]
pub mod receipt_journal;
mod records;
#[cfg(feature = "persistence")]
pub mod recovery;
#[cfg(feature = "persistence")]
pub mod relocation;
#[cfg(feature = "persistence")]
pub mod server_authority;
#[cfg(feature = "persistence")]
pub mod state_export;
#[cfg(feature = "persistence")]
pub mod xdoc;
/// The pure build carries only the signed merge record (the merge needs persistence).
#[cfg(not(feature = "persistence"))]
pub mod convergence {
    pub use super::records::{Resolution, MAX_REPORTED_FILES, STRATEGY};
}
/// The pure build carries only the signed recovery source (planning needs persistence).
#[cfg(not(feature = "persistence"))]
pub mod recovery {
    pub use super::records::{Kind, Source};
}

pub const MAX_FILES: usize = 4096;
pub const MAX_COMMIT_BYTES: usize = 1024 * 1024;
pub const MAX_ANCESTORS: usize = 100_000;
const COMMIT_DOMAIN: &[u8] = b"dynodoc.project-commit\0v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"dynodoc.project-commit-signature\0v1\0";
const RECOVERY_COMMIT_DOMAIN: &[u8] = b"dynodoc.project-commit\0v2\0";
const RECOVERY_SIGNATURE_DOMAIN: &[u8] = b"dynodoc.project-commit-signature\0v2\0";
const MERGE_COMMIT_DOMAIN: &[u8] = b"dynodoc.project-commit\0v3\0";
const MERGE_SIGNATURE_DOMAIN: &[u8] = b"dynodoc.project-commit-signature\0v3\0";
// The same v4 domains as the engine-merge work (decision 035 records the coordination).
const PROJECT_COMMIT_DOMAIN: &[u8] = b"dynodoc.project-commit\0v4\0";
const PROJECT_SIGNATURE_DOMAIN: &[u8] = b"dynodoc.project-commit-signature\0v4\0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid repository data: {0}")]
    Invalid(&'static str),
    #[error("repository limit: {0}")]
    Limit(&'static str),
    #[error("branch changed; fetch and compare before retrying")]
    StaleRef,
    #[error("missing commit {0:?}")]
    Missing(Address),
    #[cfg(feature = "persistence")]
    #[error("repository database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("repository encoding: {0}")]
    Json(#[from] serde_json::Error),
    #[error("repository content: {0}")]
    Object(#[from] ObjectError),
    /// The commit was released by history horizon `horizon`; only its address,
    /// parents and height remain (docs/DESIGN-COMMIT-PRUNING.md section 5.5).
    #[error(
        "commit {address:?} was released by history horizon {horizon}; only its skeleton remains"
    )]
    HistoryPruned {
        address: Address,
        horizon: u64,
        parents: Vec<Address>,
        height: u64,
    },
    /// The file state's objects were released by history horizon `horizon`.
    #[error("file state {root:?} was released by history horizon {horizon}")]
    ContentPruned { root: Address, horizon: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub document: DocumentId,
    /// V2 typed state root, not a legacy snapshot or original native file blob.
    pub state: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub version: u8,
    pub project: uuid::Uuid,
    /// Ordered parents preserve the first-parent/mainline distinction. At most two.
    pub parents: Vec<Address>,
    pub files: BTreeMap<String, FileEntry>,
    /// Ed25519 public key, lowercase hexadecimal. Identity binding is external.
    pub author_key: String,
    pub authored_at_ms: i64,
    pub message: String,
    /// V2 only. Recovery references are signed provenance, not merge parents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<recovery::Source>,
    /// V3 only: one record per path merged automatically at node/field level.
    /// Each binds the three input states and the merged result to a named
    /// strategy; paths resolved by explicit choice carry no record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub same_file_resolutions: Vec<convergence::Resolution>,
    // shortcut: the pure (WebAssembly) build has no version 4 records (their checks need
    // the merge-policy registry, over its 400 KiB gzip budget), so it refuses v4 commits.
    /// V4 merges only: one record per automatic project-level decision (rename
    /// follow, node/field merge under the embedded policy, edit follows move).
    #[cfg(feature = "persistence")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub project_resolutions: Vec<project::ProjectResolution>,
    /// V4 one-parent commits only: subtrees moved, copied, split off or joined
    /// between documents, with their deterministic destination identifiers.
    #[cfg(feature = "persistence")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relocations: Vec<relocation::Relocation>,
    /// V4 merges only: the canonical merge policy every record was decided under
    /// and its hash, so `verify-merge` is self-contained (node-conflict design 6.3).
    #[cfg(feature = "persistence")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_policy: Option<project::EmbeddedPolicy>,
    /// V4 commits of encrypted projects only (decision 035): epoch, membership-log head and
    /// the sealed message and path map. Format v4 is shared with the merge records of the
    /// engine-merge work; this is the only E2EE field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<Box<crate::e2ee::commit::Sealed>>,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn unhex(value: &str, size: usize) -> Result<Vec<u8>, Error> {
    if value.len() != size * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid("hex encoding"));
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect())
}

pub fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub fn valid_branch(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_/ .".contains(&b))
        && !name.contains(' ')
        && !name.ends_with('.')
        && !name.contains("..")
}

impl Commit {
    /// Required commit objects for import/transfer. Only `parents` are ancestry;
    /// recovery sources/mainlines are additional provenance dependencies.
    pub fn dependencies(&self) -> Vec<Address> {
        let mut result = self.parents.clone();
        if let Some(source) = &self.recovery {
            for address in std::iter::once(&source.commit).chain(source.mainline.iter()) {
                if !result.contains(address) {
                    result.push(address.clone());
                }
            }
        }
        result
    }

    /// Whether decision 033's records are present, and whether they have a valid shape:
    /// a v4 merge has records and a policy; a v4 one-parent commit relocates.
    #[cfg(feature = "persistence")]
    fn v4_records(&self) -> (bool, bool) {
        let v4 = !self.project_resolutions.is_empty()
            || !self.relocations.is_empty()
            || self.merge_policy.is_some();
        let v4_shape = match self.parents.len() {
            2 => {
                !self.project_resolutions.is_empty()
                    && self.relocations.is_empty()
                    && self.merge_policy.is_some()
            }
            1 => {
                self.project_resolutions.is_empty()
                    && !self.relocations.is_empty()
                    && self.merge_policy.is_none()
            }
            _ => false,
        };
        (v4, v4_shape)
    }

    /// The pure build carries no version 4 records.
    #[cfg(not(feature = "persistence"))]
    fn v4_records(&self) -> (bool, bool) {
        (false, false)
    }

    pub fn validate(&self) -> Result<(), Error> {
        let merged = !self.same_file_resolutions.is_empty();
        let (v4, v4_shape) = self.v4_records();
        let sealed = self.sealed.is_some();
        if !matches!(
            (self.version, &self.recovery, merged, v4, sealed),
            (1, None, false, false, false)
                | (2, Some(_), false, false, false)
                | (3, None, true, false, false)
                // Decision 033's records, optionally sealed (decision 035).
                | (4, None, false, true, _)
                // A sealed commit without them keeps decision 035's shapes.
                | (4, _, _, false, true)
        ) || (self.recovery.is_some() && self.parents.len() != 1)
            || (self.version == 4 && merged && self.parents.len() != 2)
            || (self.version == 3 && self.parents.len() != 2)
            || (self.version == 4 && v4 && !v4_shape)
            || self.project.is_nil()
            || self.parents.len() > 2
            || (self.parents.len() == 2 && self.parents[0] == self.parents[1])
            || self.authored_at_ms < 0
            || self.message.len() > 4096
        {
            return Err(Error::Invalid("commit metadata"));
        }
        unhex(&self.author_key, 32)?;
        if self.files.len() > MAX_FILES {
            return Err(Error::Limit("project files"));
        }
        let mut documents = BTreeSet::new();
        for (path, file) in &self.files {
            if !valid_path(path) || file.document.0.is_nil() || !documents.insert(file.document.0) {
                return Err(Error::Invalid("file path or duplicate document identity"));
            }
            // A logical file cannot simultaneously act as a directory.
            if path
                .match_indices('/')
                .any(|(index, _)| self.files.contains_key(&path[..index]))
            {
                return Err(Error::Invalid("file/directory collision"));
            }
        }
        if let Some(sealed) = &self.sealed {
            sealed
                .validate(self)
                .map_err(|_| Error::Invalid("sealed commit fields"))?;
        }
        if self.same_file_resolutions.len() > convergence::MAX_REPORTED_FILES {
            return Err(Error::Limit("same-file resolutions"));
        }
        let mut resolved = BTreeSet::new();
        for record in &self.same_file_resolutions {
            let file = self
                .files
                .get(&record.path)
                .ok_or(Error::Invalid("same-file resolution path"))?;
            // A real conflict needs both sides to differ from the base and each other.
            if !resolved.insert(&record.path)
                || file.document != record.document
                || file.state != record.merged
                || record.strategy != convergence::STRATEGY
                || record.left == record.right
                || record.base == record.left
                || record.base == record.right
            {
                return Err(Error::Invalid("same-file resolution record"));
            }
        }
        #[cfg(feature = "persistence")]
        if self.version == 4 {
            project::validate(self)?;
        }
        Ok(())
    }

    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        let bytes =
            serde_json::to_vec(&crate::shared_checkpoint::canonical::CanonicalValue(&value))?;
        if bytes.len() > MAX_COMMIT_BYTES {
            return Err(Error::Limit("commit bytes"));
        }
        Ok(bytes)
    }
    pub fn address(&self) -> Result<Address, Error> {
        let domain = match self.version {
            1 => COMMIT_DOMAIN,
            2 => RECOVERY_COMMIT_DOMAIN,
            3 => MERGE_COMMIT_DOMAIN,
            _ => PROJECT_COMMIT_DOMAIN,
        };
        let hash = crate::hashing::sha256(&[domain, &self.bytes()?]);
        Ok(Address::try_from(hex(&hash))?)
    }

    /// The bytes an author's Ed25519 key signs: the version's signature domain and the
    /// commit address. Any signer (a key file, a hardware token, a browser's WebCrypto
    /// key) signs exactly these; `author_key` must already name its public key.
    pub fn signing_message(&self) -> Result<Vec<u8>, Error> {
        let mut message = signature_domain(self.version).to_vec();
        message.extend(unhex(self.address()?.as_str(), 32)?);
        Ok(message)
    }
}

/// An Ed25519 key wherever it is held: in this process (`ring`), on a hardware token
/// (`engine-cli`'s PKCS#11 signer), in a browser. Signatures are plain RFC 8032 ones, so
/// verification never depends on where the key lives.
pub trait Signer {
    /// The 32-byte public key.
    fn public_key_bytes(&self) -> Vec<u8>;
    /// The 64-byte signature of `message`.
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

#[cfg(feature = "persistence")]
impl Signer for Ed25519KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        KeyPair::public_key(self).as_ref().to_vec()
    }
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.sign(message).as_ref().to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCommit {
    pub commit: Commit,
    pub signature: String,
}

#[cfg(feature = "persistence")]
impl SignedCommit {
    pub fn sign(mut commit: Commit, key: &(impl Signer + ?Sized)) -> Result<Self, Error> {
        commit.author_key = hex(&key.public_key_bytes());
        let message = commit.signing_message()?;
        Ok(Self {
            commit,
            signature: hex(&key.sign_message(&message)?),
        })
    }
    pub fn verify(&self) -> Result<Address, Error> {
        let address = self.commit.address()?;
        signature::UnparsedPublicKey::new(&signature::ED25519, unhex(&self.commit.author_key, 32)?)
            .verify(
                &self.commit.signing_message()?,
                &unhex(&self.signature, 64)?,
            )
            .map_err(|_| Error::Invalid("commit signature"))?;
        Ok(address)
    }
}

fn signature_domain(version: u8) -> &'static [u8] {
    match version {
        1 => SIGNATURE_DOMAIN,
        2 => RECOVERY_SIGNATURE_DOMAIN,
        3 => MERGE_SIGNATURE_DOMAIN,
        _ => PROJECT_SIGNATURE_DOMAIN,
    }
}

/// Generation prevents an ABA ref update (A -> B -> A) from satisfying an old CAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub commit: Address,
    pub generation: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn signed(
        project: uuid::Uuid,
        parents: Vec<Address>,
        files: BTreeMap<String, FileEntry>,
        message: &str,
    ) -> SignedCommit {
        SignedCommit::sign(
            Commit {
                sealed: None,
                version: 1,
                project,
                parents,
                files,
                author_key: String::new(),
                authored_at_ms: 1_700_000_000_000,
                message: message.into(),
                recovery: None,
                project_resolutions: Vec::new(),
                relocations: Vec::new(),
                merge_policy: None,
                same_file_resolutions: Vec::new(),
            },
            &Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn signature_binds_repository_parents_files_actor_time_and_message() {
        let project = uuid::Uuid::from_u128(1);
        let original = signed(project, vec![], BTreeMap::new(), "Initial");
        let root = original.verify().unwrap();
        let mut changes = Vec::new();
        let mut changed = original.clone();
        changed.commit.project = uuid::Uuid::from_u128(2);
        changes.push(changed);
        let mut changed = original.clone();
        changed.commit.parents.push(root);
        changes.push(changed);
        let mut changed = original.clone();
        changed.commit.authored_at_ms += 1;
        changes.push(changed);
        let mut changed = original.clone();
        changed.commit.message.push('!');
        changes.push(changed);
        let mut changed = original.clone();
        changed.commit.author_key = "00".repeat(32);
        changes.push(changed);
        for changed in changes {
            assert!(changed.verify().is_err());
        }
        let mut wrong = original;
        wrong.signature = "00".repeat(64);
        assert!(wrong.verify().is_err());
    }
    #[test]
    fn paths_and_branches_are_bounded_relative_identifiers() {
        for bad in ["", "../a", "/a", "a//b", "a/./b", "a\\b", "C:a", "a\nb"] {
            assert!(!valid_path(bad));
        }
        assert!(valid_path("বাংলা/Document.docx"));
        for bad in ["", "/main", "../main", "a//b", "a b", "x..y", "main."] {
            assert!(!valid_branch(bad));
        }
        assert!(valid_branch("review/round-2"));
    }

    #[test]
    fn independent_commit_hash_vector_and_file_identity_constraints() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/project-commit-v1.json")).unwrap();
        let commit: Commit = serde_json::from_value(fixture["commit"].clone()).unwrap();
        assert_eq!(
            commit.bytes().unwrap(),
            fixture["canonical"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            commit.address().unwrap().as_str(),
            fixture["address"].as_str().unwrap()
        );
        let mut changed = commit;
        let entry = FileEntry {
            document: DocumentId(uuid::Uuid::from_u128(1)),
            state: Address::try_from("ab".repeat(32)).unwrap(),
        };
        changed.files.insert("a".into(), entry.clone());
        changed.files.insert(
            "a-else".into(),
            FileEntry {
                document: DocumentId(uuid::Uuid::from_u128(2)),
                ..entry.clone()
            },
        );
        changed.files.insert(
            "a/file".into(),
            FileEntry {
                document: DocumentId(uuid::Uuid::from_u128(3)),
                ..entry.clone()
            },
        );
        assert!(changed.validate().is_err());
        changed.files.remove("a/file");
        changed.files.insert("duplicate".into(), entry);
        assert!(changed.validate().is_err());
    }

    #[test]
    fn independent_v3_vector_binds_same_file_records_without_changing_v1_or_v2() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/project-merge-v3.json")).unwrap();
        let signed: SignedCommit = serde_json::from_value(fixture["signed"].clone()).unwrap();
        assert_eq!(
            signed.commit.bytes().unwrap(),
            fixture["canonical"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            signed.verify().unwrap().as_str(),
            fixture["address"].as_str().unwrap()
        );
        // The public synthetic seed reproduces the independent OpenSSL signature.
        assert_eq!(
            SignedCommit::sign(
                signed.commit.clone(),
                &Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
            )
            .unwrap()
            .signature,
            signed.signature
        );
        // Every provenance field is signed.
        let record = |f: &dyn Fn(&mut convergence::Resolution)| {
            let mut changed = signed.clone();
            f(&mut changed.commit.same_file_resolutions[0]);
            changed
        };
        let other = Address::try_from("66".repeat(32)).unwrap();
        for forged in [
            record(&|r| r.base = other.clone()),
            record(&|r| r.left = other.clone()),
            record(&|r| r.right = other.clone()),
            record(&|r| r.strategy.push('x')),
            record(&|r| r.document = DocumentId(uuid::Uuid::from_u128(9))),
        ] {
            assert!(forged.verify().is_err());
        }
        // Version 3 is exactly: two parents, no recovery, at least one valid record.
        let mut bad = signed.commit.clone();
        bad.version = 1;
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.version = 2;
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.same_file_resolutions.clear();
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.parents.pop();
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.same_file_resolutions[0].merged = other.clone();
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.same_file_resolutions[0].path = "Other.docx".into();
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.same_file_resolutions[0].strategy = "unknown".into();
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.same_file_resolutions[0].right = bad.same_file_resolutions[0].left.clone();
        assert!(bad.validate().is_err());
        bad = signed.commit.clone();
        bad.same_file_resolutions
            .push(bad.same_file_resolutions[0].clone());
        assert!(bad.validate().is_err());
        // The v1 and v2 serializations never mention the new field.
        let v1 = signed_v1_for_serialization();
        assert!(!serde_json::to_string(&v1).unwrap().contains("same_file"));
        let v1_fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/project-commit-v1.json")).unwrap();
        let parsed: Commit = serde_json::from_value(v1_fixture["commit"].clone()).unwrap();
        assert!(parsed.same_file_resolutions.is_empty());
    }

    /// Commit format v4 (decision 033): the independent vectors reproduce, every
    /// field is signed, the version gate holds both ways, and the v1 to v3 vectors
    /// are untouched (their own tests above and in `recovery.rs`).
    #[test]
    fn independent_v4_vectors_bind_relocations_resolutions_and_the_policy() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/project-v4.json")).unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        // Derived identifiers.
        let spec = &fixture["relocation"]["spec"];
        let doc = |v: &serde_json::Value| DocumentId(v.as_str().unwrap().parse().unwrap());
        let s = relocation::Spec {
            kind: relocation::Kind::Split,
            from: relocation::Source {
                document: doc(&spec["from_document"]),
                roots: vec![engine_shared::NodeId(
                    spec["roots"][0].as_str().unwrap().into(),
                )],
            },
            to: relocation::Destination {
                document: doc(&spec["to_document"]),
                parent: engine_shared::NodeId(spec["parent"].as_str().unwrap().into()),
                position: spec["position"].as_str().unwrap().into(),
            },
        };
        assert_eq!(s.id(), fixture["relocation"]["id"].as_str().unwrap());
        for (node, derived) in fixture["relocation"]["dest_ids"].as_object().unwrap() {
            assert_eq!(
                relocation::dest_id(&s.id(), &engine_shared::NodeId(node.clone())).0,
                derived.as_str().unwrap()
            );
        }
        for name in ["split_commit", "merge_commit"] {
            let v = &fixture[name];
            let signed: SignedCommit = serde_json::from_value(v["signed"].clone()).unwrap();
            assert_eq!(signed.commit.version, 4);
            assert_eq!(
                signed.commit.bytes().unwrap(),
                v["canonical"].as_str().unwrap().as_bytes(),
                "{name}"
            );
            assert_eq!(
                signed.verify().unwrap().as_str(),
                v["address"].as_str().unwrap()
            );
            let again = SignedCommit::sign(signed.commit.clone(), &key).unwrap();
            assert_eq!(again.signature, signed.signature);
            // A v4 commit is not a v1, v2 or v3 commit, and the reverse.
            for version in [1, 2, 3, 5] {
                let mut bad = signed.commit.clone();
                bad.version = version;
                assert!(bad.validate().is_err(), "{name} as v{version}");
            }
            // A v4 signature does not verify under another version's domain.
            let mut relabelled = signed.clone();
            relabelled.commit.version = 3;
            assert!(relabelled.verify().is_err());
        }
        let merge: SignedCommit =
            serde_json::from_value(fixture["merge_commit"]["signed"].clone()).unwrap();
        assert_eq!(
            project::resolution_set_hash(&merge.commit),
            fixture["merge_commit"]["resolution_set_hash"]
                .as_str()
                .unwrap()
        );
        assert!(project::needs_review(&merge.commit));
        // Every provenance field of a v4 record is signed.
        let other = Address::try_from("66".repeat(32)).unwrap();
        let resolution = |f: &dyn Fn(&mut project::ProjectResolution)| {
            let mut changed = merge.clone();
            f(&mut changed.commit.project_resolutions[1]);
            changed
        };
        for forged in [
            resolution(&|r| r.left = Some(other.clone())),
            resolution(&|r| r.base = Some(other.clone())),
            resolution(&|r| r.needs_review = false),
            resolution(&|r| r.resolution_set = Some("cd".repeat(32))),
            resolution(&|r| r.follows = Some(project::Parent::Right)),
            resolution(&|r| r.source.as_mut().unwrap().right = Some(other.clone())),
            resolution(&|r| r.relocation = Some("ef".repeat(32))),
        ] {
            assert!(forged.verify().is_err());
        }
        // The embedded policy is signed and must match its hash.
        let mut policy = merge.clone();
        policy.commit.merge_policy.as_mut().unwrap().policy["id"] = serde_json::json!("other");
        assert!(policy.verify().is_err());
        let mut bad = merge.commit.clone();
        bad.merge_policy = None;
        assert!(bad.validate().is_err());
        bad = merge.commit.clone();
        bad.project_resolutions[0].strategy = "dynodoc.project.unknown.v1".into();
        assert!(bad.validate().is_err());
        bad = merge.commit.clone();
        bad.project_resolutions[1].merged = Address::try_from("5a".repeat(32)).unwrap();
        assert!(bad.validate().is_err());
        let split: SignedCommit =
            serde_json::from_value(fixture["split_commit"]["signed"].clone()).unwrap();
        let relocated = |f: &dyn Fn(&mut relocation::Relocation)| {
            let mut changed = split.clone();
            f(&mut changed.commit.relocations[0]);
            changed
        };
        for forged in [
            relocated(&|r| r.count += 1),
            relocated(&|r| r.dest_state_after = other.clone()),
            relocated(&|r| r.source_state_after = Some(other.clone())),
            relocated(&|r| r.to.position.push('x')),
        ] {
            assert!(forged.verify().is_err());
        }
        // An id that is not the derivation of its fields is refused unsigned too.
        let mut bad = split.commit.clone();
        bad.relocations[0].to.position = "b1".into();
        assert!(bad.validate().is_err());
        // A relocation and a merge record cannot share one commit.
        let mut both = merge.commit.clone();
        both.relocations = split.commit.relocations.clone();
        assert!(both.validate().is_err());
        // v1 to v3 serializations never mention the v4 fields.
        let v1 = signed_v1_for_serialization();
        let text = serde_json::to_string(&v1).unwrap();
        for field in ["project_resolutions", "relocations", "merge_policy"] {
            assert!(!text.contains(field));
        }
        let v3: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/project-merge-v3.json")).unwrap();
        let v3: SignedCommit = serde_json::from_value(v3["signed"].clone()).unwrap();
        assert!(v3.commit.project_resolutions.is_empty() && v3.verify().is_ok());
    }

    fn signed_v1_for_serialization() -> Commit {
        signed(uuid::Uuid::from_u128(1), vec![], BTreeMap::new(), "plain").commit
    }
}
