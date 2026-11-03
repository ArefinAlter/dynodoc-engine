//! History archive transport container and streaming codec (NEXT-25).
//!
//! Magic is `DYNOARC\0\x01`. Frames have a u32 little-endian length prefix and
//! canonical JSON payload (maximum 2 MiB per frame).
//!
//! Frame sequence:
//! 1. Header frame (version, project UUID, selected head)
//! 2. Zero or more Object frames (document UUID, address, base64 canonical object bytes)
//! 3. One or more Commit frames (dependency-first, base64 verified signed-envelope bytes)
//! 4. Footer frame (object count, commit count, bytes before footer, running SHA-256)
#![allow(clippy::manual_is_multiple_of)]

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use engine_shared::DocumentId;
use ring::digest;
use serde::{Deserialize, Serialize};

use super::local::{LocalRepository, ObjectKey, ObjectPacket};
use crate::repository::{SignedCommit, MAX_COMMIT_BYTES};
use crate::shared_checkpoint::{Address, MAX_OBJECT_BYTES};
use crate::transparency::encoding::{b64, hex, unb64};

/// Transport container magic: `DYNOARC\0` + byte 1.
pub const MAGIC: [u8; 9] = *b"DYNOARC\0\x01";

/// Maximum allowed frame length in bytes (2 MiB).
pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// Current archive format version.
pub const ARCHIVE_VERSION_1: u32 = 1;

/// Configurable limits for streaming archive decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_objects: usize,
    pub max_commits: usize,
    pub max_frame_bytes: usize,
    pub max_total_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_commits: 10_000,
            max_frame_bytes: MAX_FRAME_BYTES,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Errors returned by the archive transport codec.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error: {0}")]
    Base64(&'static str),
    #[error("invalid magic: expected DYNOARC\\0\\x01")]
    InvalidMagic,
    #[error("archive limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid archive frame: {0}")]
    InvalidFrame(&'static str),
    #[error("frame ordering violation: {0}")]
    OrderViolation(&'static str),
    #[error("dependency missing: commit {0} depends on unseen {1}")]
    MissingDependency(String, String),
    #[error("footer mismatch: {0}")]
    FooterMismatch(&'static str),
    #[error("unexpected trailing data after footer")]
    TrailingData,
    #[error("unexpected end of file")]
    UnexpectedEof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    Header {
        version: u32,
        project: DocumentId,
        head: Address,
    },
    Object {
        document: DocumentId,
        address: Address,
        data: String,
    },
    Commit {
        address: Address,
        envelope: String,
    },
    Footer {
        objects: u64,
        commits: u64,
        bytes_before_footer: u64,
        sha256: String,
    },
}

/// Summary emitted when an archive is fully read and verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveSummary {
    pub objects: u64,
    pub commits: u64,
    pub bytes_before_footer: u64,
    pub total_bytes: u64,
    pub sha256: String,
    pub head: Address,
    pub project: DocumentId,
}

/// An entry yielded by [`ArchiveReader`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveEntry {
    Header {
        version: u32,
        project: DocumentId,
        head: Address,
    },
    Object {
        document: DocumentId,
        address: Address,
        bytes: Vec<u8>,
    },
    Commit {
        address: Address,
        signed: SignedCommit,
        raw_envelope: Vec<u8>,
    },
    Footer(ArchiveSummary),
}

fn decode_b64(text: &str, max_bytes: usize) -> Result<Vec<u8>, ArchiveError> {
    if text.len() % 4 != 0 {
        return Err(ArchiveError::Base64("length is not a multiple of 4"));
    }
    let est_len = (text.len() / 4) * 3;
    if est_len > max_bytes + 3 {
        return Err(ArchiveError::Limit(
            "base64 payload exceeds maximum allowed size",
        ));
    }
    unb64(text).map_err(|_| ArchiveError::Base64("invalid canonical base64"))
}

fn canonical_frame_bytes(frame: &Frame) -> Result<Vec<u8>, ArchiveError> {
    let val = serde_json::to_value(frame)?;
    let mut out = Vec::new();
    serde_json::to_writer(
        &mut out,
        &crate::shared_checkpoint::canonical::CanonicalValue(&val),
    )?;
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
enum WriterStage {
    ExpectHeader,
    WritingObjectsOrCommits,
    WritingCommits,
    Finished,
}

/// Streaming writer for the `DYNOARC\0\x01` transport container.
pub struct ArchiveWriter<W: Write> {
    writer: W,
    hasher: digest::Context,
    bytes_written: u64,
    objects_count: u64,
    commits_count: u64,
    stage: WriterStage,
    header_info: Option<(DocumentId, Address)>,
    seen_objects: HashSet<(DocumentId, Address)>,
    seen_commits: HashSet<Address>,
    last_commit: Option<Address>,
    limits: ArchiveLimits,
}

impl<W: Write> ArchiveWriter<W> {
    pub fn new(writer: W) -> Result<Self, ArchiveError> {
        Self::with_limits(writer, ArchiveLimits::default())
    }

    pub fn with_limits(mut writer: W, limits: ArchiveLimits) -> Result<Self, ArchiveError> {
        if MAGIC.len() as u64 > limits.max_total_bytes {
            return Err(ArchiveError::Limit(
                "archive exceeds total allowed bytes limit",
            ));
        }
        writer.write_all(&MAGIC)?;
        let mut hasher = digest::Context::new(&digest::SHA256);
        hasher.update(&MAGIC);
        Ok(Self {
            writer,
            hasher,
            bytes_written: MAGIC.len() as u64,
            objects_count: 0,
            commits_count: 0,
            stage: WriterStage::ExpectHeader,
            header_info: None,
            seen_objects: HashSet::new(),
            seen_commits: HashSet::new(),
            last_commit: None,
            limits,
        })
    }

    pub fn write_header(
        &mut self,
        version: u32,
        project: DocumentId,
        head: Address,
    ) -> Result<(), ArchiveError> {
        if self.stage != WriterStage::ExpectHeader {
            return Err(ArchiveError::OrderViolation("header must be written first"));
        }
        if version != ARCHIVE_VERSION_1 {
            return Err(ArchiveError::InvalidFrame("unsupported archive version"));
        }
        let frame = Frame::Header {
            version,
            project,
            head: head.clone(),
        };
        self.write_frame(&frame)?;
        self.header_info = Some((project, head));
        self.stage = WriterStage::WritingObjectsOrCommits;
        Ok(())
    }

    pub fn write_object(
        &mut self,
        document: DocumentId,
        address: Address,
        canonical_bytes: &[u8],
    ) -> Result<(), ArchiveError> {
        if self.stage != WriterStage::WritingObjectsOrCommits {
            return Err(ArchiveError::OrderViolation(
                "objects must be written after header and before any commits",
            ));
        }
        if self.objects_count >= self.limits.max_objects as u64 {
            return Err(ArchiveError::Limit("maximum object count exceeded"));
        }
        crate::shared_checkpoint::validate_stored(&address, canonical_bytes)
            .map_err(|_| ArchiveError::InvalidFrame("invalid object bytes or address mismatch"))?;
        if !self.seen_objects.insert((document, address.clone())) {
            return Err(ArchiveError::InvalidFrame("duplicate object frame"));
        }
        let data = b64(canonical_bytes);
        let frame = Frame::Object {
            document,
            address,
            data,
        };
        self.write_frame(&frame)?;
        self.objects_count += 1;
        Ok(())
    }

    pub fn write_commit(&mut self, signed: &SignedCommit) -> Result<Address, ArchiveError> {
        if self.stage == WriterStage::ExpectHeader || self.stage == WriterStage::Finished {
            return Err(ArchiveError::OrderViolation(
                "cannot write commit in current stage",
            ));
        }
        self.stage = WriterStage::WritingCommits;
        if self.commits_count >= self.limits.max_commits as u64 {
            return Err(ArchiveError::Limit("maximum commit count exceeded"));
        }

        let address = signed
            .verify()
            .map_err(|_| ArchiveError::InvalidFrame("commit signature verification failed"))?;
        if let Some((proj, _)) = self.header_info {
            if signed.commit.project != proj.0 {
                return Err(ArchiveError::InvalidFrame(
                    "commit project mismatch with archive header",
                ));
            }
        }
        for dep in signed.commit.dependencies() {
            if !self.seen_commits.contains(&dep) {
                return Err(ArchiveError::MissingDependency(
                    address.as_str().to_string(),
                    dep.as_str().to_string(),
                ));
            }
        }
        if !self.seen_commits.insert(address.clone()) {
            return Err(ArchiveError::InvalidFrame("duplicate commit frame"));
        }

        let raw_envelope = serde_json::to_vec(signed)?;
        let envelope = b64(&raw_envelope);
        let frame = Frame::Commit {
            address: address.clone(),
            envelope,
        };
        self.write_frame(&frame)?;
        self.commits_count += 1;
        self.last_commit = Some(address.clone());
        Ok(address)
    }

    pub fn finish(mut self) -> Result<ArchiveSummary, ArchiveError> {
        if self.stage != WriterStage::WritingCommits {
            return Err(ArchiveError::OrderViolation(
                "archive must contain at least one commit",
            ));
        }
        let (project, head) = self
            .header_info
            .clone()
            .ok_or(ArchiveError::OrderViolation("missing header"))?;
        if self.last_commit.as_ref() != Some(&head) {
            return Err(ArchiveError::InvalidFrame(
                "last commit does not match header head",
            ));
        }

        let bytes_before_footer = self.bytes_written;
        let digest_bytes = self.hasher.clone().finish();
        let digest_hex = hex(digest_bytes.as_ref());

        let footer_frame = Frame::Footer {
            objects: self.objects_count,
            commits: self.commits_count,
            bytes_before_footer,
            sha256: digest_hex.clone(),
        };

        let footer_bytes = canonical_frame_bytes(&footer_frame)?;
        if footer_bytes.len() > self.limits.max_frame_bytes {
            return Err(ArchiveError::Limit("frame length exceeds maximum limit"));
        }
        let footer_total = 4 + footer_bytes.len() as u64;
        if self.bytes_written + footer_total > self.limits.max_total_bytes {
            return Err(ArchiveError::Limit(
                "archive exceeds total allowed bytes limit",
            ));
        }
        let len_prefix = (footer_bytes.len() as u32).to_le_bytes();
        self.writer.write_all(&len_prefix)?;
        self.writer.write_all(&footer_bytes)?;
        self.bytes_written += footer_total;
        self.writer.flush()?;

        self.stage = WriterStage::Finished;
        Ok(ArchiveSummary {
            objects: self.objects_count,
            commits: self.commits_count,
            bytes_before_footer,
            total_bytes: self.bytes_written,
            sha256: digest_hex,
            head,
            project,
        })
    }

    fn write_frame(&mut self, frame: &Frame) -> Result<(), ArchiveError> {
        let payload = canonical_frame_bytes(frame)?;
        if payload.len() > self.limits.max_frame_bytes {
            return Err(ArchiveError::Limit("frame length exceeds maximum limit"));
        }
        let frame_bytes = 4 + payload.len() as u64;
        if self.bytes_written + frame_bytes > self.limits.max_total_bytes {
            return Err(ArchiveError::Limit(
                "archive exceeds total allowed bytes limit",
            ));
        }
        let len = (payload.len() as u32).to_le_bytes();
        self.writer.write_all(&len)?;
        self.writer.write_all(&payload)?;
        self.hasher.update(&len);
        self.hasher.update(&payload);
        self.bytes_written += frame_bytes;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ReaderStage {
    ExpectMagic,
    ExpectHeader,
    ReadingObjectsOrCommits,
    ReadingCommits,
    ExpectEof,
    Done,
}

/// Streaming reader and validator for the `DYNOARC\0\x01` transport container.
pub struct ArchiveReader<R: Read> {
    reader: R,
    limits: ArchiveLimits,
    hasher: digest::Context,
    bytes_read: u64,
    objects_count: u64,
    commits_count: u64,
    stage: ReaderStage,
    header_info: Option<(DocumentId, Address)>,
    seen_objects: HashSet<(DocumentId, Address)>,
    seen_commits: HashSet<Address>,
    last_commit: Option<Address>,
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(reader: R, limits: ArchiveLimits) -> Self {
        Self {
            reader,
            limits,
            hasher: digest::Context::new(&digest::SHA256),
            bytes_read: 0,
            objects_count: 0,
            commits_count: 0,
            stage: ReaderStage::ExpectMagic,
            header_info: None,
            seen_objects: HashSet::new(),
            seen_commits: HashSet::new(),
            last_commit: None,
        }
    }

    pub fn next_entry(&mut self) -> Result<Option<ArchiveEntry>, ArchiveError> {
        if self.stage == ReaderStage::ExpectMagic {
            let mut magic = [0u8; 9];
            self.read_exact_limited(&mut magic)?;
            if magic != MAGIC {
                return Err(ArchiveError::InvalidMagic);
            }
            self.hasher.update(&magic);
            self.stage = ReaderStage::ExpectHeader;
        }

        if self.stage == ReaderStage::ExpectEof {
            let mut buf = [0u8; 1];
            match self.reader.read(&mut buf) {
                Ok(0) => {
                    self.stage = ReaderStage::Done;
                    return Ok(None);
                }
                Ok(_) => return Err(ArchiveError::TrailingData),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    self.stage = ReaderStage::Done;
                    return Ok(None);
                }
                Err(e) => return Err(ArchiveError::Io(e)),
            }
        }

        if self.stage == ReaderStage::Done {
            return Ok(None);
        }

        let (frame, frame_len_bytes, payload_bytes) = self.read_frame()?;

        match frame {
            Frame::Header {
                version,
                project,
                head,
            } => {
                if self.stage != ReaderStage::ExpectHeader {
                    return Err(ArchiveError::OrderViolation("header frame must be first"));
                }
                if version != ARCHIVE_VERSION_1 {
                    return Err(ArchiveError::InvalidFrame("unsupported archive version"));
                }
                self.hasher.update(&frame_len_bytes);
                self.hasher.update(&payload_bytes);
                self.header_info = Some((project, head.clone()));
                self.stage = ReaderStage::ReadingObjectsOrCommits;
                Ok(Some(ArchiveEntry::Header {
                    version,
                    project,
                    head,
                }))
            }
            Frame::Object {
                document,
                address,
                data,
            } => {
                if self.stage != ReaderStage::ReadingObjectsOrCommits {
                    return Err(ArchiveError::OrderViolation(
                        "objects must appear before commits",
                    ));
                }
                if self.objects_count >= self.limits.max_objects as u64 {
                    return Err(ArchiveError::Limit("maximum object count exceeded"));
                }
                if !self.seen_objects.insert((document, address.clone())) {
                    return Err(ArchiveError::InvalidFrame("duplicate object frame"));
                }
                let raw_bytes = decode_b64(&data, MAX_OBJECT_BYTES)?;
                crate::shared_checkpoint::validate_stored(&address, &raw_bytes).map_err(|_| {
                    ArchiveError::InvalidFrame("invalid object bytes or address mismatch")
                })?;

                self.hasher.update(&frame_len_bytes);
                self.hasher.update(&payload_bytes);
                self.objects_count += 1;
                Ok(Some(ArchiveEntry::Object {
                    document,
                    address,
                    bytes: raw_bytes,
                }))
            }
            Frame::Commit { address, envelope } => {
                if self.stage == ReaderStage::ExpectHeader || self.stage == ReaderStage::ExpectEof {
                    return Err(ArchiveError::OrderViolation(
                        "commit frame in invalid stage",
                    ));
                }
                self.stage = ReaderStage::ReadingCommits;
                if self.commits_count >= self.limits.max_commits as u64 {
                    return Err(ArchiveError::Limit("maximum commit count exceeded"));
                }

                let raw_envelope = decode_b64(&envelope, MAX_COMMIT_BYTES + 1024)?;
                let signed: SignedCommit = serde_json::from_slice(&raw_envelope)?;
                let verified_addr = signed.verify().map_err(|_| {
                    ArchiveError::InvalidFrame("commit signature verification failed")
                })?;
                if verified_addr != address {
                    return Err(ArchiveError::InvalidFrame("commit address mismatch"));
                }
                if let Some((proj, _)) = self.header_info {
                    if signed.commit.project != proj.0 {
                        return Err(ArchiveError::InvalidFrame(
                            "commit project mismatch with archive header",
                        ));
                    }
                }
                for dep in signed.commit.dependencies() {
                    if !self.seen_commits.contains(&dep) {
                        return Err(ArchiveError::MissingDependency(
                            address.as_str().to_string(),
                            dep.as_str().to_string(),
                        ));
                    }
                }
                if !self.seen_commits.insert(address.clone()) {
                    return Err(ArchiveError::InvalidFrame("duplicate commit frame"));
                }
                self.last_commit = Some(address.clone());

                self.hasher.update(&frame_len_bytes);
                self.hasher.update(&payload_bytes);
                self.commits_count += 1;
                Ok(Some(ArchiveEntry::Commit {
                    address,
                    signed,
                    raw_envelope,
                }))
            }
            Frame::Footer {
                objects,
                commits,
                bytes_before_footer,
                sha256: expected_hash,
            } => {
                if self.stage != ReaderStage::ReadingCommits {
                    return Err(ArchiveError::OrderViolation(
                        "footer requires at least one commit and must be the final frame",
                    ));
                }
                let (project, head) = self
                    .header_info
                    .clone()
                    .ok_or(ArchiveError::OrderViolation("missing header"))?;

                if self.last_commit.as_ref() != Some(&head) {
                    return Err(ArchiveError::InvalidFrame(
                        "last commit does not match header head",
                    ));
                }
                if objects != self.objects_count {
                    return Err(ArchiveError::FooterMismatch("object count mismatch"));
                }
                if commits != self.commits_count {
                    return Err(ArchiveError::FooterMismatch("commit count mismatch"));
                }
                let actual_bytes_before_footer = self.bytes_read - 4 - payload_bytes.len() as u64;
                if bytes_before_footer != actual_bytes_before_footer {
                    return Err(ArchiveError::FooterMismatch(
                        "bytes_before_footer offset mismatch",
                    ));
                }

                let actual_hash = hex(self.hasher.clone().finish().as_ref());
                let expected_hash_lower = expected_hash.to_ascii_lowercase();
                if actual_hash != expected_hash_lower {
                    return Err(ArchiveError::FooterMismatch(
                        "SHA-256 integrity digest mismatch",
                    ));
                }

                self.stage = ReaderStage::ExpectEof;
                let summary = ArchiveSummary {
                    objects,
                    commits,
                    bytes_before_footer,
                    total_bytes: self.bytes_read,
                    sha256: actual_hash,
                    head,
                    project,
                };
                Ok(Some(ArchiveEntry::Footer(summary)))
            }
        }
    }

    fn read_frame(&mut self) -> Result<(Frame, [u8; 4], Vec<u8>), ArchiveError> {
        let mut len_bytes = [0u8; 4];
        self.read_exact_limited(&mut len_bytes)?;
        let frame_len = u32::from_le_bytes(len_bytes) as usize;
        if frame_len == 0 {
            return Err(ArchiveError::InvalidFrame("empty frame length 0"));
        }
        if frame_len > self.limits.max_frame_bytes {
            return Err(ArchiveError::Limit("frame length exceeds maximum limit"));
        }

        let mut payload = vec![0u8; frame_len];
        self.read_exact_limited(&mut payload)?;

        // Canonical JSON check: parse into Value and verify re-serialized canonical form matches exactly.
        let val: serde_json::Value = serde_json::from_slice(&payload)?;
        let mut canonical = Vec::with_capacity(payload.len());
        serde_json::to_writer(
            &mut canonical,
            &crate::shared_checkpoint::canonical::CanonicalValue(&val),
        )?;
        if canonical != payload {
            return Err(ArchiveError::InvalidFrame(
                "frame payload is not canonical JSON",
            ));
        }

        let frame: Frame = serde_json::from_value(val)?;
        Ok((frame, len_bytes, payload))
    }

    fn read_exact_limited(&mut self, buf: &mut [u8]) -> Result<(), ArchiveError> {
        if self.bytes_read + buf.len() as u64 > self.limits.max_total_bytes {
            return Err(ArchiveError::Limit(
                "archive exceeds total allowed bytes limit",
            ));
        }
        self.reader.read_exact(buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                ArchiveError::UnexpectedEof
            } else {
                ArchiveError::Io(e)
            }
        })?;
        self.bytes_read += buf.len() as u64;
        Ok(())
    }
}

/// Verify an archive stream offline against an expected head and limits without buffering.
pub fn verify_archive_stream<R: Read>(
    reader: R,
    limits: ArchiveLimits,
    expected_head: Option<&Address>,
    expected_project: Option<DocumentId>,
) -> Result<ArchiveSummary, ArchiveError> {
    let mut reader = ArchiveReader::new(reader, limits);
    let mut summary = None;

    while let Some(entry) = reader.next_entry()? {
        match entry {
            ArchiveEntry::Header { project, head, .. } => {
                if let Some(exp_proj) = expected_project {
                    if project != exp_proj {
                        return Err(ArchiveError::InvalidFrame("archive project mismatch"));
                    }
                }
                if let Some(exp_head) = expected_head {
                    if &head != exp_head {
                        return Err(ArchiveError::InvalidFrame("archive header head mismatch"));
                    }
                }
            }
            ArchiveEntry::Footer(s) => {
                summary = Some(s);
            }
            _ => {}
        }
    }

    summary.ok_or(ArchiveError::UnexpectedEof)
}

/// Export only the selected dependency closure and verified object graphs starting from `head`.
pub async fn export_archive<W: Write>(
    repo: &LocalRepository,
    head: &Address,
    writer: W,
    limits: ArchiveLimits,
) -> Result<ArchiveSummary, ArchiveError> {
    // 1. Dependency-first iterative traversal with explicit visiting / done states
    enum Step {
        Expand(Address),
        Emit(Address),
    }

    let mut stack = vec![Step::Expand(head.clone())];
    let mut visiting = HashSet::new();
    let mut done = HashSet::new();
    let mut ordered_commits = Vec::new();
    let mut file_roots: HashMap<DocumentId, BTreeSet<Address>> = HashMap::new();

    while let Some(step) = stack.pop() {
        match step {
            Step::Expand(addr) => {
                if done.contains(&addr) {
                    continue;
                }
                if visiting.contains(&addr) {
                    return Err(ArchiveError::InvalidFrame(
                        "cycle detected in commit dependencies",
                    ));
                }
                if done.len() + visiting.len() >= limits.max_commits {
                    return Err(ArchiveError::Limit("exceeded maximum commit limit"));
                }
                visiting.insert(addr.clone());
                stack.push(Step::Emit(addr.clone()));

                let signed = repo.commit(&addr).await.map_err(|_| {
                    ArchiveError::InvalidFrame("commit in dependency closure missing")
                })?;
                let verified_addr = signed.verify().map_err(|_| {
                    ArchiveError::InvalidFrame("commit signature verification failed")
                })?;
                if verified_addr != addr {
                    return Err(ArchiveError::InvalidFrame("commit address mismatch"));
                }
                if signed.commit.project != repo.project() {
                    return Err(ArchiveError::InvalidFrame(
                        "commit project mismatch with repository project",
                    ));
                }

                for file_entry in signed.commit.files.values() {
                    file_roots
                        .entry(file_entry.document)
                        .or_default()
                        .insert(file_entry.state.clone());
                }

                let mut deps = signed.commit.dependencies();
                deps.sort();
                for dep in deps.into_iter().rev() {
                    if !done.contains(&dep) {
                        stack.push(Step::Expand(dep));
                    }
                }
            }
            Step::Emit(addr) => {
                visiting.remove(&addr);
                if done.insert(addr.clone()) {
                    ordered_commits.push(addr);
                }
            }
        }
    }

    // 2. Collect scoped object keys using bounded iterative reference walks.
    // Retain only bounded (DocumentId, Address) keys, not object payloads.
    let mut visited_objects: HashSet<(DocumentId, Address)> = HashSet::new();
    let mut scoped_object_keys: Vec<(DocumentId, Address)> = Vec::new();

    let mut sorted_docs: Vec<_> = file_roots.into_iter().collect();
    sorted_docs.sort_by_key(|(doc, _)| doc.0);

    for (doc_id, roots) in sorted_docs {
        for root in roots {
            let mut queue = VecDeque::new();
            if visited_objects.insert((doc_id, root.clone())) {
                if visited_objects.len() > limits.max_objects {
                    return Err(ArchiveError::Limit("exceeded maximum object count"));
                }
                scoped_object_keys.push((doc_id, root.clone()));
                queue.push_back(root);
            }

            while let Some(addr) = queue.pop_front() {
                let packet = repo
                    .object(&ObjectKey {
                        document: doc_id,
                        address: addr.clone(),
                    })
                    .await
                    .map_err(|_| {
                        ArchiveError::InvalidFrame("object in graph missing or corrupt")
                    })?;

                crate::shared_checkpoint::validate_stored(&addr, &packet.bytes)
                    .map_err(|_| ArchiveError::InvalidFrame("object hash mismatch or invalid"))?;

                let mut children = crate::shared_checkpoint::references(&addr, &packet.bytes)
                    .map_err(|_| ArchiveError::InvalidFrame("malformed object references"))?;
                children.sort();

                for child in children {
                    if visited_objects.insert((doc_id, child.clone())) {
                        if visited_objects.len() > limits.max_objects {
                            return Err(ArchiveError::Limit("exceeded maximum object count"));
                        }
                        scoped_object_keys.push((doc_id, child.clone()));
                        queue.push_back(child);
                    }
                }
            }
        }
    }

    // 3. Stream out frames via ArchiveWriter with limits.
    // Read and validate one payload at a time when emitting frames.
    let mut writer = ArchiveWriter::with_limits(writer, limits)?;
    writer.write_header(ARCHIVE_VERSION_1, DocumentId(repo.project()), head.clone())?;

    for (doc_id, addr) in scoped_object_keys {
        let packet = repo
            .object(&ObjectKey {
                document: doc_id,
                address: addr.clone(),
            })
            .await
            .map_err(|_| ArchiveError::InvalidFrame("object in graph missing or corrupt"))?;

        crate::shared_checkpoint::validate_stored(&addr, &packet.bytes)
            .map_err(|_| ArchiveError::InvalidFrame("object hash mismatch or invalid"))?;

        writer.write_object(doc_id, addr, &packet.bytes)?;
    }

    for addr in ordered_commits {
        let signed = repo
            .commit(&addr)
            .await
            .map_err(|_| ArchiveError::InvalidFrame("commit in dependency closure missing"))?;
        writer.write_commit(&signed)?;
    }

    writer.finish()
}

/// Bounded private temporary directory for archive staging.
/// Permissions are 0700 on Unix. Recursively cleaned up on drop.
pub struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    pub fn new() -> io::Result<Self> {
        let path =
            std::env::temp_dir().join(format!("dynodoc-archive-staging-{}", uuid::Uuid::new_v4()));
        super::private_fs::create_private_dir(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A staged object entry verified and saved to bounded temporary disk storage.
#[derive(Debug, Clone)]
pub struct StagedObjectEntry {
    pub document: DocumentId,
    pub address: Address,
    pub path: PathBuf,
    pub size: usize,
}

/// A fully verified archive staged on temporary disk, ready for atomic target import.
pub struct StagedArchive {
    pub summary: ArchiveSummary,
    pub objects: Vec<StagedObjectEntry>,
    pub commits: Vec<SignedCommit>,
    pub staging_dir: Option<PrivateTempDir>,
}

/// Summary emitted when an archive import completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveImportSummary {
    pub head: Address,
    pub objects_imported: usize,
    pub commits_imported: usize,
    pub total_objects: usize,
    pub total_commits: usize,
}

/// Errors returned during archive import.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveImportError {
    #[error("archive validation failed: {0}")]
    Validation(#[from] ArchiveError),
    #[error("target copy failed after importing {objects_imported} objects and {commits_imported} commits: {source}")]
    TargetCopy {
        objects_imported: usize,
        commits_imported: usize,
        #[source]
        source: crate::repository::Error,
    },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Fully verify an offline history archive without keeping staged data.
///
/// An independently obtained expected head anchors integrity. A self-signed
/// archive alone does not establish account authority, timestamps, server
/// freshness or native-format fidelity.
///
/// Requires the exact selected dependency and object closure, full footer,
/// valid signatures and hashes, matching head and project.
/// Private bounded temporary disk is cleaned up on completion or failure.
pub async fn verify_archive<R: Read>(
    reader: R,
    limits: ArchiveLimits,
    expected_head: Option<&Address>,
    expected_project: Option<DocumentId>,
) -> Result<ArchiveSummary, ArchiveError> {
    let staged =
        validate_and_stage_archive(reader, limits, expected_head, expected_project).await?;
    Ok(staged.summary)
}

/// Validate an archive stream and stage its objects into a fresh private temporary directory.
///
/// Verifies magic, frames, hashes, signatures, counts, dependency closure and object graph.
/// All objects and commits must belong to the selected head closure (no extra or missing data).
pub async fn validate_and_stage_archive<R: Read>(
    reader: R,
    limits: ArchiveLimits,
    expected_head: Option<&Address>,
    expected_project: Option<DocumentId>,
) -> Result<StagedArchive, ArchiveError> {
    let staging_dir = PrivateTempDir::new()?;
    validate_and_stage_archive_in(reader, limits, expected_head, expected_project, staging_dir)
        .await
}

/// Validate and stage an archive into the given private temporary directory.
pub async fn validate_and_stage_archive_in<R: Read>(
    reader: R,
    limits: ArchiveLimits,
    expected_head: Option<&Address>,
    expected_project: Option<DocumentId>,
    staging_dir: PrivateTempDir,
) -> Result<StagedArchive, ArchiveError> {
    let mut archive_reader = ArchiveReader::new(reader, limits);
    let objects_dir = staging_dir.path().join("objects");
    super::private_fs::create_private_dir(&objects_dir)?;

    let mut staged_objects: Vec<StagedObjectEntry> = Vec::new();
    let mut staged_commits: Vec<SignedCommit> = Vec::new();
    let mut staged_objects_map: HashMap<(DocumentId, Address), usize> = HashMap::new();
    let mut staged_commits_map: HashMap<Address, usize> = HashMap::new();
    let mut total_staged_bytes: u64 = 0;
    let mut footer_summary = None;

    while let Some(entry) = archive_reader.next_entry()? {
        match entry {
            ArchiveEntry::Header {
                version: _,
                project,
                head,
            } => {
                if let Some(exp_proj) = expected_project {
                    if project != exp_proj {
                        return Err(ArchiveError::InvalidFrame(
                            "archive header project mismatch with expected project",
                        ));
                    }
                }
                if let Some(exp_head) = expected_head {
                    if &head != exp_head {
                        return Err(ArchiveError::InvalidFrame(
                            "archive header head mismatch with expected head",
                        ));
                    }
                }
            }
            ArchiveEntry::Object {
                document,
                address,
                bytes,
            } => {
                total_staged_bytes = total_staged_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or(ArchiveError::Limit("total archive bytes overflow"))?;
                if total_staged_bytes > limits.max_total_bytes {
                    return Err(ArchiveError::Limit("archive exceeds total bytes limit"));
                }
                if staged_objects.len() >= limits.max_objects {
                    return Err(ArchiveError::Limit("maximum object count exceeded"));
                }
                let obj_file = objects_dir.join(format!("{}.bin", staged_objects.len()));
                let mut obj_f = super::private_fs::create_private_file(&obj_file)?;
                use std::io::Write;
                obj_f.write_all(&bytes)?;
                obj_f.sync_all()?;
                staged_objects_map.insert((document, address.clone()), staged_objects.len());
                staged_objects.push(StagedObjectEntry {
                    document,
                    address,
                    path: obj_file,
                    size: bytes.len(),
                });
            }
            ArchiveEntry::Commit {
                address,
                signed,
                raw_envelope: _,
            } => {
                if staged_commits.len() >= limits.max_commits {
                    return Err(ArchiveError::Limit("maximum commit count exceeded"));
                }
                staged_commits_map.insert(address, staged_commits.len());
                staged_commits.push(signed);
            }
            ArchiveEntry::Footer(summary) => {
                footer_summary = Some(summary);
            }
        }
    }

    let summary = footer_summary.ok_or(ArchiveError::UnexpectedEof)?;

    if let Some(exp_head) = expected_head {
        if &summary.head != exp_head {
            return Err(ArchiveError::InvalidFrame(
                "archive footer head mismatch with expected head",
            ));
        }
    }
    if let Some(exp_proj) = expected_project {
        if summary.project != exp_proj {
            return Err(ArchiveError::InvalidFrame(
                "archive footer project mismatch with expected project",
            ));
        }
    }

    // 1. Commit closure verification
    let mut reachable_commits = HashSet::new();
    let mut commit_stack = vec![summary.head.clone()];
    while let Some(addr) = commit_stack.pop() {
        if reachable_commits.insert(addr.clone()) {
            let idx = staged_commits_map.get(&addr).ok_or_else(|| {
                ArchiveError::MissingDependency("commit".into(), addr.as_str().into())
            })?;
            let signed = &staged_commits[*idx];
            for dep in signed.commit.dependencies() {
                if !reachable_commits.contains(&dep) {
                    commit_stack.push(dep);
                }
            }
        }
    }

    if reachable_commits.len() != staged_commits.len() {
        return Err(ArchiveError::InvalidFrame(
            "archive contains extra commits outside the selected dependency closure",
        ));
    }

    // 2. Object graph closure verification
    let mut file_roots: HashMap<DocumentId, HashSet<Address>> = HashMap::new();
    for signed in &staged_commits {
        for file_entry in signed.commit.files.values() {
            file_roots
                .entry(file_entry.document)
                .or_default()
                .insert(file_entry.state.clone());
        }
    }

    let mut reachable_objects: HashSet<(DocumentId, Address)> = HashSet::new();
    let mut sorted_docs: Vec<_> = file_roots.into_iter().collect();
    sorted_docs.sort_by_key(|(doc, _)| doc.0);

    for (doc_id, roots) in sorted_docs {
        let mut obj_stack: Vec<Address> = roots.into_iter().collect();
        while let Some(addr) = obj_stack.pop() {
            if reachable_objects.insert((doc_id, addr.clone())) {
                let idx = staged_objects_map.get(&(doc_id, addr.clone())).ok_or(
                    ArchiveError::InvalidFrame(
                        "object referenced in file graph is missing from archive",
                    ),
                )?;
                let raw_bytes = std::fs::read(&staged_objects[*idx].path)?;
                let children = crate::shared_checkpoint::references(&addr, &raw_bytes)
                    .map_err(|_| ArchiveError::InvalidFrame("malformed object references"))?;
                for child in children {
                    if !reachable_objects.contains(&(doc_id, child.clone())) {
                        obj_stack.push(child);
                    }
                }
            }
        }
    }

    if reachable_objects.len() != staged_objects.len() {
        return Err(ArchiveError::InvalidFrame(
            "archive contains extra objects outside the selected object closure",
        ));
    }

    // 3. Async semantic preflight in a private disposable LocalRepository.
    // Verifies complete typed reconstructions, recovery and merge evidence
    // before touching any destination repository.
    let scratch_db_path = staging_dir.path().join("preflight_scratch.db");
    let scratch_repo = LocalRepository::open(&scratch_db_path, summary.project.0)
        .await
        .map_err(|_| {
            ArchiveError::InvalidFrame("failed to initialize preflight scratch repository")
        })?;

    let mut batch_packets: Vec<ObjectPacket> = Vec::new();
    let mut batch_bytes = 0usize;

    for entry in &staged_objects {
        let bytes = std::fs::read(&entry.path)?;
        batch_bytes += bytes.len();
        batch_packets.push(ObjectPacket {
            key: ObjectKey {
                document: entry.document,
                address: entry.address.clone(),
            },
            bytes,
        });
        if batch_packets.len() >= 64 || batch_bytes >= 800 * 1024 {
            scratch_repo
                .import_objects(&batch_packets)
                .await
                .map_err(|_| ArchiveError::InvalidFrame("preflight object staging failed"))?;
            batch_packets.clear();
            batch_bytes = 0;
        }
    }
    if !batch_packets.is_empty() {
        scratch_repo
            .import_objects(&batch_packets)
            .await
            .map_err(|_| ArchiveError::InvalidFrame("preflight object staging failed"))?;
    }

    for signed in &staged_commits {
        scratch_repo
            .import_commit(signed)
            .await
            .map_err(|e| match e {
                crate::repository::Error::Limit(_) => {
                    ArchiveError::Limit("semantic preflight limit exceeded")
                }
                _ => ArchiveError::InvalidFrame(
                    "archive contains semantically invalid commits or object graphs",
                ),
            })?;
    }

    scratch_repo.close().await;
    let _ = std::fs::remove_file(&scratch_db_path);
    let _ = std::fs::remove_file(staging_dir.path().join("preflight_scratch.db-wal"));
    let _ = std::fs::remove_file(staging_dir.path().join("preflight_scratch.db-shm"));

    Ok(StagedArchive {
        summary,
        objects: staged_objects,
        commits: staged_commits,
        staging_dir: Some(staging_dir),
    })
}

/// Import a verified and staged archive into a local target repository.
///
/// Copies objects in bounded batches and verified commits in dependency-first order.
/// Branches and quotas are never modified.
pub async fn import_archive(
    repo: &LocalRepository,
    staged: &StagedArchive,
) -> Result<ArchiveImportSummary, ArchiveImportError> {
    if staged.summary.project != DocumentId(repo.project()) {
        return Err(ArchiveImportError::Validation(ArchiveError::InvalidFrame(
            "archive project mismatch with target repository",
        )));
    }

    let mut objects_imported = 0usize;
    let mut batch_packets: Vec<ObjectPacket> = Vec::new();
    let mut batch_bytes = 0usize;

    for entry in &staged.objects {
        let bytes = std::fs::read(&entry.path)?;
        if batch_packets.len() >= 64 || batch_bytes + bytes.len() > 800 * 1024 {
            repo.import_objects(&batch_packets).await.map_err(|e| {
                ArchiveImportError::TargetCopy {
                    objects_imported,
                    commits_imported: 0,
                    source: e,
                }
            })?;
            objects_imported += batch_packets.len();
            batch_packets.clear();
            batch_bytes = 0;
        }
        batch_bytes += bytes.len();
        batch_packets.push(ObjectPacket {
            key: ObjectKey {
                document: entry.document,
                address: entry.address.clone(),
            },
            bytes,
        });
    }

    if !batch_packets.is_empty() {
        repo.import_objects(&batch_packets)
            .await
            .map_err(|e| ArchiveImportError::TargetCopy {
                objects_imported,
                commits_imported: 0,
                source: e,
            })?;
        objects_imported += batch_packets.len();
    }

    let mut commits_imported = 0usize;
    for signed in &staged.commits {
        repo.import_commit(signed)
            .await
            .map_err(|e| ArchiveImportError::TargetCopy {
                objects_imported,
                commits_imported,
                source: e,
            })?;
        commits_imported += 1;
    }

    Ok(ArchiveImportSummary {
        head: staged.summary.head.clone(),
        objects_imported,
        commits_imported,
        total_objects: staged.objects.len(),
        total_commits: staged.commits.len(),
    })
}
