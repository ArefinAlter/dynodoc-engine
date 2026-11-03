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

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Read, Write};

use engine_shared::DocumentId;
use ring::digest;
use serde::{Deserialize, Serialize};

use super::local::{LocalRepository, ObjectKey};
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
}

impl<W: Write> ArchiveWriter<W> {
    pub fn new(mut writer: W) -> Result<Self, ArchiveError> {
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
        let len_prefix = (footer_bytes.len() as u32).to_le_bytes();
        self.writer.write_all(&len_prefix)?;
        self.writer.write_all(&footer_bytes)?;
        self.bytes_written += 4 + footer_bytes.len() as u64;
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
        if payload.len() > MAX_FRAME_BYTES {
            return Err(ArchiveError::Limit("frame length exceeds 2 MiB limit"));
        }
        let len = (payload.len() as u32).to_le_bytes();
        self.writer.write_all(&len)?;
        self.writer.write_all(&payload)?;
        self.hasher.update(&len);
        self.hasher.update(&payload);
        self.bytes_written += 4 + payload.len() as u64;
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
    let mut pending = vec![head.clone()];
    let mut visited_commits = HashSet::new();
    let mut commits_by_addr: BTreeMap<Address, SignedCommit> = BTreeMap::new();
    let mut dep_graph: BTreeMap<Address, Vec<Address>> = BTreeMap::new();

    while let Some(addr) = pending.pop() {
        if visited_commits.insert(addr.clone()) {
            if visited_commits.len() > limits.max_commits {
                return Err(ArchiveError::Limit("exceeded maximum commit limit"));
            }
            let signed = repo
                .commit(&addr)
                .await
                .map_err(|_| ArchiveError::InvalidFrame("commit in dependency closure missing"))?;
            let deps = signed.commit.dependencies();
            for dep in &deps {
                if !visited_commits.contains(dep) {
                    pending.push(dep.clone());
                }
            }
            dep_graph.insert(addr.clone(), deps);
            commits_by_addr.insert(addr, signed);
        }
    }

    // Topological sort (dependency-first): dependencies before children, head is last
    let mut ordered_commits = Vec::with_capacity(commits_by_addr.len());
    let mut visited_for_sort = HashSet::new();
    fn sort_visit(
        addr: &Address,
        dep_graph: &BTreeMap<Address, Vec<Address>>,
        commits_by_addr: &BTreeMap<Address, SignedCommit>,
        visited: &mut HashSet<Address>,
        ordered: &mut Vec<SignedCommit>,
    ) {
        if visited.insert(addr.clone()) {
            if let Some(deps) = dep_graph.get(addr) {
                for dep in deps {
                    sort_visit(dep, dep_graph, commits_by_addr, visited, ordered);
                }
            }
            if let Some(c) = commits_by_addr.get(addr) {
                ordered.push(c.clone());
            }
        }
    }
    sort_visit(
        head,
        &dep_graph,
        &commits_by_addr,
        &mut visited_for_sort,
        &mut ordered_commits,
    );

    // Collect file roots across all commits in the closure
    let mut file_roots: std::collections::HashMap<DocumentId, BTreeSet<Address>> =
        std::collections::HashMap::new();
    for c in &ordered_commits {
        for file_entry in c.commit.files.values() {
            file_roots
                .entry(file_entry.document)
                .or_default()
                .insert(file_entry.state.clone());
        }
    }

    // Traverse each file root's object graph
    let mut visited_objects: HashSet<(DocumentId, Address)> = HashSet::new();
    let mut objects_to_export: Vec<(DocumentId, Address, Vec<u8>)> = Vec::new();

    for (doc_id, roots) in file_roots {
        for root in roots {
            let mut stack = vec![root];
            while let Some(addr) = stack.pop() {
                if visited_objects.insert((doc_id, addr.clone())) {
                    if visited_objects.len() > limits.max_objects {
                        return Err(ArchiveError::Limit("exceeded maximum object count"));
                    }
                    let packet = repo
                        .object(&ObjectKey {
                            document: doc_id,
                            address: addr.clone(),
                        })
                        .await
                        .map_err(|_| {
                            ArchiveError::InvalidFrame("object in graph missing or corrupt")
                        })?;

                    crate::shared_checkpoint::validate_stored(&addr, &packet.bytes).map_err(
                        |_| ArchiveError::InvalidFrame("object hash mismatch or invalid"),
                    )?;

                    let children = crate::shared_checkpoint::references(&addr, &packet.bytes)
                        .map_err(|_| ArchiveError::InvalidFrame("malformed object references"))?;

                    for child in children {
                        if !visited_objects.contains(&(doc_id, child.clone())) {
                            stack.push(child);
                        }
                    }

                    objects_to_export.push((doc_id, addr, packet.bytes));
                }
            }
        }
    }

    // Stream out to ArchiveWriter
    let mut writer = ArchiveWriter::new(writer)?;
    writer.write_header(ARCHIVE_VERSION_1, DocumentId(repo.project()), head.clone())?;

    for (doc, addr, bytes) in objects_to_export {
        writer.write_object(doc, addr, &bytes)?;
    }

    for commit in ordered_commits {
        writer.write_commit(&commit)?;
    }

    writer.finish()
}
