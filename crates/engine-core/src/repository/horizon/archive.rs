//! `dynodoc.history-archive` v1: the cold copy of what a horizon released
//! (docs/DESIGN-COMMIT-PRUNING.md section 5.6, phase P3, decision 032).
//!
//! ```text
//! line 1   : canonical JSON {"kind":"dynodoc.history-archive","project":UUID,"sequence":N,"version":1} LF
//! repeated : kind u8 (1 commit, 2 object) | key length u16 BE | key | body length u64 BE | body
//! trailer  : SHA-256 over every preceding byte (32 bytes) | b"DYNARCEND"
//! ```
//!
//! A commit's key is its address (64 hex digits) and its body the stored signed
//! envelope; an object's key is `document-uuid:address` and its body the logical
//! (uncompressed) object bytes. Commits come first in address order, then objects in
//! `(document, address)` order, so one plan always yields the same bytes. The horizon
//! record commits to the trailer hash and the file length; [`verify`] checks an archive
//! against a record offline, without the repository.
use super::{Archive, Envelope, Error};
use crate::{
    repository::SignedCommit,
    shared_checkpoint::{self, Address},
};
use ring::digest;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::Path,
};

pub const KIND: &str = "dynodoc.history-archive";
/// The design names an "8-byte magic DYNARCEND"; the text is nine bytes and all nine
/// are written (decision 032).
pub const MAGIC: &[u8; 9] = b"DYNARCEND";
const COMMIT: u8 = 1;
const OBJECT: u8 = 2;
const MAX_HEADER: usize = 256;
const MAX_KEY: usize = 128;
const MAX_BODY: u64 = 2 * 1024 * 1024;

fn io(error: std::io::Error) -> Error {
    Error::Repository(format!("history archive: {error}"))
}

fn header(project: uuid::Uuid, sequence: u64) -> Vec<u8> {
    let mut line = format!(
        "{{\"kind\":\"{KIND}\",\"project\":\"{project}\",\"sequence\":{sequence},\"version\":1}}"
    )
    .into_bytes();
    line.push(b'\n');
    line
}

/// Hashing writer; creates the file and refuses to overwrite one.
pub struct ArchiveWriter {
    out: BufWriter<File>,
    hash: digest::Context,
    bytes: u64,
    commits: u64,
    objects: u64,
    last: Option<(u8, Vec<u8>)>,
}

impl ArchiveWriter {
    pub fn create(path: &Path, project: uuid::Uuid, sequence: u64) -> Result<Self, Error> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(io)?;
        let mut writer = Self {
            out: BufWriter::new(file),
            hash: digest::Context::new(&digest::SHA256),
            bytes: 0,
            commits: 0,
            objects: 0,
            last: None,
        };
        writer.put(&header(project, sequence))?;
        Ok(writer)
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.hash.update(bytes);
        self.bytes += bytes.len() as u64;
        self.out.write_all(bytes).map_err(io)
    }

    fn entry(&mut self, kind: u8, key: &[u8], body: &[u8]) -> Result<(), Error> {
        // Commits before objects, each strictly ascending: one order per plan.
        if self
            .last
            .as_ref()
            .is_some_and(|(k, last)| (*k, last.as_slice()) >= (kind, key))
        {
            return Err(Error::Format("history archive entries out of order"));
        }
        if key.len() > MAX_KEY || body.len() as u64 > MAX_BODY {
            return Err(Error::Limit("history archive entry"));
        }
        self.put(&[kind])?;
        self.put(&(key.len() as u16).to_be_bytes())?;
        self.put(key)?;
        self.put(&(body.len() as u64).to_be_bytes())?;
        self.put(body)?;
        self.last = Some((kind, key.to_vec()));
        Ok(())
    }

    pub fn add_commit(&mut self, address: &Address, envelope: &[u8]) -> Result<(), Error> {
        self.commits += 1;
        self.entry(COMMIT, address.as_str().as_bytes(), envelope)
    }

    pub fn add_object(
        &mut self,
        document: uuid::Uuid,
        address: &Address,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.objects += 1;
        self.entry(
            OBJECT,
            format!("{document}:{}", address.as_str()).as_bytes(),
            bytes,
        )
    }

    /// Write the trailer, flush and fsync. Returns the record's `archive` field.
    pub fn finish(mut self) -> Result<Archive, Error> {
        let sum = self.hash.clone().finish();
        self.out.write_all(sum.as_ref()).map_err(io)?;
        self.out.write_all(MAGIC).map_err(io)?;
        self.out.flush().map_err(io)?;
        self.out.get_ref().sync_all().map_err(io)?;
        Ok(Archive {
            sha256: super::address_of(
                &sum.as_ref()
                    .try_into()
                    .map_err(|_| Error::Format("sha256"))?,
            ),
            bytes: self.bytes + 32 + MAGIC.len() as u64,
            commits: self.commits,
            objects: self.objects,
        })
    }
}

/// One verified archive entry.
#[derive(Debug, PartialEq, Eq)]
pub enum Entry {
    Commit {
        address: Address,
        envelope: Vec<u8>,
    },
    Object {
        document: uuid::Uuid,
        address: Address,
        bytes: Vec<u8>,
    },
}

/// Streaming reader. Every entry is checked (a commit's signature and address, an
/// object's hash) as it is read; [`ArchiveReader::finish`] checks the trailer, so a
/// caller must not commit anything it read before `finish` succeeds.
pub struct ArchiveReader {
    input: BufReader<File>,
    hash: digest::Context,
    bytes: u64,
    total: u64,
    pub project: uuid::Uuid,
    pub sequence: u64,
    commits: u64,
    objects: u64,
    last: Option<(u8, Vec<u8>)>,
}

impl ArchiveReader {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(io)?;
        let total = file.metadata().map_err(io)?.len();
        let mut input = BufReader::new(file);
        let mut line = Vec::new();
        (&mut input)
            .take(MAX_HEADER as u64)
            .read_until(b'\n', &mut line)
            .map_err(io)?;
        if line.last() != Some(&b'\n') {
            return Err(Error::Format("history archive header"));
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Header {
            kind: String,
            project: uuid::Uuid,
            sequence: u64,
            version: u8,
        }
        let parsed: Header = serde_json::from_slice(&line[..line.len() - 1])
            .map_err(|_| Error::Format("history archive header"))?;
        if parsed.kind != KIND
            || parsed.version != 1
            || header(parsed.project, parsed.sequence) != line
        {
            return Err(Error::Format("history archive header"));
        }
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(&line);
        Ok(Self {
            input,
            hash,
            bytes: line.len() as u64,
            total,
            project: parsed.project,
            sequence: parsed.sequence,
            commits: 0,
            objects: 0,
            last: None,
        })
    }

    fn take(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        let mut buffer = vec![0; n];
        self.input.read_exact(&mut buffer).map_err(io)?;
        self.hash.update(&buffer);
        self.bytes += n as u64;
        Ok(buffer)
    }

    /// The next entry, or `None` when only the trailer is left.
    pub fn next_entry(&mut self) -> Result<Option<Entry>, Error> {
        let trailer = 32 + MAGIC.len() as u64;
        if self.bytes + trailer == self.total {
            return Ok(None);
        }
        if self.bytes + trailer > self.total {
            return Err(Error::Format("history archive is truncated"));
        }
        let kind = self.take(1)?[0];
        let key_len = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| Error::Format("key length"))?,
        ) as usize;
        if key_len > MAX_KEY {
            return Err(Error::Limit("history archive key"));
        }
        let key = self.take(key_len)?;
        let body_len = u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| Error::Format("body length"))?,
        );
        if body_len > MAX_BODY || self.bytes + body_len + trailer > self.total {
            return Err(Error::Limit("history archive body"));
        }
        let body = self.take(body_len as usize)?;
        if self
            .last
            .as_ref()
            .is_some_and(|(k, last)| (*k, last.as_slice()) >= (kind, key.as_slice()))
        {
            return Err(Error::Format("history archive entries out of order"));
        }
        self.last = Some((kind, key.clone()));
        let key = String::from_utf8(key).map_err(|_| Error::Format("history archive key"))?;
        match kind {
            COMMIT => {
                let address = Address::try_from(key)?;
                let signed: SignedCommit = serde_json::from_slice(&body)
                    .map_err(|_| Error::Format("archived commit envelope"))?;
                if signed.verify()? != address
                    || signed.commit.project != self.project
                    || serde_json::to_vec(&signed)? != body
                {
                    return Err(Error::Format("archived commit address, scope or encoding"));
                }
                self.commits += 1;
                Ok(Some(Entry::Commit {
                    address,
                    envelope: body,
                }))
            }
            OBJECT => {
                let (document, address) = key
                    .split_once(':')
                    .ok_or(Error::Format("archived object key"))?;
                let document = uuid::Uuid::parse_str(document)
                    .map_err(|_| Error::Format("archived object key"))?;
                let address = Address::try_from(address.to_owned())?;
                shared_checkpoint::validate_stored(&address, &body)?;
                self.objects += 1;
                Ok(Some(Entry::Object {
                    document,
                    address,
                    bytes: body,
                }))
            }
            _ => Err(Error::Format("history archive entry kind")),
        }
    }

    /// Check the trailer after the last entry and return what the record must say.
    pub fn finish(mut self) -> Result<Archive, Error> {
        if self.next_entry()?.is_some() {
            return Err(Error::Format("history archive has entries after the end"));
        }
        let sum = self.hash.clone().finish();
        let mut trailer = vec![0; 32 + MAGIC.len()];
        self.input.read_exact(&mut trailer).map_err(io)?;
        if &trailer[..32] != sum.as_ref() || &trailer[32..] != MAGIC {
            return Err(Error::Format(
                "history archive trailer does not match its content",
            ));
        }
        Ok(Archive {
            sha256: super::address_of(
                &sum.as_ref()
                    .try_into()
                    .map_err(|_| Error::Format("sha256"))?,
            ),
            bytes: self.total,
            commits: self.commits,
            objects: self.objects,
        })
    }
}

/// Offline check of an archive against the record it belongs to: header, every entry,
/// the trailer, and the hash, length and counts the record committed to. Signatures on
/// the envelope are a separate check ([`Envelope::verify`]).
pub fn verify(path: &Path, envelope: &Envelope) -> Result<Archive, Error> {
    let record = &envelope.horizon;
    let expected = record
        .archive
        .as_ref()
        .ok_or(Error::Format("the horizon record names no archive"))?;
    let mut reader = ArchiveReader::open(path)?;
    if reader.project != record.project || reader.sequence != record.sequence {
        return Err(Error::Format("history archive belongs to another horizon"));
    }
    while reader.next_entry()?.is_some() {}
    let found = reader.finish()?;
    if &found != expected {
        return Err(Error::Format(
            "history archive differs from the horizon record",
        ));
    }
    Ok(found)
}
