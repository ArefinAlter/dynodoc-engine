//! Versioned, streaming byte content for future chunked values and assets.
//!
//! This is an internal storage primitive, not a published checkpoint/commit or an
//! authorization API. Callers authorize the document and own transaction rollback,
//! root publication and staged output. See docs/CHUNKED-CONTENT.md.
//!
//! Version 1 trees use fixed 64 KiB chunks. Version 2 trees (decision 034) allow
//! variable-length chunks of at most 256 KiB, cut by a [`Chunker`]: fixed 64 KiB
//! restarted at forced boundaries (package-aware originals) or FastCDC. Readers
//! accept both; one tree never mixes versions.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Address, Error, Limits, ObjectStore, WriteStats, Writer};
use engine_shared::DocumentId;

pub const CHUNK_BYTES: usize = 64 * 1024;
pub const FANOUT: usize = 128;
pub const MAX_HEIGHT: u8 = 4;
pub(super) const MAGIC: &[u8] = b"DYNOCNT\0";
const DOMAIN: &[u8] = b"dynodoc.content\0v1\0";
const DOMAIN_V2: &[u8] = b"dynodoc.content\0v2\0";
const HEADER: usize = 10;
/// Largest chunk of a version 2 tree (the FastCDC maximum).
pub const MAX_CHUNK_BYTES_V2: usize = 256 * 1024;
/// FastCDC profile `fastcdc-16k-64k-256k`: minimum chunk bytes.
pub const CDC_MIN_BYTES: usize = 16 * 1024;
/// FastCDC profile `fastcdc-16k-64k-256k`: average chunk bytes.
pub const CDC_AVG_BYTES: usize = 64 * 1024;
// Normalization level 2 around a 2^16 average: stricter mask below it, looser above.
const CDC_MASK_SMALL: u64 = !0 << (64 - 18);
const CDC_MASK_LARGE: u64 = !0 << (64 - 14);

#[derive(Debug, Clone)]
struct Reference {
    address: Address,
    length: u64,
}

enum Object<'a> {
    Chunk(&'a [u8]),
    Branch {
        height: u8,
        children: Vec<Reference>,
    },
    Root {
        height: u8,
        child: Reference,
    },
}

fn capacity(height: u8) -> u64 {
    (CHUNK_BYTES as u64) * (FANOUT as u64).pow(height.into())
}

fn capacity_v2(height: u8) -> u64 {
    (MAX_CHUNK_BYTES_V2 as u64) * (FANOUT as u64).pow(height.into())
}

fn height_for(length: u64) -> Result<u8, Error> {
    (0..=MAX_HEIGHT)
        .find(|height| length <= capacity(*height))
        .ok_or(Error::Limit("content tree height"))
}

#[cfg(test)]
fn address(bytes: &[u8]) -> Address {
    address_v(1, bytes)
}

fn address_v(version: u8, bytes: &[u8]) -> Address {
    let domain = if version == 1 { DOMAIN } else { DOMAIN_V2 };
    Address(super::hex(&crate::hashing::sha256(&[domain, bytes])))
}

fn header(version: u8, tag: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&[version, tag]);
    bytes
}

/// A FastCDC gear table. Derived from a per-document secret seed so chunk
/// boundaries cannot be fingerprinted or steered by a chosen input; the seed is
/// needed only to write a version with maximal reuse, never to read (decision 034).
pub struct Gear([u64; 256]);

impl Gear {
    /// Derive the table from a seed (32 random bytes stored with the document).
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut table = [0u64; 256];
        for (i, value) in table.iter_mut().enumerate() {
            let hash = crate::hashing::sha256(&[b"dynodoc.cdc-gear\0v1\0", seed, &[i as u8]]);
            let mut word = [0u8; 8];
            word.copy_from_slice(&hash[..8]);
            *value = u64::from_be_bytes(word);
        }
        Self(table)
    }

    /// Length of the next chunk of `data`: 1..=len for non-empty input. Callers
    /// pass a full [`MAX_CHUNK_BYTES_V2`] window unless the stream or a forced
    /// boundary ends sooner.
    fn cut(&self, data: &[u8]) -> usize {
        let n = data.len();
        if n <= CDC_MIN_BYTES {
            return n;
        }
        let normal = n.min(CDC_AVG_BYTES);
        let end = n.min(MAX_CHUNK_BYTES_V2);
        let mut hash = 0u64;
        for (i, byte) in data.iter().enumerate().take(end).skip(CDC_MIN_BYTES) {
            hash = (hash << 1).wrapping_add(self.0[*byte as usize]);
            let mask = if i < normal {
                CDC_MASK_SMALL
            } else {
                CDC_MASK_LARGE
            };
            if hash & mask == 0 {
                return i + 1;
            }
        }
        end
    }
}

/// How a version 2 writer cuts a stream into chunks.
#[derive(Clone, Copy)]
pub enum Chunker<'a> {
    /// 64 KiB chunks, restarted at each forced boundary.
    Fixed,
    /// FastCDC `fastcdc-16k-64k-256k` with the document's gear table.
    Cdc(&'a Gear),
}

impl Chunker<'_> {
    fn cut(&self, data: &[u8]) -> usize {
        match self {
            Self::Fixed => data.len().min(CHUNK_BYTES),
            Self::Cdc(gear) => gear.cut(data),
        }
    }
}

fn put_address(bytes: &mut Vec<u8>, address: &Address) {
    // Address construction already guarantees 64 lowercase hex characters.
    for pair in address.as_str().as_bytes().chunks_exact(2) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
    }
}

#[allow(
    clippy::expect_used,
    reason = "reference callers pass a checked 40-byte record"
)]
fn reference(bytes: &[u8]) -> Reference {
    Reference {
        address: Address(super::hex(&bytes[..32])),
        length: u64::from_be_bytes(
            bytes[32..40]
                .try_into()
                .expect("reference callers pass a checked 40-byte record"),
        ),
    }
}

#[allow(
    clippy::expect_used,
    reason = "the matching branch checked the header length; the matching branch checked at least 21 bytes"
)]
fn decode<'a>(expected: &Address, bytes: &'a [u8]) -> Result<Object<'a>, Error> {
    let version = bytes.get(8).copied().unwrap_or(0);
    if bytes.len() > HEADER + CHUNK_BYTES
        && (version != 2 || bytes.len() > HEADER + MAX_CHUNK_BYTES_V2)
    {
        return Err(Error::Limit("content object bytes"));
    }
    if bytes.len() < HEADER || !bytes.starts_with(MAGIC) || !matches!(version, 1 | 2) {
        return Err(Error::Invalid("content header or version"));
    }
    if &address_v(version, bytes) != expected {
        return Err(Error::HashMismatch);
    }
    match bytes[9] {
        1 => Ok(Object::Chunk(&bytes[HEADER..])),
        2 if bytes.len() >= 21 => {
            let height = bytes[10];
            let length = u64::from_be_bytes(
                bytes[11..19]
                    .try_into()
                    .expect("the matching branch checked the header length"),
            );
            let count = u16::from_be_bytes(
                bytes[19..21]
                    .try_into()
                    .expect("the matching branch checked at least 21 bytes"),
            ) as usize;
            if height == 0
                || height > MAX_HEIGHT
                || count == 0
                || count > FANOUT
                || bytes.len() != 21 + count * 40
            {
                return Err(Error::Invalid("content branch bounds"));
            }
            let children: Vec<_> = bytes[21..].chunks_exact(40).map(reference).collect();
            let mut total = 0;
            for (index, child) in children.iter().enumerate() {
                // Version 1 packs every child but the last full; version 2 chunks vary.
                let unpacked = if version == 1 {
                    let maximum = capacity(height - 1);
                    child.length > maximum || (index + 1 < count && child.length != maximum)
                } else {
                    child.length > capacity_v2(height - 1)
                };
                if child.length == 0 || unpacked {
                    return Err(Error::Invalid("content branch packing"));
                }
                total += child.length; // bounded by capacity_v2(MAX_HEIGHT), below u64::MAX
            }
            if total != length {
                return Err(Error::Invalid("content branch length"));
            }
            Ok(Object::Branch { height, children })
        }
        3 if bytes.len() == 51 => {
            let height = bytes[10];
            let length = u64::from_be_bytes(
                bytes[11..19]
                    .try_into()
                    .expect("the matching branch checked the header length"),
            );
            let fits = if version == 1 {
                height_for(length)? == height
            } else {
                height <= MAX_HEIGHT && length <= capacity_v2(height)
            };
            if !fits {
                return Err(Error::Invalid("content root height"));
            }
            Ok(Object::Root {
                height,
                child: Reference {
                    address: Address(super::hex(&bytes[19..51])),
                    length,
                },
            })
        }
        _ => Err(Error::Invalid("content object kind or size")),
    }
}

pub(super) fn validate(expected: &Address, bytes: &[u8]) -> Result<(), Error> {
    decode(expected, bytes).map(|_| ())
}

/// Direct child addresses of a verified content object (see `super::references`).
pub(super) fn references(expected: &Address, bytes: &[u8]) -> Result<Vec<Address>, Error> {
    Ok(match decode(expected, bytes)? {
        Object::Chunk(_) => Vec::new(),
        Object::Branch { children, .. } => {
            children.into_iter().map(|child| child.address).collect()
        }
        Object::Root { child, .. } => vec![child.address],
    })
}

struct Builder<'a, 'b, S> {
    writer: &'a mut Writer<'b, S>,
    levels: Vec<Vec<Reference>>,
    version: u8,
}

impl<S: ObjectStore> Builder<'_, '_, S> {
    fn new<'a, 'b>(writer: &'a mut Writer<'b, S>, version: u8) -> Builder<'a, 'b, S> {
        Builder {
            writer,
            levels: (0..=MAX_HEIGHT).map(|_| Vec::new()).collect(),
            version,
        }
    }

    async fn chunk(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut bytes = header(self.version, 1);
        bytes.extend_from_slice(data);
        let address = self
            .writer
            .encoded(address_v(self.version, &bytes), bytes)
            .await?;
        let length = data.len() as u64;
        self.push(0, Reference { address, length }).await
    }

    async fn root(&mut self) -> Result<Address, Error> {
        let (height, child) = self.finish().await?;
        let mut bytes = header(self.version, 3);
        bytes.push(height);
        bytes.extend_from_slice(&child.length.to_be_bytes());
        put_address(&mut bytes, &child.address);
        self.writer
            .encoded(address_v(self.version, &bytes), bytes)
            .await
    }

    async fn branch(&mut self, height: u8, children: &[Reference]) -> Result<Reference, Error> {
        let length = children.iter().map(|child| child.length).sum::<u64>();
        let mut bytes = header(self.version, 2);
        bytes.push(height);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&(children.len() as u16).to_be_bytes());
        for child in children {
            put_address(&mut bytes, &child.address);
            bytes.extend_from_slice(&child.length.to_be_bytes());
        }
        let address = self
            .writer
            .encoded(address_v(self.version, &bytes), bytes)
            .await?;
        Ok(Reference { address, length })
    }

    async fn push(&mut self, mut level: usize, mut child: Reference) -> Result<(), Error> {
        loop {
            if level > MAX_HEIGHT as usize {
                return Err(Error::Limit("content tree height"));
            }
            self.levels[level].push(child);
            if self.levels[level].len() < FANOUT {
                return Ok(());
            }
            if level == MAX_HEIGHT as usize {
                return Err(Error::Limit("content tree height"));
            }
            let children = std::mem::take(&mut self.levels[level]);
            child = self.branch(level as u8 + 1, &children).await?;
            level += 1;
        }
    }

    #[allow(
        clippy::expect_used,
        reason = "the branch checked exactly one reference"
    )]
    async fn finish(&mut self) -> Result<(u8, Reference), Error> {
        for level in 0..=MAX_HEIGHT as usize {
            if self.levels[level].is_empty() {
                continue;
            }
            if self.levels[level].len() == 1 && self.levels[level + 1..].iter().all(Vec::is_empty) {
                return Ok((
                    level as u8,
                    self.levels[level]
                        .pop()
                        .expect("the branch checked exactly one reference"),
                ));
            }
            if level == MAX_HEIGHT as usize {
                return Err(Error::Limit("content tree height"));
            }
            let children = std::mem::take(&mut self.levels[level]);
            let child = self.branch(level as u8 + 1, &children).await?;
            self.push(level + 1, child).await?;
        }
        Err(Error::Invalid("empty content frontier"))
    }
}

/// Store a byte stream with deterministic 64 KiB chunks and a bounded radix
/// frontier. Repeated calls reuse identical objects only within this document.
/// Input errors/budget exhaustion may leave unpublished objects: the caller must
/// own a transaction or staging/cleanup policy. Returning a root does not publish
/// a checkpoint, commit, branch or native asset reference.
pub async fn write<S: ObjectStore, R: AsyncRead + Unpin + Send>(
    store: &mut S,
    document: DocumentId,
    input: &mut R,
    limits: Limits,
) -> Result<(Address, WriteStats), Error> {
    let mut writer = Writer {
        store,
        document,
        budget: limits,
        stats: WriteStats::default(),
        pending: Vec::new(),
        pending_bytes: 0,
    };
    let root = write_with_writer(&mut writer, input).await?;
    writer.flush().await?;
    Ok((root, writer.stats))
}

pub(super) async fn write_with_writer<S: ObjectStore, R: AsyncRead + Unpin + Send>(
    writer: &mut Writer<'_, S>,
    input: &mut R,
) -> Result<Address, Error> {
    let mut builder = Builder::new(writer, 1);
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut first = true;
    loop {
        let mut count = 0;
        while count < CHUNK_BYTES {
            let n = input.read(&mut buffer[count..]).await?;
            if n == 0 {
                break;
            }
            count += n;
        }
        if count == 0 && !first {
            break;
        }
        first = false;
        builder.chunk(&buffer[..count]).await?;
        if count < CHUNK_BYTES {
            break;
        }
    }
    builder.root().await
}

/// Store a byte stream as a version 2 tree. `boundaries` are ascending stream
/// offsets where a chunk must end (for example where each part of an OPC package
/// starts and ends), so bytes after them deduplicate by their own content wherever
/// they sit in the stream. Boundaries and the chunker affect reuse only, never what
/// is read back. Same caller duties as [`write()`].
pub async fn write_v2<S: ObjectStore, R: AsyncRead + Unpin + Send>(
    store: &mut S,
    document: DocumentId,
    input: &mut R,
    boundaries: &[u64],
    chunker: Chunker<'_>,
    limits: Limits,
) -> Result<(Address, WriteStats), Error> {
    let mut writer = Writer {
        store,
        document,
        budget: limits,
        stats: WriteStats::default(),
        pending: Vec::new(),
        pending_bytes: 0,
    };
    let root = write_v2_with_writer(&mut writer, input, boundaries, chunker).await?;
    writer.flush().await?;
    Ok((root, writer.stats))
}

pub(super) async fn write_v2_with_writer<S: ObjectStore, R: AsyncRead + Unpin + Send>(
    writer: &mut Writer<'_, S>,
    input: &mut R,
    boundaries: &[u64],
    chunker: Chunker<'_>,
) -> Result<Address, Error> {
    let mut builder = Builder::new(writer, 2);
    // One maximum chunk is resident: a cut never needs more look-ahead.
    let mut buffer = vec![0; MAX_CHUNK_BYTES_V2];
    let (mut filled, mut position, mut eof, mut emitted) = (0, 0u64, false, false);
    let mut forced = boundaries.iter().copied().peekable();
    loop {
        while !eof && filled < buffer.len() {
            let n = input.read(&mut buffer[filled..]).await?;
            eof = n == 0;
            filled += n;
        }
        if filled == 0 {
            break;
        }
        while forced.next_if(|b| *b <= position).is_some() {}
        let limit = forced
            .peek()
            .map_or(filled, |b| filled.min((b - position) as usize));
        let cut = chunker.cut(&buffer[..limit]);
        builder.chunk(&buffer[..cut]).await?;
        buffer.copy_within(cut..filled, 0);
        filled -= cut;
        position += cut as u64;
        emitted = true;
    }
    if !emitted {
        builder.chunk(&[]).await?;
    }
    builder.root().await
}

async fn get<S: ObjectStore>(
    store: &mut S,
    document: DocumentId,
    address: &Address,
    budget: &mut Limits,
) -> Result<Vec<u8>, Error> {
    if budget.max_objects == 0 {
        return Err(Error::Limit("objects"));
    }
    let bytes = store.get(document, address).await?;
    budget.consume(bytes.len())?;
    Ok(bytes)
}

/// Verify and stream every byte in order. The sink may contain a verified prefix
/// on a later error. Use a temporary/staged sink and publish/apply only on success;
/// this function deliberately does not flush/close a caller-owned sink.
/// The byte budget counts encoded visits, including repeated chunk references.
pub async fn read_into<S: ObjectStore, W: AsyncWrite + Unpin + Send>(
    store: &mut S,
    document: DocumentId,
    root: &Address,
    output: &mut W,
    mut limits: Limits,
) -> Result<u64, Error> {
    read_with_budget(store, document, root, output, &mut limits).await
}

pub(super) async fn read_with_budget<S: ObjectStore, W: AsyncWrite + Unpin + Send>(
    store: &mut S,
    document: DocumentId,
    root: &Address,
    output: &mut W,
    limits: &mut Limits,
) -> Result<u64, Error> {
    let bytes = get(store, document, root, limits).await?;
    let Object::Root { height, child } = decode(root, &bytes)? else {
        return Err(Error::Invalid("expected content root"));
    };
    let version = bytes[8];
    let total = child.length;
    if total > limits.max_bytes as u64 {
        return Err(Error::Limit("bytes"));
    }
    let mut stack = vec![(height, child)];
    while let Some((height, child)) = stack.pop() {
        let bytes = get(store, document, &child.address, limits).await?;
        let object = decode(&child.address, &bytes)?;
        if bytes[8] != version {
            return Err(Error::Invalid("content version mix"));
        }
        match object {
            Object::Chunk(data) if height == 0 && data.len() as u64 == child.length => {
                output.write_all(data).await?;
            }
            Object::Branch {
                height: actual,
                children,
            } if height > 0 && actual == height => {
                if children.iter().map(|entry| entry.length).sum::<u64>() != child.length {
                    return Err(Error::Invalid("content reference length"));
                }
                if stack.len() + children.len() > limits.max_objects {
                    return Err(Error::Limit("objects"));
                }
                stack.extend(children.into_iter().rev().map(|entry| (height - 1, entry)));
            }
            _ => return Err(Error::Invalid("content reference type, height or length")),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_checkpoint::MemoryStore;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use tokio::io::ReadBuf;

    struct Fragmented<'a> {
        bytes: &'a [u8],
        maximum: usize,
    }
    impl AsyncRead for Fragmented<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let n = self.bytes.len().min(output.remaining()).min(self.maximum);
            output.put_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Poll::Ready(Ok(()))
        }
    }

    fn doc() -> DocumentId {
        DocumentId(uuid::Uuid::new_v4())
    }

    async fn roundtrip(bytes: &[u8]) -> (MemoryStore, DocumentId, Address, WriteStats) {
        let mut store = MemoryStore::default();
        let document = doc();
        let (root, stats) = write(&mut store, document, &mut &*bytes, Limits::default())
            .await
            .unwrap();
        let mut output = Vec::new();
        assert_eq!(
            read_into(&mut store, document, &root, &mut output, Limits::default())
                .await
                .unwrap(),
            bytes.len() as u64
        );
        assert_eq!(output, bytes);
        (store, document, root, stats)
    }

    #[tokio::test]
    async fn independent_hash_vectors_pin_the_binary_format() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/content-v1.json")).unwrap();
        for row in fixture["vectors"].as_array().unwrap() {
            let bytes = match row["name"].as_str().unwrap() {
                "empty" => Vec::new(),
                "abc" => b"abc".to_vec(),
                "full" => vec![b'a'; CHUNK_BYTES],
                "two_chunks" => {
                    let mut b = vec![b'a'; CHUNK_BYTES];
                    b.push(b'b');
                    b
                }
                _ => panic!("unexpected vector"),
            };
            let (store, document, root, _) = roundtrip(&bytes).await;
            assert_eq!(root.as_str(), row["root_hash"].as_str().unwrap());
            assert_eq!(bytes.len() as u64, row["length"].as_u64().unwrap());
            for field in ["leaf_hash", "branch_hash"] {
                if let Some(hash) = row[field].as_str() {
                    let encoded = &store.objects[&(document.0, Address(hash.to_owned()))];
                    assert_eq!(address(encoded).as_str(), hash);
                    if field == "branch_hash" {
                        assert_eq!(
                            super::super::hex(encoded),
                            row["branch_hex"].as_str().unwrap()
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn boundaries_and_short_reads_have_identical_roots() {
        for size in [
            0,
            1,
            CHUNK_BYTES - 1,
            CHUNK_BYTES,
            CHUNK_BYTES + 1,
            CHUNK_BYTES * FANOUT - 1,
            CHUNK_BYTES * FANOUT,
            CHUNK_BYTES * FANOUT + 1,
        ] {
            let data: Vec<u8> = (0..size)
                .map(|n| (n.wrapping_mul(131) >> 7) as u8)
                .collect();
            let (mut store, document, root, stats) = roundtrip(&data).await;
            let (again, reused) = write(
                &mut store,
                document,
                &mut Fragmented {
                    bytes: &data,
                    maximum: 731,
                },
                Limits::default(),
            )
            .await
            .unwrap();
            assert_eq!(root, again);
            assert_eq!(reused.new_objects, 0);
            assert_eq!(stats.visited_objects, reused.visited_objects);
            assert!(store
                .objects
                .values()
                .all(|bytes| bytes.len() <= HEADER + CHUNK_BYTES));
        }
    }

    #[tokio::test]
    async fn equal_length_edit_reuses_unaffected_content_and_scopes_documents() {
        let mut data = vec![b'a'; CHUNK_BYTES * 3];
        let (mut store, document, old, _) = roundtrip(&data).await;
        let before = store.stored_bytes();
        data[CHUNK_BYTES + 17] = b'z';
        let (new, stats) = write(
            &mut store,
            document,
            &mut data.as_slice(),
            Limits::default(),
        )
        .await
        .unwrap();
        assert_ne!(old, new);
        assert_eq!(stats.new_objects, 3); // one chunk, one branch, one root
        assert_eq!(
            store.stored_bytes() - before,
            CHUNK_BYTES + HEADER + 21 + 3 * 40 + 51
        );
        let mut output = Vec::new();
        read_into(&mut store, document, &old, &mut output, Limits::default())
            .await
            .unwrap();
        assert_eq!(output, vec![b'a'; data.len()]);
        let other = doc();
        assert!(matches!(
            read_into(
                &mut store,
                other,
                &new,
                &mut tokio::io::sink(),
                Limits::default()
            )
            .await,
            Err(Error::Missing(_))
        ));
        let (other_root, other_stats) =
            write(&mut store, other, &mut data.as_slice(), Limits::default())
                .await
                .unwrap();
        assert_eq!(new, other_root);
        assert_eq!(other_stats.new_objects, 4); // two distinct chunks, branch, root
    }

    #[tokio::test]
    async fn budgets_count_repeated_visits_and_fail_without_returning_a_root() {
        let data = vec![9; CHUNK_BYTES * 2];
        let (mut store, document, root, stats) = roundtrip(&data).await;
        assert_eq!(stats.visited_objects, 4);
        assert_eq!(stats.new_objects, 3);
        for limits in [
            Limits {
                max_objects: 3,
                max_bytes: usize::MAX,
            },
            Limits {
                max_objects: 4,
                max_bytes: stats.encoded_bytes - 1,
            },
        ] {
            assert!(matches!(
                write(&mut store, document, &mut data.as_slice(), limits).await,
                Err(Error::Limit(_))
            ));
            assert!(matches!(
                read_into(&mut store, document, &root, &mut tokio::io::sink(), limits).await,
                Err(Error::Limit(_))
            ));
        }
        let exact = Limits {
            max_objects: 4,
            max_bytes: stats.encoded_bytes,
        };
        read_into(&mut store, document, &root, &mut tokio::io::sink(), exact)
            .await
            .unwrap();
        let (again, _) = write(&mut store, document, &mut data.as_slice(), exact)
            .await
            .unwrap();
        assert_eq!(again, root);
    }

    fn store_raw(store: &mut MemoryStore, document: DocumentId, bytes: Vec<u8>) -> Address {
        let root = address(&bytes);
        store.objects.insert((document.0, root.clone()), bytes);
        root
    }

    #[tokio::test]
    async fn missing_corrupt_and_wrongly_typed_children_fail() {
        let (mut store, document, root, _) = roundtrip(b"abc").await;
        let bytes = store.objects[&(document.0, root.clone())].clone();
        let Object::Root { child, .. } = decode(&root, &bytes).unwrap() else {
            panic!()
        };
        let leaf = store
            .objects
            .remove(&(document.0, child.address.clone()))
            .unwrap();
        assert!(matches!(
            read_into(
                &mut store,
                document,
                &root,
                &mut tokio::io::sink(),
                Limits::default()
            )
            .await,
            Err(Error::Missing(_))
        ));
        store
            .objects
            .insert((document.0, child.address.clone()), b"corrupt".to_vec());
        assert!(read_into(
            &mut store,
            document,
            &root,
            &mut tokio::io::sink(),
            Limits::default()
        )
        .await
        .is_err());
        store
            .objects
            .insert((document.0, child.address.clone()), leaf);
        let mut bad_length = bytes.clone();
        bad_length[18] = 4;
        let bad = store_raw(&mut store, document, bad_length);
        assert!(matches!(
            read_into(
                &mut store,
                document,
                &bad,
                &mut tokio::io::sink(),
                Limits::default()
            )
            .await,
            Err(Error::Invalid(_))
        ));
        let mut wrong_type = bytes;
        wrong_type.truncate(19);
        put_address(&mut wrong_type, &root);
        let bad = store_raw(&mut store, document, wrong_type);
        assert!(matches!(
            read_into(
                &mut store,
                document,
                &bad,
                &mut tokio::io::sink(),
                Limits::default()
            )
            .await,
            Err(Error::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn malformed_and_noncanonical_trees_are_rejected() {
        let (store, document, root, _) = roundtrip(&vec![1; CHUNK_BYTES + 1]).await;
        let root_bytes = &store.objects[&(document.0, root.clone())];
        let Object::Root { child, .. } = decode(&root, root_bytes).unwrap() else {
            panic!()
        };
        let branch = &store.objects[&(document.0, child.address)];
        for offset in [8, 9, 10, 18, 19, 20, 60] {
            let mut mutated = branch.clone();
            mutated[offset] = 255;
            assert!(
                validate(&address(&mutated), &mutated).is_err(),
                "offset {offset}"
            );
        }
        for len in [0, 1, 9, branch.len() - 1] {
            assert!(validate(&address(&branch[..len]), &branch[..len]).is_err());
        }
        let mut tall = root_bytes.clone();
        tall[10] += 1;
        assert!(validate(&address(&tall), &tall).is_err());
        let oversized = vec![0; HEADER + CHUNK_BYTES + 1];
        assert!(matches!(
            validate(&address(&oversized), &oversized),
            Err(Error::Limit(_))
        ));
        let mut wrong_hash = branch.clone();
        wrong_hash[21] ^= 1;
        assert!(matches!(
            validate(&address(branch), &wrong_hash),
            Err(Error::HashMismatch)
        ));
    }

    #[tokio::test]
    async fn input_and_output_failures_propagate() {
        struct Failed;
        impl AsyncRead for Failed {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Err(std::io::Error::other("input failed")))
            }
        }
        assert!(matches!(
            write(
                &mut MemoryStore::default(),
                doc(),
                &mut Failed,
                Limits::default()
            )
            .await,
            Err(Error::Io(_))
        ));
        let (mut store, document, root, _) = roundtrip(b"abc").await;
        let (mut output, peer) = tokio::io::duplex(1);
        drop(peer);
        assert!(matches!(
            read_into(&mut store, document, &root, &mut output, Limits::default()).await,
            Err(Error::Io(_))
        ));
    }

    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    async fn write_v2_mem(
        store: &mut MemoryStore,
        document: DocumentId,
        bytes: &[u8],
        boundaries: &[u64],
        chunker: Chunker<'_>,
    ) -> (Address, WriteStats) {
        let (root, stats) = write_v2(
            store,
            document,
            &mut Fragmented {
                bytes,
                maximum: 70_001,
            },
            boundaries,
            chunker,
            Limits::default(),
        )
        .await
        .unwrap();
        let mut output = Vec::new();
        read_into(store, document, &root, &mut output, Limits::default())
            .await
            .unwrap();
        assert_eq!(output, bytes);
        (root, stats)
    }

    #[tokio::test]
    async fn version_2_trees_round_trip_with_both_chunkers() {
        let gear = Gear::from_seed(&[3; 32]);
        for chunker in [Chunker::Fixed, Chunker::Cdc(&gear)] {
            for size in [
                0,
                1,
                CDC_MIN_BYTES,
                MAX_CHUNK_BYTES_V2,
                MAX_CHUNK_BYTES_V2 + 1,
                9 << 20,
            ] {
                let mut store = MemoryStore::default();
                let data = noise(size as u64, size);
                write_v2_mem(&mut store, doc(), &data, &[], chunker).await;
                assert!(store
                    .objects
                    .values()
                    .all(|bytes| bytes.len() <= HEADER + MAX_CHUNK_BYTES_V2 && bytes[8] == 2));
            }
        }
    }

    #[tokio::test]
    async fn content_defined_chunks_resynchronise_after_an_insertion() {
        let gear = Gear::from_seed(&[9; 32]);
        let data = noise(1, 4 << 20);
        let mut edited = data.clone();
        edited.splice(1 << 20..1 << 20, noise(2, 100));
        let document = doc();
        let mut cdc = MemoryStore::default();
        write_v2_mem(&mut cdc, document, &data, &[], Chunker::Cdc(&gear)).await;
        let (_, stats) = write_v2_mem(&mut cdc, document, &edited, &[], Chunker::Cdc(&gear)).await;
        let mut fixed = MemoryStore::default();
        write_v2_mem(&mut fixed, document, &data, &[], Chunker::Fixed).await;
        let (_, fixed_stats) =
            write_v2_mem(&mut fixed, document, &edited, &[], Chunker::Fixed).await;
        // About two new chunks plus the branch and root, against every chunk after
        // the edit for fixed chunks.
        assert!(stats.new_bytes < 3 * MAX_CHUNK_BYTES_V2, "{stats:?}");
        assert!(fixed_stats.new_bytes > 3 << 20, "{fixed_stats:?}");
        let sizes: Vec<usize> = cdc
            .objects
            .values()
            .filter(|b| b[9] == 1)
            .map(Vec::len)
            .collect();
        assert!(sizes.iter().all(|n| *n <= HEADER + MAX_CHUNK_BYTES_V2));
        assert!(
            sizes
                .iter()
                .filter(|n| **n < HEADER + CDC_MIN_BYTES)
                .count()
                <= 2
        );
    }

    #[tokio::test]
    async fn forced_boundaries_reuse_a_part_wherever_it_sits() {
        let part = noise(5, 1 << 20);
        let document = doc();
        let mut store = MemoryStore::default();
        let mut first = noise(6, 100);
        first.extend_from_slice(&part);
        write_v2_mem(&mut store, document, &first, &[100], Chunker::Fixed).await;
        let mut second = noise(7, 333);
        second.extend_from_slice(&part);
        let (_, stats) = write_v2_mem(&mut store, document, &second, &[333], Chunker::Fixed).await;
        // The new header chunk, the branch and the root; every part chunk is reused.
        assert_eq!(stats.new_objects, 3, "{stats:?}");
    }

    #[tokio::test]
    async fn version_2_objects_are_verified_and_never_mixed_with_version_1() {
        let gear = Gear::from_seed(&[1; 32]);
        let mut store = MemoryStore::default();
        let document = doc();
        let data = noise(8, 300_000);
        let (root, _) = write_v2_mem(&mut store, document, &data, &[], Chunker::Cdc(&gear)).await;
        // A changed chunk byte no longer matches its address.
        let (chunk_address, chunk) = store
            .objects
            .iter()
            .find(|(_, b)| b[9] == 1)
            .map(|((_, a), b)| (a.clone(), b.clone()))
            .unwrap();
        let mut tampered = chunk.clone();
        tampered[HEADER] ^= 1;
        assert!(matches!(
            validate(&chunk_address, &tampered),
            Err(Error::HashMismatch)
        ));
        assert!(matches!(
            read_into(
                &mut store,
                document,
                &root,
                &mut tokio::io::sink(),
                Limits::default()
            )
            .await,
            Ok(300_000)
        ));
        // A version 2 root over a version 1 chunk is refused.
        let mut v1_store = MemoryStore::default();
        let mut chunk_v1 = header(1, 1);
        chunk_v1.extend_from_slice(b"abc");
        let v1_chunk = store_raw(&mut v1_store, document, chunk_v1);
        let mut mixed = header(2, 3);
        mixed.push(0);
        mixed.extend_from_slice(&3u64.to_be_bytes());
        put_address(&mut mixed, &v1_chunk);
        let mixed_root = address_v(2, &mixed);
        v1_store
            .objects
            .insert((document.0, mixed_root.clone()), mixed);
        assert!(matches!(
            read_into(
                &mut v1_store,
                document,
                &mixed_root,
                &mut tokio::io::sink(),
                Limits::default()
            )
            .await,
            Err(Error::Invalid("content version mix"))
        ));
        // Oversized version 2 chunks and version 1 chunks over 64 KiB are limits.
        let mut big = header(2, 1);
        big.extend(vec![0; MAX_CHUNK_BYTES_V2 + 1]);
        assert!(matches!(
            validate(&address_v(2, &big), &big),
            Err(Error::Limit(_))
        ));
        let mut v1_big = header(1, 1);
        v1_big.extend(vec![0; CHUNK_BYTES + 1]);
        assert!(matches!(
            validate(&address(&v1_big), &v1_big),
            Err(Error::Limit(_))
        ));
    }
}
