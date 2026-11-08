//! Bounded zip (OPC package) reading and streaming writing for server ingest,
//! streaming export and the large-file corpus (decision 034). Stored and deflated
//! entries only; zip64, encryption, multi-disk archives and duplicate or unsafe
//! names are refused.

use std::future::Future;

use miniz_oxide::deflate::core::{create_comp_flags_from_zip_params, CompressorOxide};
use miniz_oxide::inflate::stream::InflateState;
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::OoxmlError;

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
/// The end record plus the largest comment it may carry.
const END_SEARCH: u64 = 22 + 65_535;

/// Parser budget (design section 7: at most 100,000 entries, 100:1 expansion,
/// 2 GiB per part).
#[derive(Debug, Clone, Copy)]
pub struct ZipLimits {
    pub max_entries: usize,
    pub max_central_bytes: u64,
    pub max_ratio: u64,
    pub max_entry_bytes: u64,
}

impl Default for ZipLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_central_bytes: 16 << 20,
            max_ratio: 100,
            max_entry_bytes: 2 << 30,
        }
    }
}

/// One entry of the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub method: u16,
    pub crc: u32,
    pub compressed: u64,
    pub size: u64,
    pub header_offset: u64,
}

/// Random access to a staged package.
pub trait Source: Send {
    /// Total package bytes.
    fn size(&self) -> u64;
    /// Exactly `len` bytes at `offset`, or an error.
    fn read_at(
        &mut self,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<Vec<u8>, OoxmlError>> + Send;
}

impl Source for &[u8] {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    async fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, OoxmlError> {
        let start = usize::try_from(offset).map_err(|_| OoxmlError::Zip("offset"))?;
        self.get(start..start.saturating_add(len))
            .map(<[u8]>::to_vec)
            .ok_or(OoxmlError::Zip("truncated package"))
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && !name.contains(':')
        && !name.split('/').any(|part| part == ".." || part == ".")
}

/// Read and check the central directory. Entry data is not touched.
pub async fn central_directory<S: Source>(
    source: &mut S,
    limits: ZipLimits,
) -> Result<Vec<Entry>, OoxmlError> {
    let len = source.size();
    if len < 22 {
        return Err(OoxmlError::Zip("not a zip package"));
    }
    let tail_start = len.saturating_sub(END_SEARCH);
    let tail = source
        .read_at(tail_start, (len - tail_start) as usize)
        .await?;
    let at = (0..=tail.len() - 22)
        .rev()
        .find(|i| u32_at(&tail, *i) == END)
        .ok_or(OoxmlError::Zip("no end of central directory"))?;
    let end = &tail[at..];
    let (disk, start_disk) = (u16_at(end, 4), u16_at(end, 6));
    let (count, total) = (u16_at(end, 8) as usize, u16_at(end, 10) as usize);
    let (size, offset) = (u32_at(end, 12) as u64, u32_at(end, 16) as u64);
    if disk != 0 || start_disk != 0 || count != total {
        return Err(OoxmlError::Zip("multi-disk archive"));
    }
    if count == 0xffff || size == 0xffff_ffff || offset == 0xffff_ffff {
        return Err(OoxmlError::Zip("zip64 is not supported"));
    }
    if count > limits.max_entries || size > limits.max_central_bytes {
        return Err(OoxmlError::Limit("zip entries"));
    }
    if offset + size > tail_start + at as u64 {
        return Err(OoxmlError::Zip("central directory bounds"));
    }
    let directory = source.read_at(offset, size as usize).await?;
    let mut entries = Vec::with_capacity(count);
    let mut names = std::collections::BTreeSet::new();
    let mut at = 0usize;
    for _ in 0..count {
        if directory.len() < at + 46 || u32_at(&directory, at) != CENTRAL {
            return Err(OoxmlError::Zip("central directory record"));
        }
        let record = &directory[at..];
        let flags = u16_at(record, 8);
        let method = u16_at(record, 10);
        let crc = u32_at(record, 16);
        let compressed = u32_at(record, 20) as u64;
        let size = u32_at(record, 24) as u64;
        let (name_len, extra_len, comment_len) = (
            u16_at(record, 28) as usize,
            u16_at(record, 30) as usize,
            u16_at(record, 32) as usize,
        );
        let header_offset = u32_at(record, 42) as u64;
        let next = 46 + name_len + extra_len + comment_len;
        if record.len() < next {
            return Err(OoxmlError::Zip("central directory record"));
        }
        if flags & 1 != 0 {
            return Err(OoxmlError::Zip("encrypted entry"));
        }
        if compressed == 0xffff_ffff || size == 0xffff_ffff || header_offset == 0xffff_ffff {
            return Err(OoxmlError::Zip("zip64 is not supported"));
        }
        if !matches!(method, 0 | 8) {
            return Err(OoxmlError::Zip("unsupported compression method"));
        }
        let name = std::str::from_utf8(&record[46..46 + name_len])
            .map_err(|_| OoxmlError::Zip("entry name encoding"))?
            .to_owned();
        if !safe_name(&name) || !names.insert(name.to_ascii_lowercase()) {
            return Err(OoxmlError::Zip("unsafe or duplicate entry name"));
        }
        if size > limits.max_entry_bytes
            || size > compressed.saturating_mul(limits.max_ratio).max(1 << 20)
            || (method == 0 && size != compressed)
        {
            return Err(OoxmlError::Limit("zip entry expansion"));
        }
        if header_offset + 30 + compressed > offset {
            return Err(OoxmlError::Zip("entry bounds"));
        }
        entries.push(Entry {
            name,
            method,
            crc,
            compressed,
            size,
            header_offset,
        });
        at += next;
    }
    Ok(entries)
}

/// Offset of an entry's data, after its local header.
pub async fn data_offset<S: Source>(source: &mut S, entry: &Entry) -> Result<u64, OoxmlError> {
    let header = source.read_at(entry.header_offset, 30).await?;
    if header.len() != 30 || u32_at(&header, 0) != LOCAL {
        return Err(OoxmlError::Zip("local header"));
    }
    Ok(entry.header_offset + 30 + u16_at(&header, 26) as u64 + u16_at(&header, 28) as u64)
}

/// Streaming inflation of one entry with its declared size and CRC enforced.
pub struct Inflater {
    state: Option<Box<InflateState>>,
    remaining_in: u64,
    count: Count,
}

struct Count {
    produced: u64,
    expected: u64,
    crc: u32,
    expected_crc: u32,
}

impl Count {
    fn emit(
        &mut self,
        data: &[u8],
        out: &mut impl FnMut(&[u8]) -> Result<(), OoxmlError>,
    ) -> Result<(), OoxmlError> {
        self.produced += data.len() as u64;
        if self.produced > self.expected {
            return Err(OoxmlError::Limit("zip entry expansion"));
        }
        self.crc = crc32(self.crc, data);
        if data.is_empty() {
            return Ok(());
        }
        out(data)
    }

    fn end(&self) -> Result<(), OoxmlError> {
        if self.produced != self.expected || self.crc != self.expected_crc {
            return Err(OoxmlError::Zip("entry size or CRC"));
        }
        Ok(())
    }
}

impl Inflater {
    pub fn new(entry: &Entry) -> Self {
        Self {
            state: (entry.method == 8).then(|| InflateState::new_boxed(DataFormat::Raw)),
            remaining_in: entry.compressed,
            count: Count {
                produced: 0,
                expected: entry.size,
                crc: 0,
                expected_crc: entry.crc,
            },
        }
    }

    /// Compressed bytes still to feed.
    pub fn remaining(&self) -> u64 {
        self.remaining_in
    }

    /// Feed compressed bytes in order; `out` receives each decompressed slice
    /// (at most 64 KiB). Never produces more than the declared size, and checks
    /// the size and CRC after the last byte.
    pub fn feed(
        &mut self,
        mut input: &[u8],
        out: &mut impl FnMut(&[u8]) -> Result<(), OoxmlError>,
    ) -> Result<(), OoxmlError> {
        if input.len() as u64 > self.remaining_in {
            input = &input[..self.remaining_in as usize];
        }
        self.remaining_in -= input.len() as u64;
        let last = self.remaining_in == 0;
        let Some(state) = self.state.as_mut() else {
            for piece in input.chunks(64 * 1024) {
                self.count.emit(piece, out)?;
            }
            return if last { self.count.end() } else { Ok(()) };
        };
        // Never MZFlush::Finish: on a first call miniz then needs the whole output
        // in one buffer. The end of the stream is its own end-of-block marker.
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let result =
                miniz_oxide::inflate::stream::inflate(state, input, &mut buffer, MZFlush::None);
            input = &input[result.bytes_consumed..];
            let written = result.bytes_written;
            self.count.emit(&buffer[..written], out)?;
            let progress = written > 0 || result.bytes_consumed > 0;
            match result.status {
                Ok(MZStatus::StreamEnd) => {
                    if !input.is_empty() || !last {
                        return Err(OoxmlError::Zip("deflate data length"));
                    }
                    return self.count.end();
                }
                Ok(_) if input.is_empty() && !last && written < buffer.len() => return Ok(()),
                Ok(_) if progress => {}
                Err(miniz_oxide::MZError::Buf) if input.is_empty() && !last => return Ok(()),
                Ok(_) | Err(miniz_oxide::MZError::Buf) => {
                    return Err(OoxmlError::Zip("truncated deflate data"))
                }
                Err(_) => return Err(OoxmlError::Zip("corrupt deflate data")),
            }
        }
    }
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Zip CRC-32 (IEEE), continuing from `crc` (0 to start).
pub fn crc32(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for byte in data {
        c = CRC_TABLE[((c ^ *byte as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// Where an entry sits in a written package (the corpus records this).
#[derive(Debug, Clone)]
pub struct Written {
    pub name: String,
    pub header_offset: u64,
    pub data_offset: u64,
    pub data_end: u64,
}

struct Open {
    name: String,
    header_offset: u64,
    data_offset: u64,
    deflate: Option<Box<CompressorOxide>>,
    crc: u32,
    size: u64,
}

/// Streaming zip writer. Each entry is written with a data descriptor
/// (general-purpose bit 3), so CRC and sizes follow the data and nothing is
/// buffered beyond one compression window.
pub struct ZipWriter<W> {
    out: W,
    offset: u64,
    open: Option<Open>,
    central: Vec<u8>,
    written: Vec<Written>,
}

impl<W: AsyncWrite + Unpin> ZipWriter<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            offset: 0,
            open: None,
            central: Vec::new(),
            written: Vec::new(),
        }
    }

    /// Bytes written so far.
    pub fn position(&self) -> u64 {
        self.offset
    }

    async fn put(&mut self, bytes: &[u8]) -> Result<(), OoxmlError> {
        self.out.write_all(bytes).await?;
        self.offset += bytes.len() as u64;
        if self.offset > u32::MAX as u64 {
            return Err(OoxmlError::Limit("package over 4 GiB"));
        }
        Ok(())
    }

    /// Start an entry; `level` 0 stores it, 1-10 deflates it.
    pub async fn start(&mut self, name: &str, level: u8) -> Result<(), OoxmlError> {
        if self.open.is_some() {
            self.finish_entry().await?;
        }
        if !safe_name(name) || self.written.len() >= 0xfffe {
            return Err(OoxmlError::Zip("entry name or count"));
        }
        let method: u16 = if level == 0 { 0 } else { 8 };
        let mut header = Vec::with_capacity(30 + name.len());
        header.extend_from_slice(&LOCAL.to_le_bytes());
        header.extend_from_slice(&20u16.to_le_bytes());
        header.extend_from_slice(&0x0808u16.to_le_bytes()); // descriptor + UTF-8 names
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&[0, 0, 0x21, 0]); // 1980-01-01 00:00, fixed for determinism
        header.extend_from_slice(&[0; 12]);
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(name.as_bytes());
        let header_offset = self.offset;
        self.put(&header).await?;
        self.open = Some(Open {
            name: name.to_owned(),
            header_offset,
            data_offset: self.offset,
            deflate: (level > 0).then(|| {
                Box::new(CompressorOxide::new(create_comp_flags_from_zip_params(
                    i32::from(level.min(10)),
                    -15,
                    0,
                )))
            }),
            crc: 0,
            size: 0,
        });
        Ok(())
    }

    /// Append bytes to the open entry.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), OoxmlError> {
        if data.is_empty() {
            return Ok(());
        }
        self.compress(data, MZFlush::None).await
    }

    async fn compress(&mut self, mut data: &[u8], flush: MZFlush) -> Result<(), OoxmlError> {
        let open = self.open.as_mut().ok_or(OoxmlError::Zip("no open entry"))?;
        open.crc = crc32(open.crc, data);
        open.size += data.len() as u64;
        let Some(mut compressor) = open.deflate.take() else {
            return self.put(data).await;
        };
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let result =
                miniz_oxide::deflate::stream::deflate(&mut compressor, data, &mut buffer, flush);
            data = &data[result.bytes_consumed..];
            let status = result
                .status
                .map_err(|_| OoxmlError::Zip("deflate failed"))?;
            self.put(&buffer[..result.bytes_written]).await?;
            // Without a flush, buffered output stays in the compressor until later.
            if status == MZStatus::StreamEnd || (flush == MZFlush::None && data.is_empty()) {
                break;
            }
        }
        if let Some(open) = self.open.as_mut() {
            open.deflate = Some(compressor);
        }
        Ok(())
    }

    /// Close the open entry with its data descriptor.
    pub async fn finish_entry(&mut self) -> Result<(), OoxmlError> {
        if self.open.as_ref().is_some_and(|o| o.deflate.is_some()) {
            self.compress(&[], MZFlush::Finish).await?;
        }
        let open = self.open.take().ok_or(OoxmlError::Zip("no open entry"))?;
        let compressed = self.offset - open.data_offset;
        if open.size > u32::MAX as u64 {
            return Err(OoxmlError::Limit("entry over 4 GiB"));
        }
        let data_end = self.offset;
        let mut descriptor = Vec::with_capacity(16);
        descriptor.extend_from_slice(&DESCRIPTOR.to_le_bytes());
        descriptor.extend_from_slice(&open.crc.to_le_bytes());
        descriptor.extend_from_slice(&(compressed as u32).to_le_bytes());
        descriptor.extend_from_slice(&(open.size as u32).to_le_bytes());
        self.put(&descriptor).await?;
        let method: u16 = if open.deflate.is_some() { 8 } else { 0 };
        let c = &mut self.central;
        c.extend_from_slice(&CENTRAL.to_le_bytes());
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&0x0808u16.to_le_bytes());
        c.extend_from_slice(&method.to_le_bytes());
        c.extend_from_slice(&[0, 0, 0x21, 0]);
        c.extend_from_slice(&open.crc.to_le_bytes());
        c.extend_from_slice(&(compressed as u32).to_le_bytes());
        c.extend_from_slice(&(open.size as u32).to_le_bytes());
        c.extend_from_slice(&(open.name.len() as u16).to_le_bytes());
        c.extend_from_slice(&[0; 12]);
        c.extend_from_slice(&(open.header_offset as u32).to_le_bytes());
        c.extend_from_slice(open.name.as_bytes());
        self.written.push(Written {
            name: open.name,
            header_offset: open.header_offset,
            data_offset: open.data_offset,
            data_end,
        });
        Ok(())
    }

    /// Write the central directory and return the sink and entry offsets.
    pub async fn finish(mut self) -> Result<(W, Vec<Written>), OoxmlError> {
        if self.open.is_some() {
            self.finish_entry().await?;
        }
        let start = self.offset;
        let central = std::mem::take(&mut self.central);
        self.put(&central).await?;
        let count = self.written.len() as u16;
        let mut end = Vec::with_capacity(22);
        end.extend_from_slice(&END.to_le_bytes());
        end.extend_from_slice(&[0; 4]);
        end.extend_from_slice(&count.to_le_bytes());
        end.extend_from_slice(&count.to_le_bytes());
        end.extend_from_slice(&(central.len() as u32).to_le_bytes());
        end.extend_from_slice(&(start as u32).to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        self.put(&end).await?;
        self.out.flush().await?;
        Ok((self.out, self.written))
    }
}
