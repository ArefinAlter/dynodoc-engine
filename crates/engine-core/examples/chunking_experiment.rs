//! H15 chunking experiment (design section 9.6, decision 034). Builds seeded
//! version corpora of synthetic Office packages and large block values, stores
//! every version under each chunking variant, and prints unique stored bytes.
//! cargo run --release -p engine-core --example chunking_experiment -- \
//!   [--mib 25] [--versions 50] [--kinds docx,xlsx,pptx] [--compositions M,B,T]
#[path = "support/office.rs"]
mod office;

use std::collections::HashSet;
use std::time::{Duration, Instant};

use engine_core::ooxml::zip::{central_directory, data_offset, Inflater, ZipLimits};
use engine_core::shared_checkpoint::content::{self, Chunker, Gear};
use engine_core::shared_checkpoint::{Address, Error, Limits, ObjectStore};
use engine_shared::DocumentId;
use office::{Doc, Kind, Save};
use serde_json::{json, Value};

/// Keeps only addresses: enough to count unique stored bytes without the bytes.
#[derive(Default)]
struct Counting {
    seen: HashSet<Address>,
    bytes: u64,
    objects: u64,
}

impl ObjectStore for Counting {
    async fn put(&mut self, _: DocumentId, address: &Address, bytes: &[u8]) -> Result<bool, Error> {
        let new = self.seen.insert(address.clone());
        if new {
            self.bytes += bytes.len() as u64;
            self.objects += 1;
        }
        Ok(new)
    }
    async fn get(&mut self, _: DocumentId, address: &Address) -> Result<Vec<u8>, Error> {
        Err(Error::Missing(address.as_str().to_owned()))
    }
}

#[derive(Default)]
struct Variant {
    store: Counting,
    time: Duration,
    initial: u64,
}

impl Variant {
    fn report(&self, name: &str, logical: u64) -> Value {
        json!({
            "variant": name, "stored_bytes": self.store.bytes, "objects": self.store.objects,
            "initial_bytes": self.initial,
            "added_after_initial": self.store.bytes - self.initial,
            "stored_over_logical": self.store.bytes as f64 / logical as f64,
            "cpu_seconds_per_gb": self.time.as_secs_f64() / (logical as f64 / 1e9),
        })
    }
}

const NAMES: [&str; 7] = [
    "whole-file fixed 64 KiB (v1)",
    "whole-file FastCDC",
    "part-aligned fixed (v2)",
    "part-aligned FastCDC",
    "per-part decompressed fixed (v1)",
    "per-part decompressed FastCDC",
    "per-part decompressed, FastCDC above 8 MiB",
];
const CDC_THRESHOLD: usize = 8 << 20;

fn doc_id() -> DocumentId {
    DocumentId(uuid::Uuid::from_u128(34))
}

async fn timed<F: std::future::Future<Output = Result<(Address, impl Sized), Error>>>(
    time: &mut Duration,
    f: F,
) -> anyhow::Result<()> {
    let start = Instant::now();
    f.await?;
    *time += start.elapsed();
    Ok(())
}

async fn store_package(
    v: &mut [Variant],
    gear: &Gear,
    package: &[u8],
    boundaries: &[u64],
    parts: &[Vec<u8>],
) -> anyhow::Result<()> {
    let d = doc_id();
    let l = Limits {
        max_objects: usize::MAX,
        max_bytes: usize::MAX,
    };
    let [a, b, c, e, f, g, h] = v else {
        anyhow::bail!("variants")
    };
    timed(
        &mut a.time,
        content::write(&mut a.store, d, &mut &*package, l),
    )
    .await?;
    let (input, cdc) = (&mut &*package, Chunker::Cdc(gear));
    timed(
        &mut b.time,
        content::write_v2(&mut b.store, d, input, &[], cdc, l),
    )
    .await?;
    let input = &mut &*package;
    timed(
        &mut c.time,
        content::write_v2(&mut c.store, d, input, boundaries, Chunker::Fixed, l),
    )
    .await?;
    let input = &mut &*package;
    timed(
        &mut e.time,
        content::write_v2(&mut e.store, d, input, boundaries, cdc, l),
    )
    .await?;
    for part in parts {
        timed(
            &mut f.time,
            content::write(&mut f.store, d, &mut part.as_slice(), l),
        )
        .await?;
        let input = &mut part.as_slice();
        timed(
            &mut g.time,
            content::write_v2(&mut g.store, d, input, &[], cdc, l),
        )
        .await?;
        if part.len() > CDC_THRESHOLD {
            let input = &mut part.as_slice();
            timed(
                &mut h.time,
                content::write_v2(&mut h.store, d, input, &[], cdc, l),
            )
            .await?;
        } else {
            timed(
                &mut h.time,
                content::write(&mut h.store, d, &mut part.as_slice(), l),
            )
            .await?;
        }
    }
    Ok(())
}

async fn unpack(package: &[u8]) -> anyhow::Result<(Vec<u64>, Vec<Vec<u8>>)> {
    let mut source = package;
    let entries = central_directory(&mut source, ZipLimits::default()).await?;
    let (mut boundaries, mut parts) = (Vec::new(), Vec::new());
    for entry in &entries {
        let start = data_offset(&mut source, entry).await?;
        boundaries.extend([entry.header_offset, start, start + entry.compressed]);
        let mut part = Vec::with_capacity(entry.size as usize);
        let mut inflater = Inflater::new(entry);
        let data = &package[start as usize..(start + entry.compressed) as usize];
        for piece in data.chunks(1 << 20) {
            inflater.feed(piece, &mut |d| {
                part.extend_from_slice(d);
                Ok(())
            })?;
        }
        if entry.compressed == 0 {
            inflater.feed(&[], &mut |_| Ok(()))?;
        }
        parts.push(part);
    }
    boundaries.sort_unstable();
    Ok((boundaries, parts))
}

async fn package_corpus(
    kind: Kind,
    composition: char,
    mib: u64,
    versions: u64,
    local: bool,
) -> anyhow::Result<Value> {
    let gear = Gear::from_seed(b"chunking-experiment-seed-034....");
    let mut doc = Doc::new(kind, composition, mib << 20, 7);
    let mut v: Vec<Variant> = (0..7).map(|_| Variant::default()).collect();
    let (mut logical, mut first_size, mut xml_share) = (0u64, 0u64, 0f64);
    for version in 0..versions {
        if version > 0 {
            doc.edit_with(version, local);
        }
        let save = Save {
            mimic: true,
            version,
        };
        let (package, _) = office::write(&doc, Vec::new(), save).await?;
        let (boundaries, parts) = unpack(&package).await?;
        if version == 0 {
            first_size = package.len() as u64;
            let total: usize = parts.iter().map(Vec::len).sum();
            let large_xml: usize = parts
                .iter()
                .filter(|p| p.len() > CDC_THRESHOLD && !p.starts_with(b"\x89PNG"))
                .map(Vec::len)
                .sum();
            xml_share = large_xml as f64 / total.max(1) as f64;
        }
        logical += package.len() as u64;
        store_package(&mut v, &gear, &package, &boundaries, &parts).await?;
        if version == 0 {
            for variant in &mut v {
                variant.initial = variant.store.bytes;
            }
        }
    }
    Ok(json!({
        "corpus": format!("{}-{composition}-{mib}MiB-seed7", kind.ext()),
        "generator": office::GENERATOR, "versions": versions,
        "first_package_bytes": first_size, "logical_package_bytes": logical,
        "decompressed_share_in_parts_over_8MiB": xml_share,
        "variants": v.iter().zip(NAMES).map(|(v, n)| v.report(n, logical)).collect::<Vec<_>>(),
    }))
}

/// One large block value (text items joined), edited like a document.
async fn block_corpus(mib: f64, versions: u64, local: bool) -> anyhow::Result<Value> {
    let gear = Gear::from_seed(b"chunking-experiment-seed-034....");
    let target = (mib * 1024.0 * 1024.0) as usize;
    let count = (target / 110).max(10) as u64;
    let mut doc = Doc::new(Kind::Docx, 'T', 0, 11);
    let mut rng = office::Rng::new(11);
    doc.items = (0..count).map(|_| rng.next()).collect();
    let (mut fixed, mut cdc) = (Variant::default(), Variant::default());
    let mut logical = 0u64;
    let l = Limits {
        max_objects: usize::MAX,
        max_bytes: usize::MAX,
    };
    for version in 0..versions {
        if version > 0 {
            doc.edit_with(version, local);
        }
        let value: String = doc.items.iter().map(|s| office::text(*s) + "\n").collect();
        logical += value.len() as u64;
        let input = &mut value.as_bytes();
        timed(
            &mut fixed.time,
            content::write(&mut fixed.store, doc_id(), input, l),
        )
        .await?;
        let input = &mut value.as_bytes();
        let chunker = Chunker::Cdc(&gear);
        timed(
            &mut cdc.time,
            content::write_v2(&mut cdc.store, doc_id(), input, &[], chunker, l),
        )
        .await?;
        if version == 0 {
            fixed.initial = fixed.store.bytes;
            cdc.initial = cdc.store.bytes;
        }
    }
    Ok(json!({
        "corpus": format!("block-{mib}MiB-seed11"), "versions": versions, "logical_bytes": logical,
        "variants": [fixed.report("fixed 64 KiB (v1)", logical), cdc.report("FastCDC (v2)", logical)],
        "fixed_over_cdc": fixed.store.bytes as f64 / cdc.store.bytes as f64,
    }))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str, default: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let mib: u64 = arg("--mib", "25").parse()?;
    let versions: u64 = arg("--versions", "50").parse()?;
    let local = match arg("--edits", "scattered").as_str() {
        "scattered" => false,
        "local" => true,
        other => anyhow::bail!("--edits scattered|local, not {other}"),
    };
    anyhow::ensure!(
        (1..=100).contains(&mib) && (2..=200).contains(&versions),
        "--mib 1-100, --versions 2-200"
    );
    let mut corpora = Vec::new();
    for kind in arg("--kinds", "docx,xlsx,pptx").split(',') {
        let kind = Kind::parse(kind).ok_or_else(|| anyhow::anyhow!("kind {kind}"))?;
        for composition in arg("--compositions", "M,B,T").split(',') {
            let c = composition.chars().next().unwrap_or('B');
            let row = package_corpus(kind, c, mib, versions, local).await?;
            eprintln!("{}", row["corpus"]);
            corpora.push(row);
        }
    }
    let mut blocks = Vec::new();
    for size in arg("--blocks", "0.25,1,8,32").split(',') {
        blocks.push(block_corpus(size.parse()?, versions, local).await?);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "experiment": "H15 chunking (design 9.6)", "generator": office::GENERATOR,
            "cdc_profile": "fastcdc-16k-64k-256k, normalization 2, seeded gear",
            "host_mimic": "parts rotated per version; XML deflate level 6/9/1 by version; media stored, byte-identical unless replaced",
            "edit_script": if local {
                "local: per version 1-20 items inserted at one place and a run of 0.1% of items replaced at another; 1 in 50 versions replaces one media item"
            } else {
                "scattered: per version 1% items replaced, 0.1% inserted, 0.1% deleted at random positions; 1 in 50 versions replaces one media item"
            },
            "packages": corpora, "blocks": blocks,
        }))?
    );
    Ok(())
}
