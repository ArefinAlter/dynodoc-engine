//! Large-file acceptance corpus (design section 5): writes seeded synthetic
//! .docx/.xlsx/.pptx packages, streaming to disk, and a manifest with sizes and
//! SHA-256 per fixture. Many-document projects are `--count N` small fixtures.
//! cargo run --release -p engine-core --example large_file_corpus -- OUT_DIR \
//!   [--kinds docx,xlsx,pptx] [--compositions M,B,T] [--mib 3,25] [--count 1] [--seed 7]
#[path = "support/office.rs"]
mod office;

use office::{Doc, Kind, Save};
use ring::digest::{Context, SHA256};
use serde_json::json;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncWrite, BufWriter};

/// Hashes and counts bytes on their way to the file.
struct Hashing<W> {
    inner: W,
    hash: Context,
    bytes: u64,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Hashing<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.hash.update(&buf[..n]);
            self.bytes += n as u64;
        }
        poll
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let out = PathBuf::from(
        args.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: large_file_corpus OUT_DIR [options]"))?,
    );
    let arg = |name: &str, default: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let seed: u64 = arg("--seed", "7").parse()?;
    let count: u64 = arg("--count", "1").parse()?;
    anyhow::ensure!((1..=10_000).contains(&count), "--count 1-10000");
    std::fs::create_dir_all(&out)?;
    let mut fixtures = Vec::new();
    for kind in arg("--kinds", "docx,xlsx,pptx").split(',') {
        let kind = Kind::parse(kind).ok_or_else(|| anyhow::anyhow!("kind {kind}"))?;
        for composition in arg("--compositions", "M,B,T").split(',') {
            let c = composition.chars().next().unwrap_or('B');
            for mib in arg("--mib", "3,25").split(',') {
                let mib: u64 = mib.parse()?;
                anyhow::ensure!((1..=500).contains(&mib), "--mib 1-500");
                for n in 0..count {
                    let fixture_seed = seed + n;
                    let doc = Doc::new(kind, c, mib << 20, fixture_seed);
                    let suffix = if count > 1 {
                        format!("-{n:04}")
                    } else {
                        String::new()
                    };
                    let name = format!(
                        "{}-{c}-{mib}MiB-seed{seed}{suffix}.{}",
                        kind.ext(),
                        kind.ext()
                    );
                    let file = tokio::fs::File::create(out.join(&name)).await?;
                    let sink = Hashing {
                        inner: BufWriter::with_capacity(1 << 20, file),
                        hash: Context::new(&SHA256),
                        bytes: 0,
                    };
                    let (sink, entries) = office::write(
                        &doc,
                        sink,
                        Save {
                            mimic: false,
                            version: 0,
                        },
                    )
                    .await?;
                    let media: u64 = doc.media.iter().map(|m| m.1 as u64).sum();
                    fixtures.push(json!({
                        "id": name, "kind": kind.ext(), "composition": c.to_string(), "seed": fixture_seed,
                        "sha256": sink.hash.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "compressed_bytes": sink.bytes, "items": doc.items.len(), "media_items": doc.media.len(),
                        "media_bytes": media, "parts": entries.len(),
                    }));
                    eprintln!("{name}: {} bytes", sink.bytes);
                }
            }
        }
    }
    let manifest = json!({"generator": office::GENERATOR, "seed": seed, "fixtures": fixtures});
    std::fs::write(
        out.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!("{}", serde_json::to_string(&manifest)?);
    Ok(())
}
