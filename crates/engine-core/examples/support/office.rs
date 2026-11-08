//! Deterministic synthetic Office packages for large-file acceptance (design
//! section 5): .docx, .xlsx and .pptx in media-heavy (M), balanced (B) and
//! text/data-heavy (T) compositions, written streaming, with seeded edit scripts
//! and a host-mimic mode for version corpora. Synthetic content only.
#![allow(dead_code)]

use engine_core::ooxml::docx;
use engine_core::ooxml::zip::{Written, ZipWriter};
use tokio::io::AsyncWrite;

/// Generator version, part of every fixture name and manifest.
pub const GENERATOR: &str = "dynodoc-office-corpus/2";

/// xorshift64*: the same seed gives byte-identical output on every machine.
#[derive(Clone)]
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Docx,
    Xlsx,
    Pptx,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "docx" => Self::Docx,
            "xlsx" => Self::Xlsx,
            "pptx" => Self::Pptx,
            _ => return None,
        })
    }
    pub fn ext(self) -> &'static str {
        match self {
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
            Self::Pptx => "pptx",
        }
    }
}

/// Media share of the compressed size: M 95 %, B 50 %, T 5 %.
pub fn media_share(composition: char) -> f64 {
    match composition {
        'M' => 0.95,
        'B' => 0.50,
        _ => 0.05,
    }
}

const SYLLABLES: [&str; 24] = [
    "ka", "ri", "to", "men", "sal", "ve", "dor", "an", "is", "lu", "pra", "ne", "qua", "tor", "el",
    "mi", "sun", "da", "ro", "fi", "gal", "te", "nor", "ul",
];
const EXTRA: [&str; 6] = ["বাংলা", "তথ্য", "নথি", "👩‍💻", "Größe", "„draft“"];

/// One text item (paragraph, row or text shape) from its own seed.
pub fn text(seed: u64) -> String {
    let mut rng = Rng::new(seed);
    // Geometric word count with mean 12.
    let mut words = 1;
    while rng.below(12) != 0 && words < 200 {
        words += 1;
    }
    let mut out = String::new();
    for w in 0..words {
        if w > 0 {
            out.push(' ');
        }
        if rng.below(40) == 0 {
            out.push_str(EXTRA[rng.below(EXTRA.len() as u64) as usize]);
            continue;
        }
        for _ in 0..1 + rng.below(3) {
            out.push_str(SYLLABLES[rng.below(SYLLABLES.len() as u64) as usize]);
        }
    }
    out
}

/// A document model: item text seeds in order, and media (seed, bytes).
#[derive(Clone)]
pub struct Doc {
    pub kind: Kind,
    pub composition: char,
    pub seed: u64,
    pub items: Vec<u64>,
    pub media: Vec<(u64, usize)>,
    next_seed: u64,
}

/// Approximate compressed bytes of one item, measured once per kind.
fn item_bytes(kind: Kind) -> f64 {
    match kind {
        Kind::Docx => 30.0,
        Kind::Xlsx => 82.0,
        Kind::Pptx => 95.0,
    }
}

impl Doc {
    /// A model whose package is close to `target` compressed bytes.
    pub fn new(kind: Kind, composition: char, target: u64, seed: u64) -> Self {
        let media_bytes = (target as f64 * media_share(composition)) as u64;
        let text_bytes = target.saturating_sub(media_bytes) as f64;
        let mut rng = Rng::new(seed);
        let mut media = Vec::new();
        let mut left = media_bytes;
        while left > 0 {
            let size = (64 * 1024 + rng.below(1 << 20)).min(left) as usize;
            media.push((rng.next(), size));
            left -= size as u64;
        }
        let count = (text_bytes / item_bytes(kind)).max(10.0) as u64;
        let items = (0..count).map(|_| rng.next()).collect();
        Self {
            kind,
            composition,
            seed,
            items,
            media,
            next_seed: rng.next(),
        }
    }

    /// Apply one seeded edit script; `local` keeps each version's edits in one
    /// place (a person revising a section) instead of scattering them.
    pub fn edit_with(&mut self, version: u64, local: bool) {
        if local {
            self.edit_local(version)
        } else {
            self.edit(version)
        }
    }

    /// One section revised: 1-20 items inserted at one random place and a run of
    /// 0.1 % of the items replaced at another; one media item in fifty replaced.
    pub fn edit_local(&mut self, version: u64) {
        let mut rng = Rng::new(self.seed ^ version.wrapping_mul(0x9e37_79b9));
        let at = rng.below(self.items.len() as u64) as usize;
        for _ in 0..1 + rng.below(20) {
            self.items.insert(at, rng.next());
        }
        let run = (self.items.len() / 1000).max(1);
        let start = rng.below((self.items.len() - run) as u64 + 1) as usize;
        for item in &mut self.items[start..start + run] {
            *item = rng.next();
        }
        if !self.media.is_empty() && rng.below(50) == 0 {
            let at = rng.below(self.media.len() as u64) as usize;
            self.media[at].0 = rng.next();
        }
    }

    /// Apply one seeded edit script: 1 % of items replaced, 0.1 % inserted and
    /// 0.1 % deleted at random positions; one media item in fifty replaced.
    pub fn edit(&mut self, version: u64) {
        let mut rng = Rng::new(self.seed ^ version.wrapping_mul(0x1000_0000_01b3));
        let n = self.items.len() as u64;
        for _ in 0..(n / 100).max(1) {
            let at = rng.below(n) as usize;
            self.items[at] = rng.next();
        }
        for _ in 0..(n / 1000).max(1) {
            let at = rng.below(self.items.len() as u64) as usize;
            self.items.insert(at, rng.next());
        }
        for _ in 0..(n / 1000).max(1) {
            if self.items.len() > 1 {
                let at = rng.below(self.items.len() as u64) as usize;
                self.items.remove(at);
            }
        }
        if !self.media.is_empty() && rng.below(50) == 0 {
            let at = rng.below(self.media.len() as u64) as usize;
            self.media[at].0 = rng.next();
        }
        self.next_seed = rng.next();
    }
}

/// Save-time differences a host makes (design 5.3): with `mimic`, parts are
/// written in a rotated order and XML parts with a varying deflate level.
#[derive(Clone, Copy)]
pub struct Save {
    pub mimic: bool,
    pub version: u64,
}

/// Incompressible PRNG bytes behind a PNG signature (media).
pub fn media_bytes(seed: u64, size: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    while out.len() < size {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    out.truncate(size.max(8));
    out
}

fn small_part(doc: &Doc, name: &str) -> String {
    match (doc.kind, name) {
        (_, "[Content_Types].xml") => {
            let main = match doc.kind {
                Kind::Docx => r#"<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>"#.to_string(),
                Kind::Xlsx => r#"<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>"#.to_string(),
                Kind::Pptx => {
                    let mut s = r#"<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>"#.to_string();
                    for i in 1..=slides(doc) {
                        s.push_str(&format!(r#"<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>"#));
                    }
                    s
                }
            };
            format!(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/>{main}</Types>"#)
        }
        (_, "_rels/.rels") => {
            let target = match doc.kind {
                Kind::Docx => "word/document.xml",
                Kind::Xlsx => "xl/workbook.xml",
                Kind::Pptx => "ppt/presentation.xml",
            };
            format!(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{target}"/></Relationships>"#)
        }
        (Kind::Docx, "word/_rels/document.xml.rels") => {
            let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#);
            for i in 0..doc.media.len() {
                s.push_str(&format!(r#"<Relationship Id="rIdImg{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image{i}.png"/>"#));
            }
            s + "</Relationships>"
        }
        (Kind::Xlsx, "xl/workbook.xml") => r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>"#.into(),
        (Kind::Xlsx, "xl/_rels/workbook.xml.rels") => r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>"#.into(),
        (Kind::Pptx, "ppt/presentation.xml") => {
            let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldIdLst>"#);
            for i in 1..=slides(doc) {
                s.push_str(&format!(r#"<p:sldId id="{}" r:id="rId{i}"/>"#, 255 + i));
            }
            s + r#"</p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/></p:presentation>"#
        }
        (Kind::Pptx, "ppt/_rels/presentation.xml.rels") => {
            let mut s = String::from(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#);
            for i in 1..=slides(doc) {
                s.push_str(&format!(r#"<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i}.xml"/>"#));
            }
            s + "</Relationships>"
        }
        _ => String::new(),
    }
}

const SLIDE_ITEMS: usize = 8;

fn slides(doc: &Doc) -> usize {
    doc.items.len().div_ceil(SLIDE_ITEMS).max(1)
}

fn column(mut n: usize) -> String {
    let mut s = Vec::new();
    loop {
        s.push(b'A' + (n % 26) as u8);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    s.reverse();
    String::from_utf8(s).unwrap_or_default()
}

/// Part names in save order.
pub fn parts(doc: &Doc, save: Save) -> Vec<String> {
    let mut names: Vec<String> = ["[Content_Types].xml", "_rels/.rels"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    match doc.kind {
        Kind::Docx => {
            names.push("word/document.xml".into());
            names.push("word/_rels/document.xml.rels".into());
            names.extend((0..doc.media.len()).map(|i| format!("word/media/image{i}.png")));
        }
        Kind::Xlsx => {
            names.extend(
                [
                    "xl/workbook.xml",
                    "xl/_rels/workbook.xml.rels",
                    "xl/worksheets/sheet1.xml",
                    "xl/sharedStrings.xml",
                ]
                .map(String::from),
            );
            names.extend((0..doc.media.len()).map(|i| format!("xl/media/image{i}.png")));
        }
        Kind::Pptx => {
            names.push("ppt/presentation.xml".into());
            names.push("ppt/_rels/presentation.xml.rels".into());
            names.extend((1..=slides(doc)).map(|i| format!("ppt/slides/slide{i}.xml")));
            names.extend((0..doc.media.len()).map(|i| format!("ppt/media/image{i}.png")));
        }
    }
    if save.mimic && names.len() > 2 {
        // Hosts reorder parts on save; keep the content types first.
        let shift = (save.version as usize) % (names.len() - 1);
        names[1..].rotate_left(shift);
    }
    names
}

fn picture(buf: &mut String, k: usize) {
    buf.push_str(&format!(r#"<w:p><w:r><w:drawing><wp:inline><wp:extent cx="3000000" cy="2000000"/><wp:docPr id="{}" name="Picture"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImg{k}"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>"#, k + 1));
}

/// Write one part's bytes in pieces of at most about 64 KiB.
async fn part<W: AsyncWrite + Unpin>(
    doc: &Doc,
    name: &str,
    zip: &mut ZipWriter<W>,
) -> anyhow::Result<()> {
    let mut buf = String::new();
    let flush = |buf: &mut String| buf.len() >= 64 * 1024;
    if let Some(i) = name
        .rsplit_once("/image")
        .and_then(|(_, n)| n.strip_suffix(".png"))
        .and_then(|n| n.parse::<usize>().ok())
    {
        let (seed, size) = doc.media[i];
        for piece in media_bytes(seed, size).chunks(64 * 1024) {
            zip.write(piece).await?;
        }
        return Ok(());
    }
    match name {
        "word/document.xml" => {
            buf.push_str(docx::DOCUMENT_HEAD);
            // Headings, bold and picture anchors follow each item's own seed, not its
            // position, so an insertion does not restyle every later paragraph.
            let every = (doc.items.len() / doc.media.len().max(1)).max(1) as u64;
            let mut placed = 0;
            for seed in &doc.items {
                let level = if seed % 25 == 0 {
                    1 + (seed / 25 % 3) as u8
                } else {
                    0
                };
                docx::paragraph_xml(&text(*seed), level, seed % 7 == 0, &mut buf);
                if placed < doc.media.len() && (seed >> 8) % every == 0 {
                    picture(&mut buf, placed);
                    placed += 1;
                }
                if flush(&mut buf) {
                    zip.write(buf.as_bytes()).await?;
                    buf.clear();
                }
            }
            for k in placed..doc.media.len() {
                picture(&mut buf, k);
            }
            buf.push_str(docx::DOCUMENT_TAIL);
        }
        "xl/worksheets/sheet1.xml" => {
            buf.push_str(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#);
            for (r, seed) in doc.items.iter().enumerate() {
                let mut rng = Rng::new(*seed);
                buf.push_str(&format!(r#"<row r="{}">"#, r + 1));
                for c in 0..10 {
                    let cell = format!("{}{}", column(c), r + 1);
                    match c {
                        0 => buf.push_str(&format!(r#"<c r="{cell}" t="s"><v>{r}</v></c>"#)),
                        9 => buf.push_str(&format!(
                            r#"<c r="{cell}"><f>SUM(B{n}:I{n})</f></c>"#,
                            n = r + 1
                        )),
                        _ => buf.push_str(&format!(
                            r#"<c r="{cell}"><v>{}</v></c>"#,
                            rng.below(1_000_000)
                        )),
                    }
                }
                buf.push_str("</row>");
                if flush(&mut buf) {
                    zip.write(buf.as_bytes()).await?;
                    buf.clear();
                }
            }
            buf.push_str("</sheetData></worksheet>");
        }
        "xl/sharedStrings.xml" => {
            buf.push_str(&format!(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{n}" uniqueCount="{n}">"#, n = doc.items.len()));
            for seed in &doc.items {
                let words = text(*seed);
                let first: String = words.split(' ').take(3).collect::<Vec<_>>().join(" ");
                buf.push_str("<si><t>");
                docx::escape(&first, &mut buf);
                buf.push_str("</t></si>");
                if flush(&mut buf) {
                    zip.write(buf.as_bytes()).await?;
                    buf.clear();
                }
            }
            buf.push_str("</sst>");
        }
        slide if slide.starts_with("ppt/slides/slide") => {
            let n: usize = slide
                .trim_start_matches("ppt/slides/slide")
                .trim_end_matches(".xml")
                .parse()?;
            buf.push_str(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree>"#);
            for (k, seed) in doc
                .items
                .iter()
                .skip((n - 1) * SLIDE_ITEMS)
                .take(SLIDE_ITEMS)
                .enumerate()
            {
                buf.push_str(&format!(r#"<p:sp><p:nvSpPr><p:cNvPr id="{}" name="Text {k}"/></p:nvSpPr><p:txBody><a:p><a:r><a:t>"#, k + 2));
                docx::escape(&text(*seed), &mut buf);
                buf.push_str("</a:t></a:r></a:p></p:txBody></p:sp>");
            }
            buf.push_str("</p:spTree></p:cSld></p:sld>");
        }
        other => buf.push_str(&small_part(doc, other)),
    }
    zip.write(buf.as_bytes()).await?;
    Ok(())
}

/// Write the package; returns where each entry sits.
pub async fn write<W: AsyncWrite + Unpin>(
    doc: &Doc,
    out: W,
    save: Save,
) -> anyhow::Result<(W, Vec<Written>)> {
    let mut zip = ZipWriter::new(out);
    for name in parts(doc, save) {
        let media = name.ends_with(".png");
        let level = if media {
            0
        } else if save.mimic {
            [6, 9, 1][(save.version % 3) as usize]
        } else {
            6
        };
        zip.start(&name, level).await?;
        part(doc, &name, &mut zip).await?;
    }
    Ok(zip.finish().await?)
}
