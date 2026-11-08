//! Word body paragraphs, streamed in both directions: [`Body`] turns
//! `word/document.xml` into paragraphs without holding the part, and the writer
//! functions emit a minimal package one paragraph at a time.

use super::xml::{Token, Tokenizer};
use super::OoxmlError;

/// Most paragraphs one import may create (design workload T: 2,000,000 rows).
pub const MAX_PARAGRAPHS: u64 = 2_000_000;
/// Longest paragraph text accepted.
pub const MAX_PARAGRAPH_BYTES: usize = 1 << 20;

/// One body paragraph: its text and heading level (0 for body text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paragraph {
    pub text: String,
    pub level: u8,
}

/// Streaming reader of a Word body.
#[derive(Default)]
pub struct Body {
    tokens: Tokenizer,
    depth: usize,
    in_text: bool,
    fallback: usize,
    current: Option<Paragraph>,
    seen: u64,
    ready: Vec<Paragraph>,
}

fn heading(style: &str) -> u8 {
    let lower = style.to_ascii_lowercase();
    match lower.strip_prefix("heading").map(str::trim) {
        Some(n) if n.len() == 1 => n
            .parse::<u8>()
            .ok()
            .filter(|l| (1..=6).contains(l))
            .unwrap_or(0),
        _ if lower == "title" => 1,
        _ => 0,
    }
}

impl Body {
    /// Feed the next decompressed slice of `word/document.xml`.
    pub fn feed(&mut self, data: &[u8], eof: bool) -> Result<(), OoxmlError> {
        let mut tokens = std::mem::take(&mut self.tokens);
        let result = tokens.feed(data, eof, &mut |token| self.token(token));
        self.tokens = tokens;
        result
    }

    /// Paragraphs completed so far, in document order.
    pub fn take(&mut self) -> Vec<Paragraph> {
        std::mem::take(&mut self.ready)
    }

    /// Number of completed paragraphs not yet taken.
    pub fn ready(&self) -> usize {
        self.ready.len()
    }

    fn token(&mut self, token: Token<'_>) -> Result<(), OoxmlError> {
        match &token {
            Token::Start { name, empty, .. } => {
                // Alternate content repeats a text box in its fallback: read it once.
                if *name == "Fallback" && !*empty {
                    self.fallback += 1;
                }
                if self.fallback > 0 {
                    return Ok(());
                }
                match *name {
                    "p" => {
                        if self.depth == 0 {
                            self.current = Some(Paragraph {
                                text: String::new(),
                                level: 0,
                            });
                        }
                        if *empty {
                            if self.depth == 0 {
                                self.end_paragraph()?;
                            }
                        } else {
                            self.depth += 1;
                        }
                    }
                    "t" if self.depth > 0 => self.in_text = !*empty,
                    "tab" if self.depth > 0 => self.push("\t")?,
                    "br" | "cr" if self.depth > 0 => self.push("\n")?,
                    "pStyle" => {
                        let level = token.attribute("val").map_or(0, heading);
                        if let Some(p) = self.current.as_mut().filter(|_| level > 0) {
                            p.level = level;
                        }
                    }
                    "outlineLvl" => {
                        let level = token
                            .attribute("val")
                            .and_then(|v| v.parse::<u8>().ok())
                            .filter(|v| *v < 6);
                        if let (Some(p), Some(level)) = (self.current.as_mut(), level) {
                            if p.level == 0 {
                                p.level = level + 1;
                            }
                        }
                    }
                    _ => {}
                }
            }
            Token::End { name } => {
                if *name == "Fallback" && self.fallback > 0 {
                    self.fallback -= 1;
                    return Ok(());
                }
                if self.fallback > 0 {
                    return Ok(());
                }
                match *name {
                    "t" => self.in_text = false,
                    "p" if self.depth > 0 => {
                        self.depth -= 1;
                        if self.depth == 0 {
                            self.end_paragraph()?;
                        }
                    }
                    _ => {}
                }
            }
            Token::Text(text) if self.in_text && self.fallback == 0 => self.push(text)?,
            Token::Text(_) => {}
        }
        Ok(())
    }

    fn push(&mut self, text: &str) -> Result<(), OoxmlError> {
        if let Some(p) = self.current.as_mut() {
            if p.text.len() + text.len() > MAX_PARAGRAPH_BYTES {
                return Err(OoxmlError::Limit("paragraph text"));
            }
            p.text.push_str(text);
        }
        Ok(())
    }

    fn end_paragraph(&mut self) -> Result<(), OoxmlError> {
        self.in_text = false;
        if let Some(p) = self.current.take() {
            self.seen += 1;
            if self.seen > MAX_PARAGRAPHS {
                return Err(OoxmlError::Limit("paragraphs"));
            }
            self.ready.push(p);
        }
        Ok(())
    }
}

/// Escape text for an XML text node, dropping characters XML 1.0 forbids.
pub fn escape(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => {}
            c => out.push(c),
        }
    }
}

/// `[Content_Types].xml` of the minimal package.
pub const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
/// `_rels/.rels` of the minimal package.
pub const PACKAGE_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;
/// Opening of `word/document.xml`, up to the first paragraph.
pub const DOCUMENT_HEAD: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:body>"#;
/// Close of `word/document.xml`.
pub const DOCUMENT_TAIL: &str = "<w:sectPr/></w:body></w:document>";

/// Append one paragraph's XML: tabs and line breaks become `w:tab` and `w:br`,
/// headings name a `HeadingN` style.
pub fn paragraph_xml(text: &str, level: u8, bold: bool, out: &mut String) {
    out.push_str("<w:p>");
    if (1..=6).contains(&level) {
        out.push_str(&format!(
            "<w:pPr><w:pStyle w:val=\"Heading{level}\"/></w:pPr>"
        ));
    }
    if !text.is_empty() {
        out.push_str(if bold {
            "<w:r><w:rPr><w:b/></w:rPr>"
        } else {
            "<w:r>"
        });
        for (i, line) in text.split('\n').enumerate() {
            if i > 0 {
                out.push_str("<w:br/>");
            }
            for (j, piece) in line.split('\t').enumerate() {
                if j > 0 {
                    out.push_str("<w:tab/>");
                }
                if !piece.is_empty() {
                    out.push_str("<w:t xml:space=\"preserve\">");
                    escape(piece, out);
                    out.push_str("</w:t>");
                }
            }
        }
        out.push_str("</w:r>");
    }
    out.push_str("</w:p>");
}
