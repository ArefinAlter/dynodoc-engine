//! Incremental, bounded XML tokenizer for OOXML parts. It accepts input in any
//! slices and keeps at most one unfinished token resident. Document type
//! declarations and undeclared entities are refused (no entity expansion),
//! nesting is capped and end tags must match.

use std::borrow::Cow;

use super::OoxmlError;

/// Deepest element nesting accepted (design section 7).
pub const MAX_DEPTH: usize = 128;
/// Largest single tag or text node held while waiting for its end.
pub const MAX_TOKEN_BYTES: usize = 1 << 20;
const MAX_ATTRIBUTES: usize = 256;

/// One complete token. Names are local names (any `prefix:` removed).
#[derive(Debug, PartialEq, Eq)]
pub enum Token<'a> {
    Start {
        name: &'a str,
        attributes: Attributes<'a>,
        empty: bool,
    },
    End {
        name: &'a str,
    },
    Text(Cow<'a, str>),
}

impl Token<'_> {
    /// The value of a start tag's attribute by local name.
    pub fn attribute(&self, wanted: &str) -> Option<&str> {
        match self {
            Token::Start { attributes, .. } => attributes
                .iter()
                .find(|(name, _)| *name == wanted)
                .map(|(_, value)| value.as_ref()),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct Tokenizer {
    pending: Vec<u8>,
    open: Vec<String>,
}

fn local(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decode the five predefined entities and character references.
pub fn unescape(raw: &str) -> Result<Cow<'_, str>, OoxmlError> {
    if !raw.contains('&') {
        return Ok(Cow::Borrowed(raw));
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let end = rest[at..]
            .find(';')
            .ok_or(OoxmlError::Xml("unterminated entity"))?;
        let entity = &rest[at + 1..at + end];
        let ch = match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(dec) = entity.strip_prefix('#') {
                    dec.parse().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32)
                    .ok_or(OoxmlError::Xml("undeclared entity"))?
            }
        };
        out.push(ch);
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    Ok(Cow::Owned(out))
}

fn text(bytes: &[u8]) -> Result<&str, OoxmlError> {
    std::str::from_utf8(bytes).map_err(|_| OoxmlError::Xml("invalid UTF-8"))
}

type Attributes<'a> = Vec<(&'a str, Cow<'a, str>)>;

fn start_tag(inner: &str) -> Result<(&str, Attributes<'_>, bool), OoxmlError> {
    let (inner, empty) = match inner.strip_suffix('/') {
        Some(inner) => (inner, true),
        None => (inner, false),
    };
    let name_end = inner
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(inner.len());
    let name = &inner[..name_end];
    if name.is_empty() {
        return Err(OoxmlError::Xml("empty element name"));
    }
    let mut attributes = Vec::new();
    let mut rest = inner[name_end..].trim_start();
    while !rest.is_empty() {
        let eq = rest.find('=').ok_or(OoxmlError::Xml("attribute"))?;
        let key = rest[..eq].trim_end();
        let after = rest[eq + 1..].trim_start();
        let quote = after
            .chars()
            .next()
            .filter(|c| *c == '"' || *c == '\'')
            .ok_or(OoxmlError::Xml("attribute quote"))?;
        let close = after[1..]
            .find(quote)
            .ok_or(OoxmlError::Xml("attribute quote"))?;
        if key.is_empty() || attributes.len() >= MAX_ATTRIBUTES {
            return Err(OoxmlError::Xml("attribute name or count"));
        }
        attributes.push((local(key), unescape(&after[1..1 + close])?));
        rest = after[close + 2..].trim_start();
    }
    Ok((local(name), attributes, empty))
}

impl Tokenizer {
    /// Feed the next slice of the part (`eof` on the last one) and receive every
    /// token it completes.
    pub fn feed(
        &mut self,
        data: &[u8],
        eof: bool,
        on: &mut impl FnMut(Token<'_>) -> Result<(), OoxmlError>,
    ) -> Result<(), OoxmlError> {
        self.pending.extend_from_slice(data);
        let mut at = 0;
        let bytes = std::mem::take(&mut self.pending);
        let result = self.scan(&bytes, &mut at, eof, on);
        self.pending = bytes;
        self.pending.drain(..at);
        result?;
        if self.pending.len() > MAX_TOKEN_BYTES {
            return Err(OoxmlError::Limit("XML tag or text too large"));
        }
        if eof && (!self.pending.is_empty() || !self.open.is_empty()) {
            return Err(OoxmlError::Xml("unexpected end of part"));
        }
        Ok(())
    }

    fn scan(
        &mut self,
        bytes: &[u8],
        at: &mut usize,
        eof: bool,
        on: &mut impl FnMut(Token<'_>) -> Result<(), OoxmlError>,
    ) -> Result<(), OoxmlError> {
        while *at < bytes.len() {
            let rest = &bytes[*at..];
            if rest[0] != b'<' {
                let Some(end) = rest.iter().position(|b| *b == b'<') else {
                    if eof && rest.iter().all(u8::is_ascii_whitespace) {
                        *at = bytes.len();
                    }
                    return Ok(());
                };
                if end > MAX_TOKEN_BYTES {
                    return Err(OoxmlError::Limit("XML tag or text too large"));
                }
                if !self.open.is_empty() {
                    on(Token::Text(unescape(text(&rest[..end])?)?))?;
                }
                *at += end;
                continue;
            }
            if rest.len() < 9 && (b"<![CDATA[".starts_with(rest) || b"<!--".starts_with(rest)) {
                return Ok(()); // not enough bytes to tell a comment from a declaration
            }
            let (skip, close): (usize, &[u8]) = if rest.starts_with(b"<?") {
                (2, b"?>")
            } else if rest.starts_with(b"<!--") {
                (4, b"-->")
            } else if rest.starts_with(b"<![CDATA[") {
                (9, b"]]>")
            } else if rest.starts_with(b"<!") {
                return Err(OoxmlError::Xml("document type declarations are refused"));
            } else {
                // A tag ends at the first '>' outside a quoted attribute value.
                let mut quote = None;
                let mut end = None;
                for (i, b) in rest.iter().enumerate().skip(1) {
                    match (quote, *b) {
                        (None, b'"' | b'\'') => quote = Some(*b),
                        (Some(q), b) if b == q => quote = None,
                        (None, b'>') => {
                            end = Some(i);
                            break;
                        }
                        _ => {}
                    }
                }
                let Some(end) = end else { return Ok(()) };
                if end > MAX_TOKEN_BYTES {
                    return Err(OoxmlError::Limit("XML tag or text too large"));
                }
                let inner = text(&rest[1..end])?;
                if let Some(name) = inner.strip_prefix('/') {
                    let name = name.trim_end();
                    if self.open.pop().as_deref() != Some(name) {
                        return Err(OoxmlError::Xml("mismatched end tag"));
                    }
                    on(Token::End { name: local(name) })?;
                } else {
                    let raw_name = inner
                        .split(|c: char| c.is_ascii_whitespace() || c == '/')
                        .next()
                        .unwrap_or_default();
                    let (name, attributes, empty) = start_tag(inner)?;
                    if !empty {
                        if self.open.len() >= MAX_DEPTH {
                            return Err(OoxmlError::Limit("XML nesting depth"));
                        }
                        self.open.push(raw_name.to_owned());
                    }
                    on(Token::Start {
                        name,
                        attributes,
                        empty,
                    })?;
                }
                *at += end + 1;
                continue;
            };
            let Some(end) = find(&rest[skip..], close) else {
                return Ok(());
            };
            if skip == 9 && !self.open.is_empty() {
                on(Token::Text(Cow::Borrowed(text(&rest[9..9 + end])?)))?;
            }
            *at += skip + end + close.len();
        }
        Ok(())
    }
}
