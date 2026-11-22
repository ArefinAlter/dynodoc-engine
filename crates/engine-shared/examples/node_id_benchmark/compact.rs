//! The compact in-memory node id prototype measured for PR-73, kept beside its
//! benchmark rather than in `engine-shared`: the measurement found no benefit worth its
//! cost (`docs/benchmarks/node-id-compact-benchmark-20261106.json`), so the public
//! `NodeId(pub String)` stays the only representation. Unchanged from the measured
//! version; `tests/compact_node_id_prototype.rs` holds its parity properties.
#![allow(dead_code)]

use engine_shared::ids::{is_canonical_ulid, NodeId};

/// Crockford Base32 alphabet for canonical ULID encoding.
pub const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode a 128-bit integer into a 26-character canonical ULID string buffer.
pub fn encode_ulid_u128(mut val: u128, buf: &mut [u8; 26]) {
    for i in (0..26).rev() {
        buf[i] = CROCKFORD_ALPHABET[(val & 0x1F) as usize];
        val >>= 5;
    }
}

/// Decode a 26-character canonical ULID string into a 128-bit integer.
/// Returns `None` if the input is not a canonical ULID.
pub fn decode_ulid_u128(s: &str) -> Option<u128> {
    if !is_canonical_ulid(s) {
        return None;
    }
    let mut val = 0u128;
    for &b in s.as_bytes() {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u128,
            b'A'..=b'H' => (b - b'A' + 10) as u128,
            b'J'..=b'K' => (b - b'J' + 18) as u128,
            b'M'..=b'N' => (b - b'M' + 20) as u128,
            b'P'..=b'T' => (b - b'P' + 22) as u128,
            b'V'..=b'Z' => (b - b'V' + 27) as u128,
            _ => return None,
        };
        val = (val << 5) | digit;
    }
    Some(val)
}

/// Internal compact representation benchmarked for PR-73.
///
/// Stores canonical 26-character ULIDs as an inline 128-bit integer (`u128`) without
/// heap allocation, with a fallback to `String` for legacy or noncanonical IDs.
/// Preserves exact string spelling, wire representation, and total lexicographical order.
#[derive(Debug, Clone, Eq)]
pub enum CompactNodeId {
    Canonical(u128),
    Legacy(String),
}

impl CompactNodeId {
    /// Parse a string into a compact node ID.
    /// Canonical ULIDs are parsed into `u128`; noncanonical or legacy IDs are preserved exactly.
    pub fn parse(s: &str) -> Self {
        if let Some(val) = decode_ulid_u128(s) {
            CompactNodeId::Canonical(val)
        } else {
            CompactNodeId::Legacy(s.to_string())
        }
    }

    /// Construct from an existing public `NodeId`.
    pub fn from_node_id(id: &NodeId) -> Self {
        Self::parse(&id.0)
    }

    /// Convert back to a public `NodeId`.
    pub fn to_node_id(&self) -> NodeId {
        NodeId(self.to_string())
    }

    /// Render to a string slice using a caller-provided 26-byte buffer for canonical values.
    pub fn as_str_with_buf<'a>(&'a self, buf: &'a mut [u8; 26]) -> &'a str {
        match self {
            CompactNodeId::Canonical(val) => {
                encode_ulid_u128(*val, buf);
                std::str::from_utf8(buf).expect("valid Crockford Base32 ASCII")
            }
            CompactNodeId::Legacy(s) => s.as_str(),
        }
    }

    /// Returns true if this is an inlined canonical ULID.
    pub fn is_canonical(&self) -> bool {
        matches!(self, CompactNodeId::Canonical(_))
    }
}

impl std::fmt::Display for CompactNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompactNodeId::Canonical(val) => {
                let mut buf = [0u8; 26];
                encode_ulid_u128(*val, &mut buf);
                let s = std::str::from_utf8(&buf).map_err(|_| std::fmt::Error)?;
                f.write_str(s)
            }
            CompactNodeId::Legacy(s) => f.write_str(s),
        }
    }
}

impl PartialEq for CompactNodeId {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CompactNodeId::Canonical(a), CompactNodeId::Canonical(b)) => a == b,
            (CompactNodeId::Legacy(a), CompactNodeId::Legacy(b)) => a == b,
            (CompactNodeId::Canonical(a), CompactNodeId::Legacy(b)) => {
                let mut buf = [0u8; 26];
                encode_ulid_u128(*a, &mut buf);
                buf.as_slice() == b.as_bytes()
            }
            (CompactNodeId::Legacy(a), CompactNodeId::Canonical(b)) => {
                let mut buf = [0u8; 26];
                encode_ulid_u128(*b, &mut buf);
                a.as_bytes() == buf.as_slice()
            }
        }
    }
}

impl Ord for CompactNodeId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (CompactNodeId::Canonical(a), CompactNodeId::Canonical(b)) => a.cmp(b),
            (CompactNodeId::Legacy(a), CompactNodeId::Legacy(b)) => a.cmp(b),
            (CompactNodeId::Canonical(a), CompactNodeId::Legacy(b)) => {
                let mut buf = [0u8; 26];
                encode_ulid_u128(*a, &mut buf);
                buf.as_slice().cmp(b.as_bytes())
            }
            (CompactNodeId::Legacy(a), CompactNodeId::Canonical(b)) => {
                let mut buf = [0u8; 26];
                encode_ulid_u128(*b, &mut buf);
                a.as_bytes().cmp(buf.as_slice())
            }
        }
    }
}

impl PartialOrd for CompactNodeId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for CompactNodeId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            CompactNodeId::Canonical(val) => {
                let mut buf = [0u8; 26];
                encode_ulid_u128(*val, &mut buf);
                let s = std::str::from_utf8(&buf).expect("valid Crockford Base32 ASCII");
                s.hash(state);
            }
            CompactNodeId::Legacy(s) => {
                s.hash(state);
            }
        }
    }
}

impl serde::Serialize for CompactNodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CompactNodeId::Canonical(val) => {
                let mut buf = [0u8; 26];
                encode_ulid_u128(*val, &mut buf);
                let s = std::str::from_utf8(&buf).map_err(serde::ser::Error::custom)?;
                serializer.serialize_str(s)
            }
            CompactNodeId::Legacy(s) => serializer.serialize_str(s),
        }
    }
}

impl<'de> serde::Deserialize<'de> for CompactNodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CompactNodeIdVisitor;

        impl<'de> serde::de::Visitor<'de> for CompactNodeIdVisitor {
            type Value = CompactNodeId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string representing a node identity")
            }

            fn visit_str<E>(self, value: &str) -> Result<CompactNodeId, E>
            where
                E: serde::de::Error,
            {
                Ok(CompactNodeId::parse(value))
            }
        }

        deserializer.deserialize_str(CompactNodeIdVisitor)
    }
}
