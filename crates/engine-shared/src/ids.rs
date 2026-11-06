//! Identity newtypes for the dynodoc data model.
//!
//! ULID strings for log/tree identities (time-ordered, replica-unique); UUIDs for
//! db-generated row identities. Each is `#[sqlx(transparent)]`, so it encodes and
//! decodes exactly as its inner type — usable directly in queries and `FromRow`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable node identity (ULID). Never changes for a node's lifetime, never reused.
/// The load-bearing data-model decision (docs/04 §D.1).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, sqlx::Type,
)]
#[sqlx(transparent)]
pub struct NodeId(pub String);

/// Event identity (ULID). Time-ordered, unique across replicas.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct EventId(pub String);

/// Document identity (UUID, db-generated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct DocumentId(pub Uuid);

/// Snapshot identity (UUID, db-generated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct SnapshotId(pub Uuid);

/// Identity (user) identity (UUID, db-generated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct IdentityId(pub Uuid);

/// Magic-link token identity (UUID, db-generated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct MagicLinkId(pub Uuid);

/// Refresh-token identity (UUID, db-generated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct RefreshTokenId(pub Uuid);

/// Canonical uppercase ULID spelling for client-supplied new node identities.
/// Deliberately separate from serde/SQL decoding and historical operation validation.
/// Exactly 128 bits: the leading base-32 character is restricted to 0..=7.
pub fn is_canonical_ulid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 26
        && bytes.first().is_some_and(|b| (b'0'..=b'7').contains(b))
        && bytes
            .iter()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(b))
}

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

#[cfg(test)]
mod canonical_tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn compute_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    #[test]
    fn canonical_spelling_is_ascii_uppercase_and_does_not_overflow() {
        for valid in [
            "00000000000000000000000000",
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ] {
            assert!(is_canonical_ulid(valid), "{valid}");
        }
        for invalid in [
            "",
            "01NODE00000000",
            "01arz3ndektsv4rrffq69g5fav",
            "8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "<script>",
            "01ARZ3NDEKTSV4RRFFQ69G5FAI",
            "01ARZ3NDEKTSV4RRFFQ69G5FAU",
        ] {
            assert!(!is_canonical_ulid(invalid), "{invalid}");
        }
        assert!(!is_canonical_ulid(&"X".repeat(100_000)));
        for i in 0..3000 {
            assert!(!is_canonical_ulid(&format!("random-{i}")));
        }
        // Historical IDs still decode exactly; no identity is rewritten.
        let old: NodeId = serde_json::from_str("\"01NODE00000000\"").unwrap();
        assert_eq!(old.0, "01NODE00000000");
    }

    #[test]
    fn compact_node_id_preserves_exact_legacy_and_canonical_spellings() {
        let legacy_cases = [
            "01NODE00000000",
            "root",
            "question-1",
            "01arz3ndektsv4rrffq69g5fav",
            "stable",
            "clause_99",
            "<script>",
            "01ARZ3NDEKTSV4RRFFQ69G5FAI", // Contains forbidden Crockford char 'I'
        ];
        for legacy in legacy_cases {
            let compact = CompactNodeId::parse(legacy);
            assert!(
                !compact.is_canonical(),
                "expected legacy classification for {legacy}"
            );
            assert_eq!(compact.to_string(), legacy);
            let mut buf = [0u8; 26];
            assert_eq!(compact.as_str_with_buf(&mut buf), legacy);

            let node_id = NodeId(legacy.to_string());
            assert_eq!(compact.to_node_id(), node_id);
            assert_eq!(CompactNodeId::from_node_id(&node_id), compact);

            // Serde byte-for-byte equivalence
            let node_json = serde_json::to_string(&node_id).unwrap();
            let compact_json = serde_json::to_string(&compact).unwrap();
            assert_eq!(compact_json, node_json);

            let decoded_compact: CompactNodeId = serde_json::from_str(&compact_json).unwrap();
            assert_eq!(decoded_compact, compact);

            // Hash parity
            assert_eq!(compute_hash(&compact), compute_hash(&node_id));
        }

        let canonical_cases = [
            "00000000000000000000000000",
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "01BX5ZZKBKACTAV9WEVGEMMVRZ",
        ];
        for canonical in canonical_cases {
            let compact = CompactNodeId::parse(canonical);
            assert!(
                compact.is_canonical(),
                "expected canonical classification for {canonical}"
            );
            assert_eq!(compact.to_string(), canonical);
            let mut buf = [0u8; 26];
            assert_eq!(compact.as_str_with_buf(&mut buf), canonical);

            let node_id = NodeId(canonical.to_string());
            assert_eq!(compact.to_node_id(), node_id);
            assert_eq!(CompactNodeId::from_node_id(&node_id), compact);

            let node_json = serde_json::to_string(&node_id).unwrap();
            let compact_json = serde_json::to_string(&compact).unwrap();
            assert_eq!(compact_json, node_json);

            let decoded_compact: CompactNodeId = serde_json::from_str(&compact_json).unwrap();
            assert_eq!(decoded_compact, compact);

            assert_eq!(compute_hash(&compact), compute_hash(&node_id));
        }
    }

    #[test]
    fn compact_ordering_matches_string_lexicographical_ordering() {
        let ids = [
            "00000000000000000000000000",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "01NODE00000000",
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "root",
            "01arz3ndektsv4rrffq69g5fav",
            "question-1",
            "01BX5ZZKBKACTAV9WEVGEMMVRZ",
        ];
        for i in 0..ids.len() {
            for j in 0..ids.len() {
                let s1 = ids[i];
                let s2 = ids[j];
                let node1 = NodeId(s1.to_string());
                let node2 = NodeId(s2.to_string());
                let c1 = CompactNodeId::parse(s1);
                let c2 = CompactNodeId::parse(s2);
                assert_eq!(
                    c1.cmp(&c2),
                    node1.cmp(&node2),
                    "ordering mismatch between {s1} and {s2}"
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn prop_u128_ulid_roundtrip(val in any::<u128>()) {
            let mut buf = [0u8; 26];
            encode_ulid_u128(val, &mut buf);
            let s = std::str::from_utf8(&buf).unwrap();
            prop_assert!(is_canonical_ulid(s));
            let decoded = decode_ulid_u128(s);
            prop_assert_eq!(decoded, Some(val));

            let compact = CompactNodeId::Canonical(val);
            let node_id = NodeId(s.to_string());

            // Serde parity
            let c_json = serde_json::to_string(&compact).unwrap();
            let n_json = serde_json::to_string(&node_id).unwrap();
            prop_assert_eq!(&c_json, &n_json);

            let back: CompactNodeId = serde_json::from_str(&c_json).unwrap();
            prop_assert_eq!(&back, &compact);

            // Hash parity
            prop_assert_eq!(compute_hash(&compact), compute_hash(&node_id));
        }

        #[test]
        fn prop_ordering_parity(val1 in any::<u128>(), val2 in any::<u128>()) {
            let mut buf1 = [0u8; 26];
            let mut buf2 = [0u8; 26];
            encode_ulid_u128(val1, &mut buf1);
            encode_ulid_u128(val2, &mut buf2);
            let s1 = std::str::from_utf8(&buf1).unwrap();
            let s2 = std::str::from_utf8(&buf2).unwrap();

            let c1 = CompactNodeId::Canonical(val1);
            let c2 = CompactNodeId::Canonical(val2);
            let n1 = NodeId(s1.to_string());
            let n2 = NodeId(s2.to_string());

            prop_assert_eq!(c1.cmp(&c2), n1.cmp(&n2));
        }

        #[test]
        fn prop_legacy_serde_and_hash_parity(legacy in "[a-zA-Z0-9_-]{1,40}") {
            let compact = CompactNodeId::parse(&legacy);
            let node_id = NodeId(legacy.clone());

            let c_json = serde_json::to_string(&compact).unwrap();
            let n_json = serde_json::to_string(&node_id).unwrap();
            prop_assert_eq!(&c_json, &n_json);

            let back: CompactNodeId = serde_json::from_str(&c_json).unwrap();
            prop_assert_eq!(&back, &compact);
            prop_assert_eq!(compute_hash(&compact), compute_hash(&node_id));
        }
    }
}

/// Longest position key a new write may carry.
///
/// The web editor's `between()` grows a key by one character per insert once it passes 200
/// characters (see `engine-agent/src/pos.rs`): appending 3,000 rows or pasting 5,000 blocks
/// one after another reaches 1,700 to 3,600 characters, and the editors have no limit of
/// their own. The limit only has to stop abuse, not to shape what the editors write.
pub const MAX_POS_KEY_BYTES: usize = 8192;

/// Validate position keys on new writes.
///
/// Position keys must be non-empty, printable ASCII (32..=126),
/// have no trailing spaces, and not exceed [`MAX_POS_KEY_BYTES`] bytes.
///
/// ChoiceAdded uses the choice ID as pos, so ULIDs must pass.
pub fn is_valid_pos_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_POS_KEY_BYTES
        && bytes.last() != Some(&b' ')
        && bytes.iter().all(|b| (32..=126).contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pos_keys_are_validated() {
        // Rejected: empty, newline, emoji, trailing space, over the limit
        for invalid in [
            "",
            "\n",
            "\r",
            "\t",
            "🦀",
            "m ",
            " ",
            &"a".repeat(MAX_POS_KEY_BYTES + 1),
        ] {
            assert!(
                !is_valid_pos_key(invalid),
                "expected {invalid:?} to be rejected"
            );
        }

        // Passed: pending, 000000, ULID, standard fractional indices, exactly the limit
        let ulid = ulid::Ulid::generate().to_string();
        for valid in [
            "pending",
            "000000",
            &ulid,
            "a0",
            "a0V",
            "V",
            &"a".repeat(MAX_POS_KEY_BYTES),
        ] {
            assert!(is_valid_pos_key(valid), "expected {valid:?} to be accepted");
        }
    }
}
