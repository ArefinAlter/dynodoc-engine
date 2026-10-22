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

#[cfg(test)]
mod canonical_tests {
    use super::*;
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
}
