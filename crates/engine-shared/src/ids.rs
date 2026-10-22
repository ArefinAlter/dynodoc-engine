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

/// Validate position keys on new writes.
///
/// Position keys must be non-empty, printable ASCII (32..=126),
/// have no trailing spaces, and not exceed 1024 bytes.
///
/// ChoiceAdded uses the choice ID as pos, so ULIDs must pass.
pub fn is_valid_pos_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 1024
        && bytes.last() != Some(&b' ')
        && bytes.iter().all(|b| (32..=126).contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pos_keys_are_validated() {
        // Rejected: empty, newline, emoji, trailing space, over 1024 bytes
        for invalid in ["", "\n", "\r", "\t", "🦀", "m ", " ", &"a".repeat(1025)] {
            assert!(
                !is_valid_pos_key(invalid),
                "expected {invalid:?} to be rejected"
            );
        }

        // Passed: pending, 000000, ULID, standard fractional indices, exactly 1024 bytes
        let ulid = ulid::Ulid::generate().to_string();
        for valid in [
            "pending",
            "000000",
            &ulid,
            "a0",
            "a0V",
            "V",
            &"a".repeat(1024),
        ] {
            assert!(is_valid_pos_key(valid), "expected {valid:?} to be accepted");
        }
    }
}
