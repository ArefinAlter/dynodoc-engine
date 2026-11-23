//! Byte-for-byte serde, hash and ordering parity of the PR-73 compact node id
//! prototype with `NodeId`, over canonical, legacy and mixed ids. The prototype lives
//! with its benchmark (`examples/node_id_benchmark/compact.rs`); it is not part of
//! the `engine-shared` API.
#[path = "../examples/node_id_benchmark/compact.rs"]
mod compact;

use compact::*;
use engine_shared::ids::{is_canonical_ulid, NodeId};
use proptest::prelude::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn compute_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
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
