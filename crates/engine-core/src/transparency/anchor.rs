//! Event-chain anchoring (design section 4.3, phase W5, decision 032).
//!
//! Each interval the anchor job takes, for every document with new events, the tuple
//! `(doc_tag, seq, chain_hash)` of its latest event, where
//! `doc_tag = SHA-256("dynodoc.doc-tag\0v1\0" || installation UUID || document UUID)`
//! (16 raw bytes each). Tuples are sorted by tag and hashed into an RFC 6962 tree whose
//! leaf entry is `"dynodoc.event-head-leaf\0v1\0" || doc_tag || seq (u64 BE) ||
//! chain_hash`; one `event-heads` log leaf commits to its root. An operator exports one
//! tuple with its path; an auditor checks the chain hash with `engine-cli verify` and
//! the path against the root, and the root's leaf against a cosigned checkpoint.
use super::{
    merkle::{inclusion_proof, leaf_hash, verify_inclusion, Hash, MemoryTree},
    Error,
};
use ring::digest;
use serde::{Deserialize, Serialize};

const DOC_TAG_DOMAIN: &[u8] = b"dynodoc.doc-tag\0v1\0";
const HEAD_LEAF_DOMAIN: &[u8] = b"dynodoc.event-head-leaf\0v1\0";
/// One hour (open question WT-Q5, default taken).
pub const INTERVAL_SECONDS: i64 = 3600;

#[allow(clippy::expect_used, reason = "SHA-256 output is 32 bytes")]
pub fn doc_tag(installation: &uuid::Uuid, document: &uuid::Uuid) -> Hash {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(DOC_TAG_DOMAIN);
    context.update(installation.as_bytes());
    context.update(document.as_bytes());
    context.finish().as_ref().try_into().expect("32 bytes")
}

/// One document head of one interval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    #[serde(with = "hex32")]
    pub doc_tag: Hash,
    pub seq: u64,
    #[serde(with = "hex32")]
    pub chain_hash: Hash,
}

impl Head {
    fn entry(&self) -> Vec<u8> {
        let mut entry = HEAD_LEAF_DOMAIN.to_vec();
        entry.extend(self.doc_tag);
        entry.extend(self.seq.to_be_bytes());
        entry.extend(self.chain_hash);
        entry
    }
}

fn tree(heads: &[Head]) -> Result<(MemoryTree, Vec<&Head>), Error> {
    let mut sorted: Vec<&Head> = heads.iter().collect();
    sorted.sort_by_key(|h| h.doc_tag);
    if sorted.windows(2).any(|p| p[0].doc_tag == p[1].doc_tag) {
        return Err(Error::InvalidLeaf(
            "two heads for one document in an interval",
        ));
    }
    let mut tree = MemoryTree::new();
    for head in &sorted {
        tree.append_entry(&head.entry());
    }
    Ok((tree, sorted))
}

/// The root an `event-heads` leaf commits to.
pub fn root(heads: &[Head]) -> Result<Hash, Error> {
    Ok(tree(heads)?.0.root())
}

/// What an operator gives an auditor for one document of one interval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadProof {
    pub head: Head,
    pub index: u64,
    pub count: u64,
    #[serde(with = "hex32_list")]
    pub path: Vec<Hash>,
}

pub fn prove(heads: &[Head], tag: &Hash) -> Result<HeadProof, Error> {
    let (tree, sorted) = tree(heads)?;
    let index = sorted
        .iter()
        .position(|h| h.doc_tag == *tag)
        .ok_or(Error::InvalidLeaf(
            "no head for that document in the interval",
        ))?;
    Ok(HeadProof {
        head: sorted[index].clone(),
        index: index as u64,
        count: sorted.len() as u64,
        path: inclusion_proof(&tree, index as u64, sorted.len() as u64)?,
    })
}

/// Offline: the head is in the tree with this root.
pub fn verify(proof: &HeadProof, root: &Hash) -> Result<(), Error> {
    verify_inclusion(
        &leaf_hash(&proof.head.entry()),
        proof.index,
        proof.count,
        &proof.path,
        root,
    )
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::super::encoding::hex(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        super::super::encoding::unhex_array(&text).map_err(serde::de::Error::custom)
    }
}

mod hex32_list {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(value.iter().map(|h| super::super::encoding::hex(h)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|t| super::super::encoding::unhex_array(t).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_head_proves_against_the_root_and_a_changed_chain_hash_does_not() {
        let installation = uuid::Uuid::from_u128(1);
        let heads: Vec<Head> = (0..7u128)
            .map(|i| Head {
                doc_tag: doc_tag(&installation, &uuid::Uuid::from_u128(100 + i)),
                seq: i as u64 * 3,
                chain_hash: [i as u8; 32],
            })
            .collect();
        let root = super::root(&heads).unwrap();
        for head in &heads {
            let proof = prove(&heads, &head.doc_tag).unwrap();
            verify(&proof, &root).unwrap();
            let json = serde_json::to_vec(&proof).unwrap();
            assert_eq!(serde_json::from_slice::<HeadProof>(&json).unwrap(), proof);
            let mut rewritten = proof.clone();
            rewritten.head.chain_hash[0] ^= 1;
            assert!(verify(&rewritten, &root).is_err());
        }
        // The tag hides the document: another installation gives another tag.
        assert_ne!(
            doc_tag(&installation, &uuid::Uuid::from_u128(100)),
            doc_tag(&uuid::Uuid::from_u128(2), &uuid::Uuid::from_u128(100))
        );
        let mut twice = heads.clone();
        twice.push(heads[0].clone());
        assert!(super::root(&twice).is_err());
    }
}
