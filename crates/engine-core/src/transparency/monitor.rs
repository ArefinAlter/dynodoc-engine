//! The member monitor (design section 4.9 "Member monitor", phase W4, decision 032).
//!
//! A project member holding `k_project` recomputes the blinded tag of every branch
//! generation it knows a receipt for and looks for it among the log's leaves. Pure:
//! the caller fetches the leaves of a checkpoint it verified (and checks that the
//! leaves reproduce that checkpoint's root, see [`leaves_from_bundles`]) and the
//! receipts from the API. No finding is a proof of honesty; an equivocation finding
//! carries both leaf indexes and receipt addresses, which anyone can check.
use super::{
    leaf::{Leaf, TagKey},
    merkle::{Hash, MemoryTree},
    tiles::parse_entry_bundle,
    Error,
};
use std::collections::BTreeMap;

/// One receipt the monitor expects in the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub branch: String,
    pub generation: u64,
    /// The receipt's address (`dynodoc.ref-receipt` domain).
    pub receipt: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// No leaf carries this generation's tag yet (may still be pending: warn, and
    /// escalate when it stays missing over two intervals).
    Missing { branch: String, generation: u64 },
    /// Leaves with this generation's tag commit to a receipt other than the one
    /// the API served: two histories for one scope.
    Equivocation {
        branch: String,
        generation: u64,
        served: Hash,
        logged: Vec<(u64, Hash)>,
    },
}

/// Compare expected receipts with `(index, leaf)` pairs of a verified log prefix.
pub fn check_receipts(key: &TagKey, leaves: &[(u64, Leaf)], expected: &[Expected]) -> Vec<Finding> {
    let mut by_tag: BTreeMap<Hash, Vec<(u64, Hash)>> = BTreeMap::new();
    for (index, leaf) in leaves {
        if let Leaf::RefReceipt { tag, receipt } = leaf {
            by_tag.entry(*tag).or_default().push((*index, *receipt));
        }
    }
    let mut findings = Vec::new();
    for item in expected {
        let tag = key.ref_tag(&item.branch, item.generation);
        match by_tag.get(&tag) {
            None => findings.push(Finding::Missing {
                branch: item.branch.clone(),
                generation: item.generation,
            }),
            Some(logged) if logged.iter().any(|(_, r)| *r != item.receipt) => {
                findings.push(Finding::Equivocation {
                    branch: item.branch.clone(),
                    generation: item.generation,
                    served: item.receipt,
                    logged: logged.clone(),
                })
            }
            Some(_) => {}
        }
    }
    findings
}

/// Leaves from consecutive entry bundles (full tiles first, the partial last), in
/// index order, after checking that exactly `size` entries reproduce `root`: the
/// leaves are then exactly the ones the verified checkpoint committed to.
pub fn leaves_from_bundles(
    bundles: &[Vec<u8>],
    size: u64,
    root: &Hash,
) -> Result<Vec<(u64, Leaf)>, Error> {
    let mut tree = MemoryTree::new();
    let mut leaves = Vec::new();
    for bundle in bundles {
        for entry in parse_entry_bundle(bundle)? {
            let index = tree.append_entry(&entry);
            leaves.push((index, Leaf::from_entry(&entry)?));
        }
    }
    if leaves.len() as u64 != size || tree.root() != *root {
        return Err(Error::BadInclusionProof);
    }
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparency::{
        log::Log,
        tiles::{entry_bundle_path, MemoryTileStore, TileStore},
        Origin,
    };

    #[test]
    fn duplicate_tags_with_different_receipts_are_equivocation_and_absence_is_missing() {
        let key = TagKey::new([5; 32]);
        let receipt = |i: u8| [i; 32];
        let mut log = Log::open(
            Origin::new("log.example/dynodoc/v1/transparency").unwrap(),
            MemoryTileStore::new(),
        )
        .unwrap();
        log.append(&Leaf::RefReceipt {
            tag: key.ref_tag("main", 1),
            receipt: receipt(1),
        })
        .unwrap();
        log.append(&Leaf::RefReceipt {
            tag: key.ref_tag("main", 2),
            receipt: receipt(2),
        })
        .unwrap();
        // The operator shows another client a different generation-2 receipt.
        log.append(&Leaf::RefReceipt {
            tag: key.ref_tag("main", 2),
            receipt: receipt(9),
        })
        .unwrap();
        let store = log.store();
        let bundle = store.get(&entry_bundle_path(0, 3)).unwrap().unwrap();
        let leaves = leaves_from_bundles(std::slice::from_ref(&bundle), 3, &log.root()).unwrap();
        // A bundle that does not reproduce the signed root is refused.
        assert!(leaves_from_bundles(&[bundle], 3, &[0; 32]).is_err());
        let findings = check_receipts(
            &key,
            &leaves,
            &[
                Expected {
                    branch: "main".into(),
                    generation: 1,
                    receipt: receipt(1),
                },
                Expected {
                    branch: "main".into(),
                    generation: 2,
                    receipt: receipt(2),
                },
                Expected {
                    branch: "main".into(),
                    generation: 3,
                    receipt: receipt(3),
                },
            ],
        );
        assert_eq!(
            findings,
            vec![
                Finding::Equivocation {
                    branch: "main".into(),
                    generation: 2,
                    served: receipt(2),
                    logged: vec![(1, receipt(2)), (2, receipt(9))],
                },
                Finding::Missing {
                    branch: "main".into(),
                    generation: 3
                },
            ]
        );
        // Without the project key nothing links: another key finds every generation missing.
        let other = TagKey::new([6; 32]);
        assert_eq!(
            check_receipts(
                &other,
                &leaves,
                &[Expected {
                    branch: "main".into(),
                    generation: 1,
                    receipt: receipt(1)
                }]
            )
            .len(),
            1
        );
    }
}
