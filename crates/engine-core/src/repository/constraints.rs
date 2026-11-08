//! Project constraints on a merged candidate (cross-document design 5.3).
//!
//! | ID | Where |
//! |---|---|
//! | C1, C2 | `Commit::validate` (paths, file/directory, one entry per document) |
//! | C3 | [`node_identity`]: a live node id in at most one document, over the documents the merge touched |
//! | C4 | relocation records re-applied on import (`relocation::verify_commit`) |
//! | C5 | not applicable: no typed cross-document reference kind exists yet |
//! | C6 | at publication, by the review floors of the shared service |
//! | C7 | [`portability`]: case-folding and NFC collisions between distinct documents are conflicts (XD-F6); reserved names and long components are warnings |
//! | C8 | at publication, by the shared service (audience of the destination) |

use super::{
    project::{Class, XdConflict},
    FileEntry,
};
use crate::materializer::DocumentState;
use engine_shared::DocumentId;
use serde::Serialize;
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

/// A portability finding that does not block a merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub code: &'static str,
    pub path: String,
    pub detail: String,
}

const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The key two paths collide under on common filesystems.
// shortcut: lowercase approximates simple case folding (no CaseFolding.txt table); upgrade if a corpus shows full folding matters.
fn fold(path: &str) -> String {
    path.nfc().collect::<String>().to_lowercase()
}

/// C7: collisions between distinct documents, and per-path warnings.
pub fn portability(files: &BTreeMap<String, FileEntry>) -> (Vec<XdConflict>, Vec<Warning>) {
    let mut by_key: BTreeMap<String, Vec<(&String, DocumentId)>> = BTreeMap::new();
    let mut warnings = Vec::new();
    for (path, f) in files {
        by_key
            .entry(fold(path))
            .or_default()
            .push((path, f.document));
        for part in path.split('/') {
            let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            if RESERVED.contains(&stem.as_str()) {
                warnings.push(Warning {
                    code: "C7-reserved",
                    path: path.clone(),
                    detail: format!("`{part}` is a reserved name on Windows"),
                });
            }
            if part.ends_with('.') || part.ends_with(' ') {
                warnings.push(Warning {
                    code: "C7-trailing",
                    path: path.clone(),
                    detail: format!("`{part}` ends with a dot or space"),
                });
            }
            if part.len() > 255 {
                warnings.push(Warning {
                    code: "C7-length",
                    path: path.clone(),
                    detail: "a path component is longer than 255 bytes".into(),
                });
            }
        }
    }
    let conflicts = by_key
        .into_values()
        .filter(|group| group.len() > 1)
        .map(|group| {
            XdConflict::new(
                Class::PortabilityCollision,
                group.iter().map(|(p, _)| (*p).clone()).collect(),
                group.iter().map(|(_, d)| *d).collect(),
                "paths collide under case folding or Unicode normalization",
            )
        })
        .collect();
    (conflicts, warnings)
}

/// C3: a live node identifier in more than one of `states` (keyed by path).
pub fn node_identity(states: &[(String, DocumentId, &DocumentState)]) -> Vec<XdConflict> {
    let mut seen: BTreeMap<&str, Vec<(&String, DocumentId)>> = BTreeMap::new();
    for (path, doc, state) in states {
        for node in state.nodes.values().filter(|n| !n.deleted) {
            seen.entry(node.id.0.as_str())
                .or_default()
                .push((path, *doc));
        }
    }
    seen.into_iter()
        .filter(|(_, places)| places.len() > 1)
        .map(|(node, places)| {
            XdConflict::new(
                Class::NodeInTwoDocuments,
                places.iter().map(|(p, _)| format!("{p}#{node}")).collect(),
                places.iter().map(|(_, d)| *d).collect(),
                format!("node {node} is live in more than one document"),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_checkpoint::Address;

    fn entry(n: u128) -> FileEntry {
        FileEntry {
            document: DocumentId(uuid::Uuid::from_u128(n)),
            state: Address::try_from("ab".repeat(32)).unwrap(),
        }
    }

    #[test]
    fn case_and_normalization_collisions_of_distinct_documents_conflict() {
        let mut files = BTreeMap::new();
        files.insert("Report.docx".to_string(), entry(1));
        files.insert("report.DOCX".to_string(), entry(2));
        files.insert("Caf\u{e9}.docx".to_string(), entry(3));
        files.insert("Cafe\u{301}.docx".to_string(), entry(4));
        files.insert("CON.txt".to_string(), entry(5));
        let (conflicts, warnings) = portability(&files);
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts
            .iter()
            .all(|c| c.class == Class::PortabilityCollision && c.participants.len() == 2));
        assert_eq!(
            warnings.iter().map(|w| w.code).collect::<Vec<_>>(),
            ["C7-reserved"]
        );
    }
}
