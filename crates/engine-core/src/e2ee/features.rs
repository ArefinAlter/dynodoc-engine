//! The 34-row feature matrix of docs/E2EE-PROTOCOL-AND-MIGRATION.md section 11: what each
//! feature does in an encrypted project. The API answers a refused feature with
//! `422 {"error":"encrypted_project","feature":..,"alternative":..}`, never a silent result.

/// How a feature behaves in an encrypted project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Works on identifiers, addresses and counts only; the same as in plaintext projects.
    Unchanged,
    /// Runs on members' devices over decrypted state; the service stores ciphertext.
    Client,
    /// Needs plaintext on the service: refused with the named alternative.
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feature {
    pub row: u8,
    /// Stable machine name, the `feature` field of the 422 answer.
    pub code: &'static str,
    pub behaviour: Behaviour,
    /// The `alternative` field of the 422 answer (empty when not refused).
    pub alternative: &'static str,
    /// The design phase that brings the client path (`P1`, `P2`, `P3`).
    pub phase: &'static str,
}

const fn f(
    row: u8,
    code: &'static str,
    behaviour: Behaviour,
    alternative: &'static str,
    phase: &'static str,
) -> Feature {
    Feature {
        row,
        code,
        behaviour,
        alternative,
        phase,
    }
}
use Behaviour::{Client, Refused, Unchanged};

pub const MATRIX: [Feature; 34] = [
    f(1, "web_block_edit", Refused, "client_sealed_events", "P1"),
    f(2, "drafts_autosave", Refused, "client_sealed_drafts", "P1"),
    f(3, "server_merge", Refused, "client_merge", "P1"),
    f(4, "server_diff", Refused, "client_diff", "P1"),
    f(5, "server_review_rendering", Refused, "client_review", "P2"),
    f(6, "required_approvals", Unchanged, "", "P1"),
    f(7, "branch_cas_receipts", Unchanged, "", "P1"),
    f(8, "server_restore", Refused, "client_restore", "P1"),
    f(9, "named_versions", Client, "", "P1"),
    f(10, "download_export", Client, "", "P1"),
    f(11, "import", Client, "", "P1"),
    f(
        12,
        "legacy_doc_conversion",
        Refused,
        "convert_locally",
        "P1",
    ),
    f(13, "search", Refused, "client_side_search", "P2"),
    f(14, "similarity", Refused, "client_side_similarity", "P2"),
    f(15, "public_links", Refused, "publish_plaintext_copy", "P1"),
    f(16, "in_app_notifications", Unchanged, "", "P1"),
    f(17, "email_notifications", Unchanged, "", "P1"),
    f(18, "admin_overview", Unchanged, "", "P1"),
    f(19, "audited_erasure", Unchanged, "", "P1"),
    f(20, "comments", Client, "", "P1"),
    f(21, "suggestions", Client, "", "P1"),
    f(22, "project_issues", Client, "", "P1"),
    f(23, "activity_feed", Unchanged, "", "P1"),
    f(24, "verification", Unchanged, "", "P1"),
    f(25, "integrity_gate", Client, "", "P1"),
    f(26, "spreadsheet_formulas", Client, "", "P1"),
    f(27, "live_updates", Unchanged, "", "P1"),
    f(28, "office_google_addins", Refused, "delegated_keys", "P2"),
    f(29, "agent_reads", Refused, "local_agent", "P1"),
    f(30, "backups", Unchanged, "", "P1"),
    f(31, "quotas", Unchanged, "", "P1"),
    f(32, "telemetry", Unchanged, "", "P1"),
    f(33, "project_policy", Unchanged, "", "P1"),
    f(34, "profile_activity", Unchanged, "", "P1"),
];

/// The matrix row for a feature code.
pub fn feature(code: &str) -> Option<&'static Feature> {
    MATRIX.iter().find(|f| f.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_matrix_has_34_numbered_unique_rows_and_every_refusal_names_an_alternative() {
        let mut codes = std::collections::BTreeSet::new();
        for (i, row) in MATRIX.iter().enumerate() {
            assert_eq!(row.row as usize, i + 1);
            assert!(codes.insert(row.code));
            assert_eq!(
                row.behaviour == Behaviour::Refused,
                !row.alternative.is_empty(),
                "{}",
                row.code
            );
        }
        assert_eq!(
            feature("search").map(|f| f.alternative),
            Some("client_side_search")
        );
    }
}
