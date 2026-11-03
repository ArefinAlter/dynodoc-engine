//! Versioned normalized state export format (`dynodoc.state-export`, v1).
//!
//! Exports a single historical file from a signed commit as a self-contained
//! normalized DocumentState JSON envelope. It is not a DOCX/XLSX/PPTX binary,
//! but a verified canonical document model at an exact commit.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::materializer::DocumentState;
use crate::repository::SignedCommit;

/// Format identifier for normalized historical state exports.
pub const STATE_EXPORT_FORMAT: &str = "dynodoc.state-export";

/// Current format version for state exports.
pub const STATE_EXPORT_VERSION: u32 = 1;

/// Maximum size in bytes allowed for a state export JSON output (64 MiB).
pub const MAX_STATE_EXPORT_BYTES: usize = 64 * 1024 * 1024;

/// Versioned normalized state export envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateExportEnvelope {
    pub format: String,
    pub version: u32,
    pub path: String,
    pub commit: SignedCommit,
    pub state: DocumentState,
}

impl StateExportEnvelope {
    pub fn new(path: String, commit: SignedCommit, state: DocumentState) -> Self {
        Self {
            format: STATE_EXPORT_FORMAT.to_string(),
            version: STATE_EXPORT_VERSION,
            path,
            commit,
            state,
        }
    }

    /// Write this envelope to a new file created exclusively (refuses overwrite),
    /// setting 0600 permissions on Unix.
    ///
    /// If writing or serialization fails, any incomplete output file is cleaned up.
    pub fn write_to_path<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let p = path.as_ref();
        anyhow::ensure!(
            !p.exists(),
            "output file {} already exists; refusing overwrite",
            p.display()
        );

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p)
            .map_err(|e| anyhow::anyhow!("creating output file at {}: {e}", p.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
        }

        let write_result = (|| -> anyhow::Result<()> {
            let json_bytes = serde_json::to_vec_pretty(self)?;
            anyhow::ensure!(
                json_bytes.len() <= MAX_STATE_EXPORT_BYTES,
                "exported state exceeds maximum size limit ({} bytes)",
                MAX_STATE_EXPORT_BYTES
            );
            file.write_all(&json_bytes)?;
            file.flush()?;
            Ok(())
        })();

        if let Err(err) = write_result {
            let _ = std::fs::remove_file(p);
            return Err(err);
        }

        Ok(())
    }
}
