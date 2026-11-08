//! The E2EE fields of project commit v4 (protocol 4.3). Commit format v4 is owned by the
//! engine-merge work (merge records, relocations, policy); this adds only `sealed`, and the
//! rules a sealed commit obeys (decision 035 records the coordination):
//!
//! - `files` keys are document UUIDs equal to their entry's `document`;
//! - `message` is empty; the message and the path map are inline `DYNOSEAL` kind 5
//!   envelopes (base64url, no padding) under `K_meta`;
//! - at most 2048 files (the inline path map, OQ-PR-3);
//! - `sealed.epoch` and `sealed.membership_head` bind the commit to an epoch and a log
//!   position, which the service checks against the project's records.
use super::{seal, Error};
use crate::repository::Commit;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

pub const MAX_SEALED_FILES: usize = 2048;
/// The AAD node fields that tell a sealed message from a sealed path map.
pub const MESSAGE_NODE: &str = "commit.message";
pub const PATHS_NODE: &str = "commit.paths";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub epoch: u32,
    pub membership_head: String,
    pub message: String,
    pub paths: String,
}

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|_| Error::Malformed("sealed envelope encoding"))
}

impl Sealed {
    /// Keyless structural checks of a sealed commit (the service's view).
    pub fn validate(&self, commit: &Commit) -> Result<(), Error> {
        if !commit.message.is_empty() {
            return Err(Error::Refused("a sealed commit carries its message sealed"));
        }
        if commit.files.len() > MAX_SEALED_FILES {
            return Err(Error::Limit("sealed commit files"));
        }
        if commit
            .files
            .iter()
            .any(|(key, file)| *key != file.document.0.hyphenated().to_string())
        {
            return Err(Error::Malformed(
                "sealed commit file keys must be document UUIDs",
            ));
        }
        if self.epoch == 0 {
            return Err(Error::Malformed("sealed commit epoch"));
        }
        super::unhex::<32>(&self.membership_head, "membership head")?;
        for envelope in [&self.message, &self.paths] {
            let (header, _) = seal::Header::parse(&decode(envelope)?)?;
            if header.kind != seal::Kind::Meta || header.epoch > self.epoch {
                return Err(Error::Malformed("sealed commit envelope"));
            }
        }
        Ok(())
    }
}
