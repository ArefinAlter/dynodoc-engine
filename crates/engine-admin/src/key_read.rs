//! Unencrypted Ed25519 PKCS#8 DER key and secret-file reader for server-operator commands.

use anyhow::Context as _;
use ring::signature::Ed25519KeyPair;
use std::{io::Read, path::Path};

const MAX_KEY_FILE_BYTES: usize = 64 * 1024;

pub(crate) fn read_key_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode() & 0o7777;
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{} is accessible by other accounts (mode {mode:04o}); run `chmod 600` on it",
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity(4097);
    file.take(MAX_KEY_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_KEY_FILE_BYTES,
        "key file too large: {}",
        path.display()
    );
    Ok(bytes)
}

pub(crate) fn load(path: &Path) -> anyhow::Result<Ed25519KeyPair> {
    let bytes = read_key_file(path)?;
    anyhow::ensure!(bytes.len() <= 4096, "signing key file too large");
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid unencrypted Ed25519 PKCS#8 key file"))
}
