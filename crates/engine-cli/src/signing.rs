//! Ed25519 PKCS#8 signing keys for the local signing commands: unencrypted DER, or
//! a `dynodoc-key-v1` encrypted container (docs/KEY-FILE-FORMAT.md). Every command
//! that reads a key file goes through [`load`], so encrypted files work wherever a
//! plain key does. A decrypted key is cached in memory for this process only.
use crate::{
    keyfile, keystore,
    passphrase::{Secret, Sources},
};
use engine_core::e2ee::{grant::DeviceKey, keys::Key};
use ring::signature::Ed25519KeyPair;
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
};

fn parse(bytes: &[u8]) -> anyhow::Result<Ed25519KeyPair> {
    anyhow::ensure!(bytes.len() <= 4096, "signing key file too large");
    // OpenSSL exports v1 without a redundant public key. Ring
    // derives that key from the seed; v2 still checks both components match.
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(bytes).map_err(|_| {
        anyhow::anyhow!(
            "invalid Ed25519 PKCS#8 key file (unencrypted DER or a dynodoc-key-v1 container)"
        )
    })
}

/// Read a key file's bytes. On Unix a file that group or others can access is
/// refused (see `private_file::check_key_file`); `--allow-insecure-key-file`
/// accepts it.
pub(crate) fn read_key_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    crate::private_file::check_key_file(&file, path)?;
    let mut bytes = Vec::with_capacity(4097);
    file.take(keyfile::MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= keyfile::MAX_FILE_BYTES,
        "signing key file too large"
    );
    Ok(bytes)
}

/// Decrypt a parsed container: its OS keystore when it names one, otherwise a
/// passphrase from the configured sources.
pub(crate) fn unlock(
    container: &keyfile::Container,
    path: &Path,
    sources: &Sources,
) -> anyhow::Result<Secret> {
    container.open(wrapping_secret(container, path, sources)?.as_bytes())
}

/// The secret a container is wrapped with: from its OS keystore when it names one,
/// otherwise a passphrase from the configured sources.
pub(crate) fn wrapping_secret(
    container: &keyfile::Container,
    path: &Path,
    sources: &Sources,
) -> anyhow::Result<Secret> {
    Ok(match container.keystore() {
        Some(binding) => {
            let provider = keystore::Provider::parse(&binding.provider)
                .ok_or_else(|| anyhow::anyhow!("unknown keystore provider"))?;
            keystore::load(
                provider,
                container.public_key(),
                container.keystore_blob().as_deref(),
            )?
        }
        None => crate::passphrase::unlock(sources, &path.display().to_string())?,
    })
}

/// Decrypted keys (PKCS#8, and a v2 file's encryption secret) for this process, keyed by
/// canonical path and the digest of the exact file content. Never written anywhere.
type Cached = (PathBuf, Vec<u8>, Secret, Option<Secret>);
static CACHE: Mutex<Vec<Cached>> = Mutex::new(Vec::new());

/// A key for the commands that only need signatures (`device public-key`, `device prove`,
/// `repository commit`, `repository recover`, `repository merge` and `relocate`, `receipt sign`;
/// `sync --device-key` and `mcp` take a [`SharedSigner`]): a key file, or a key on a PKCS#11 token when
/// the path is a `pkcs11:` URI (see [`crate::token`]).
pub(crate) fn load_signer(path: &Path) -> anyhow::Result<Box<dyn engine_core::repository::Signer>> {
    match path.to_str().and_then(|p| p.strip_prefix("pkcs11:")) {
        Some(uri) => Ok(Box::new(crate::token::open(uri)?)),
        None => Ok(Box::new(load(path)?)),
    }
}

/// A [`load_signer`] key that tasks on several threads may share: a token session signs for one
/// caller at a time (a PKCS#11 session is not shareable across threads by itself).
pub(crate) struct SharedSigner(Mutex<Box<dyn engine_core::repository::Signer + Send>>);

impl SharedSigner {
    pub(crate) fn new(signer: impl engine_core::repository::Signer + Send + 'static) -> Self {
        Self(Mutex::new(Box::new(signer)))
    }
    /// A key file or a `pkcs11:` URI, as [`load_signer`].
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        Ok(
            match path.to_str().and_then(|p| p.strip_prefix("pkcs11:")) {
                Some(uri) => Self::new(crate::token::open(uri)?),
                None => Self::new(load(path)?),
            },
        )
    }
}

impl engine_core::repository::Signer for SharedSigner {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .map(|s| s.public_key_bytes())
            .unwrap_or_default()
    }
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, engine_core::repository::Error> {
        self.0
            .lock()
            .map_err(|_| engine_core::repository::Error::Invalid("the signing key is unavailable"))?
            .sign_message(message)
    }
}

/// Load a plain or encrypted key file.
pub(crate) fn load(path: &Path) -> anyhow::Result<Ed25519KeyPair> {
    load_with(path, &Sources::current())
}

pub(crate) fn load_with(path: &Path, sources: &Sources) -> anyhow::Result<Ed25519KeyPair> {
    with_keys(path, sources, |pkcs8, _| parse(pkcs8))
}

/// The device keys for encrypted projects: the Ed25519 signing seed and the X25519 device
/// encryption key, both wiped on drop. A `dynodoc-key-v2` file carries its own encryption
/// key (decision 035, owner decision of 6 November 2026). A v1 or plain file still opens:
/// its encryption key is derived from the signing seed as before, and `legacy` is true so
/// the caller can point to `device upgrade-key`.
pub(crate) fn load_device_keys(path: &Path, sources: &Sources) -> anyhow::Result<DeviceKeys> {
    with_keys(path, sources, |pkcs8, encryption| {
        parse(pkcs8)?;
        // RFC 8410: both PKCS#8 versions put the 32-byte seed at offset 16.
        let seed = pkcs8
            .get(16..48)
            .ok_or_else(|| anyhow::anyhow!("invalid signing key"))?;
        let seed = Key::from_slice(seed).map_err(|e| anyhow::anyhow!("{e}"))?;
        let (encryption, legacy) = match encryption {
            Some(secret) => (
                DeviceKey::from_secret(
                    &Key::from_slice(secret).map_err(|e| anyhow::anyhow!("{e}"))?,
                ),
                false,
            ),
            None => (DeviceKey::from_signing_seed(seed.as_bytes()), true),
        };
        Ok(DeviceKeys {
            seed,
            encryption: encryption.map_err(|e| anyhow::anyhow!("{e}"))?,
            legacy,
        })
    })
}

/// See [`load_device_keys`].
pub(crate) struct DeviceKeys {
    pub seed: Key,
    pub encryption: DeviceKey,
    /// The encryption key is derived from the signing seed (a v1 or plain file).
    pub legacy: bool,
}

fn with_keys<T>(
    path: &Path,
    sources: &Sources,
    parse: impl Fn(&[u8], Option<&[u8]>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let bytes = read_key_file(path)?;
    if !keyfile::is_container(&bytes) {
        return parse(&bytes, None);
    }
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .to_vec();
    {
        let cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache
            .iter()
            .find(|entry| entry.0 == canonical && entry.1 == digest)
        {
            return parse(entry.2.as_bytes(), entry.3.as_ref().map(Secret::as_bytes));
        }
    }
    let container = keyfile::Container::parse(&bytes)?;
    let (pkcs8, encryption) =
        container.open_keys(wrapping_secret(&container, path, sources)?.as_bytes())?;
    let value = parse(pkcs8.as_bytes(), encryption.as_ref().map(Secret::as_bytes))?;
    CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((canonical, digest, pkcs8, encryption));
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::repository::attestation::SignedReceipt;
    #[test]
    fn standard_v1_and_v2_keys_work_without_weakening_component_checks() {
        // Public synthetic seed, matching the independent OpenSSL signature fixture.
        let mut v1 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        v1.extend([7; 32]);
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../engine-core/tests/fixtures/ref-receipt-signatures-v1.json"
        ))
        .unwrap();
        let expected: SignedReceipt =
            serde_json::from_value(fixture["first"]["signed"].clone()).unwrap();
        assert_eq!(
            SignedReceipt::sign(expected.receipt.clone(), &parse(&v1).unwrap()).unwrap(),
            expected
        );
        assert!(parse(&v1[..v1.len() - 1]).is_err());
        v1[11] = 0x71; // Ed448 is not an Ed25519 key.
        assert!(parse(&v1).is_err());
        assert!(parse(&vec![0; 4097]).is_err());
        let v2 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        assert!(parse(v2.as_ref()).is_ok());
        let mut mismatch = v2.as_ref().to_vec();
        *mismatch.last_mut().unwrap() ^= 1;
        assert!(
            parse(&mismatch).is_err(),
            "v2 public/private consistency must remain enforced"
        );
    }
}
