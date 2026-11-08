//! Offline signing of an enrollment challenge, and key file creation and
//! protection. Private keys never leave this process.
use crate::{
    keyfile, keystore,
    keystore::Provider,
    passphrase::{Secret, Sources},
};
use clap::Subcommand;
use engine_core::repository::device::{Challenge, Proof, MAX_PROOF_BYTES};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Subcommand)]
pub enum Action {
    /// Create a new Ed25519 signing key and print its public key. Never overwrites
    /// a file. The file is the long-lived credential for `sync --device-key`: it is
    /// created readable by you only (mode 0600; on Windows an access list with just
    /// your account, verified) and creation fails if that cannot be applied unless
    /// `--allow-insecure-key-file` is passed. Without `--encrypt` it is an
    /// unencrypted DER PKCS#8 file. Enroll it in your profile, then grant it the
    /// projects it may use.
    Keygen {
        #[arg(long)]
        out: PathBuf,
        /// Encrypt the key file (dynodoc-key-v2: the signing key and a separate, random
        /// device encryption key for encrypted projects). The passphrase comes from
        /// --passphrase-file, DYNODOC_KEY_PASSPHRASE_FILE or a hidden prompt (asked
        /// twice); it is never accepted as an argument.
        #[arg(long)]
        encrypt: bool,
        /// With --encrypt: do not use a passphrase. A random secret is generated and
        /// held by the operating system (Windows DPAPI, macOS Keychain, Linux Secret
        /// Service through secret-tool). The file then opens only for that OS account.
        #[arg(long, requires = "encrypt")]
        keystore: bool,
    },
    /// Display the public key to enroll through your authenticated profile.
    PublicKey { key: PathBuf },
    /// Prove possession for the installation/account shown in your profile.
    Prove {
        challenge: PathBuf,
        #[arg(long)]
        authority: Uuid,
        #[arg(long)]
        identity: Uuid,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Encrypt an existing unencrypted key file. Replaces the file atomically with
    /// the same owner-only protection, or writes a new file with --out (never
    /// overwriting one). The key and its public key do not change, so an enrolled
    /// key stays enrolled. Old plaintext disk blocks are not erased: if the key may
    /// have been copied, generate and enroll a new one instead.
    Protect {
        key: PathBuf,
        /// Write the encrypted copy here and leave KEY untouched.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Use an OS-held secret instead of a passphrase (see keygen --keystore).
        #[arg(long)]
        keystore: bool,
    },
    /// Re-encrypt a passphrase-protected key file with the current key derivation
    /// (Argon2id), for example one written before it existed. The new passphrase
    /// comes from the same sources as the current one, so with --passphrase-file the
    /// passphrase stays the same. The key never touches the disk unencrypted, and
    /// the public key does not change.
    Rewrap {
        key: PathBuf,
        /// Write the re-encrypted copy here and leave KEY untouched.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Give a dynodoc-key-v1 file a separate encryption key: rewrite it as
    /// dynodoc-key-v2 under the same passphrase or OS key store. Both public keys stay
    /// the same (the encryption key it derived from the signing key is carried over), so
    /// nothing needs enrolling again; from then on each key can be rotated alone.
    UpgradeKey {
        key: PathBuf,
        /// Write the upgraded copy here and leave KEY untouched.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Replace one key of a dynodoc-key-v2 file and keep the other, under the same
    /// passphrase. Written to a new file: keep KEY until the new key is enrolled (a new
    /// signing key: `device prove`; a new encryption key: `e2ee enroll`) and each
    /// encrypted project has added it.
    Rotate {
        key: PathBuf,
        #[arg(long, value_enum)]
        which: Which,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write the unencrypted key back to disk (the opposite of protect). The
    /// private key will again be readable by anyone who can read the file.
    Unprotect {
        key: PathBuf,
        /// Write the plain key here and leave KEY untouched.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Required: confirms that you want an unencrypted private key on disk.
        #[arg(long)]
        i_understand: bool,
    },
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Which key `device rotate` replaces.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Which {
    Signing,
    Encryption,
}

/// A new random device encryption secret.
fn new_encryption_key() -> anyhow::Result<Secret> {
    let key = engine_core::e2ee::keys::Key::random().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Secret::new(key.as_bytes().to_vec()))
}

/// The encryption key a v1 or plain file has used until now: derived from its signing seed
/// (decision 035 before dynodoc-key-v2). Carried into v2 so nothing needs enrolling again.
fn derived_encryption_key(pkcs8: &[u8]) -> anyhow::Result<Secret> {
    // RFC 8410: both PKCS#8 versions put the 32-byte seed at offset 16.
    let seed: &[u8; 32] = pkcs8
        .get(16..48)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid signing key"))?;
    let key = engine_core::e2ee::grant::DeviceKey::from_signing_seed(seed)
        .and_then(|k| k.secret())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Secret::new(key.as_bytes().to_vec()))
}

/// Encrypt `pkcs8` for storage. `provider` None locks it with a new passphrase;
/// Some stores a random wrapping secret in that OS keystore. Returns the file
/// bytes and, when an external keystore entry was created, its provider so a
/// failed write can remove it again.
fn container(
    pkcs8: &[u8],
    encryption: Option<&[u8]>,
    provider: Option<Provider>,
    sources: &Sources,
    label: &str,
) -> anyhow::Result<(Vec<u8>, Option<Provider>)> {
    let public = keyfile::public_key_of(pkcs8)?;
    match provider {
        None => {
            let secret = crate::passphrase::create(sources, label)?;
            Ok((
                keyfile::seal_keys(pkcs8, encryption, secret.as_bytes(), None)?,
                None,
            ))
        }
        Some(provider) => {
            let secret = keystore::random_secret()?;
            let blob = keystore::store(provider, &public, &secret)?;
            let binding = keyfile::Keystore {
                provider: provider.name().to_owned(),
                blob: blob.as_deref().map(keystore::encode_blob),
            };
            match keyfile::seal_keys(pkcs8, encryption, secret.as_bytes(), Some(binding)) {
                Ok(bytes) => Ok((bytes, (!provider.blob_in_file()).then_some(provider))),
                Err(error) => {
                    let _ = keystore::forget(provider, &public);
                    Err(error)
                }
            }
        }
    }
}

/// Generate a key with the system CSPRNG, store it exclusively and owner-only
/// (see `private_file`) and return its lowercase hexadecimal public key. The
/// private key is never printed. `provider` is meaningful only with `encrypt`.
fn keygen(
    out: &Path,
    encrypt: bool,
    provider: Option<Provider>,
    sources: &Sources,
) -> anyhow::Result<String> {
    // Before any secret is stored anywhere (a keystore entry must not be orphaned).
    anyhow::ensure!(
        !out.exists(),
        "cannot create {} (an existing file is never overwritten)",
        out.display()
    );
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("system random generator failed"))?;
    let pkcs8 = Secret::new(pkcs8.as_ref().to_vec());
    // The written bytes must load through the same parser every signing command uses.
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_bytes())
        .map_err(|_| anyhow::anyhow!("generated key failed validation"))?;
    let public = hex(key.public_key().as_ref());
    let (bytes, external) = if encrypt {
        container(
            pkcs8.as_bytes(),
            Some(new_encryption_key()?.as_bytes()),
            provider,
            sources,
            &out.display().to_string(),
        )?
    } else {
        (pkcs8.as_bytes().to_vec(), None)
    };
    if let Err(error) = crate::private_file::write_new(out, &bytes) {
        if let Some(provider) = external {
            let _ = keystore::forget(provider, &public);
        }
        return Err(error);
    }
    Ok(public)
}

/// Encrypt an existing plain key file (in place, or into a new `out`).
fn protect(
    path: &Path,
    out: Option<&Path>,
    provider: Option<Provider>,
    sources: &Sources,
) -> anyhow::Result<String> {
    let bytes = Secret::new(crate::signing::read_key_file(path)?);
    anyhow::ensure!(
        !keyfile::is_container(bytes.as_bytes()),
        "{} is already encrypted",
        path.display()
    );
    let public = keyfile::public_key_of(bytes.as_bytes())?;
    // Prepared before the secret is chosen: permission problems surface while the
    // original is still the only copy.
    let replacement = match out {
        Some(_) => None,
        None => {
            let replacement = crate::private_file::Replacement::prepare(path)?;
            replacement.keep_mode_of(path);
            Some(replacement)
        }
    };
    let (encrypted, external) = container(
        bytes.as_bytes(),
        Some(derived_encryption_key(bytes.as_bytes())?.as_bytes()),
        provider,
        sources,
        &path.display().to_string(),
    )?;
    let written = match (out, replacement) {
        (Some(out), _) => crate::private_file::write_new(out, &encrypted),
        (None, Some(replacement)) => replacement.commit(&encrypted),
        (None, None) => unreachable!("in-place protection always has a replacement"),
    };
    if let Err(error) = written {
        if let Some(provider) = external {
            let _ = keystore::forget(provider, &public);
        }
        return Err(error);
    }
    Ok(public)
}

/// Re-encrypt a passphrase-protected key file under the current key derivation
/// (in place, or into a new `out`).
fn rewrap(path: &Path, out: Option<&Path>, sources: &Sources) -> anyhow::Result<String> {
    let bytes = crate::signing::read_key_file(path)?;
    anyhow::ensure!(
        keyfile::is_container(&bytes),
        "{} is not an encrypted key file",
        path.display()
    );
    let parsed = keyfile::Container::parse(&bytes)?;
    anyhow::ensure!(
        parsed.keystore().is_none(),
        "{} is bound to an operating-system key store; it has no passphrase to rewrap",
        path.display()
    );
    let secret = crate::signing::wrapping_secret(&parsed, path, sources)?;
    let (pkcs8, encryption) = parsed.open_keys(secret.as_bytes())?;
    let public = parsed.public_key().to_owned();
    let replacement = match out {
        Some(_) => None,
        None => {
            let replacement = crate::private_file::Replacement::prepare(path)?;
            replacement.keep_mode_of(path);
            Some(replacement)
        }
    };
    let (encrypted, _) = container(
        pkcs8.as_bytes(),
        encryption.as_ref().map(Secret::as_bytes),
        None,
        sources,
        &path.display().to_string(),
    )?;
    match (out, replacement) {
        (Some(out), _) => crate::private_file::write_new(out, &encrypted)?,
        (None, Some(replacement)) => replacement.commit(&encrypted)?,
        (None, None) => unreachable!("in-place rewrap always has a replacement"),
    }
    Ok(public)
}

/// Rewrite an encrypted key file as dynodoc-key-v2 under the same passphrase or key-store
/// secret, with the keys `change` makes of its signing key and encryption key (None in a v1
/// file). In place, or into a new `out`. Returns the signing and encryption public keys.
fn rekey(
    path: &Path,
    out: Option<&Path>,
    sources: &Sources,
    change: impl FnOnce(Secret, Option<Secret>) -> anyhow::Result<(Secret, Secret)>,
) -> anyhow::Result<(String, String)> {
    let bytes = crate::signing::read_key_file(path)?;
    anyhow::ensure!(
        keyfile::is_container(&bytes),
        "{} is not an encrypted key file (encrypt it with `device protect`)",
        path.display()
    );
    let parsed = keyfile::Container::parse(&bytes)?;
    let secret = crate::signing::wrapping_secret(&parsed, path, sources)?;
    let (pkcs8, encryption) = parsed.open_keys(secret.as_bytes())?;
    let (pkcs8, encryption) = change(pkcs8, encryption)?;
    let public = keyfile::public_key_of(pkcs8.as_bytes())?;
    let replacement = match out {
        Some(_) => None,
        None => {
            let replacement = crate::private_file::Replacement::prepare(path)?;
            replacement.keep_mode_of(path);
            Some(replacement)
        }
    };
    let (sealed, external) = match parsed.keystore() {
        // A key-store entry is bound to the signing key, so a new signing key gets its own.
        Some(binding) if public != parsed.public_key() => container(
            pkcs8.as_bytes(),
            Some(encryption.as_bytes()),
            Some(
                Provider::parse(&binding.provider)
                    .ok_or_else(|| anyhow::anyhow!("unknown keystore provider"))?,
            ),
            sources,
            &path.display().to_string(),
        )?,
        binding => (
            keyfile::seal_keys(
                pkcs8.as_bytes(),
                Some(encryption.as_bytes()),
                secret.as_bytes(),
                binding.cloned(),
            )?,
            None,
        ),
    };
    let written = match (out, replacement) {
        (Some(out), _) => crate::private_file::write_new(out, &sealed),
        (None, Some(replacement)) => replacement.commit(&sealed),
        (None, None) => unreachable!("in-place rekeying always has a replacement"),
    };
    if let Err(error) = written {
        if let Some(provider) = external {
            let _ = keystore::forget(provider, &public);
        }
        return Err(error);
    }
    Ok((
        public,
        keyfile::encryption_public_of(encryption.as_bytes())?,
    ))
}

/// dynodoc-key-v1 to v2, both keys unchanged.
fn upgrade(path: &Path, out: Option<&Path>, sources: &Sources) -> anyhow::Result<(String, String)> {
    rekey(path, out, sources, |pkcs8, encryption| {
        anyhow::ensure!(
            encryption.is_none(),
            "{} is already a dynodoc-key-v2 file",
            path.display()
        );
        let derived = derived_encryption_key(pkcs8.as_bytes())?;
        Ok((pkcs8, derived))
    })
}

/// One new key in a dynodoc-key-v2 file, the other kept.
fn rotate(
    path: &Path,
    which: Which,
    out: &Path,
    sources: &Sources,
) -> anyhow::Result<(String, String)> {
    rekey(path, Some(out), sources, |pkcs8, encryption| {
        let encryption = encryption.ok_or_else(|| {
            anyhow::anyhow!(
                "{} is a dynodoc-key-v1 file; run `device upgrade-key` first",
                path.display()
            )
        })?;
        Ok(match which {
            Which::Encryption => (pkcs8, new_encryption_key()?),
            Which::Signing => {
                let fresh = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map_err(|_| anyhow::anyhow!("system random generator failed"))?;
                (Secret::new(fresh.as_ref().to_vec()), encryption)
            }
        })
    })
}

/// Decrypt an encrypted key file back to plain DER (in place, or into `out`).
fn unprotect(
    path: &Path,
    out: Option<&Path>,
    understood: bool,
    sources: &Sources,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        understood,
        "this writes your private key to disk unencrypted; repeat with --i-understand to confirm"
    );
    let bytes = crate::signing::read_key_file(path)?;
    anyhow::ensure!(
        keyfile::is_container(&bytes),
        "{} is not an encrypted key file",
        path.display()
    );
    let parsed = keyfile::Container::parse(&bytes)?;
    let pkcs8 = crate::signing::unlock(&parsed, path, sources)?;
    let public = parsed.public_key().to_owned();
    let binding = parsed
        .keystore()
        .and_then(|k| Provider::parse(&k.provider))
        .filter(|p| !p.blob_in_file());
    match out {
        Some(out) => crate::private_file::write_new(out, pkcs8.as_bytes())?,
        None => {
            let replacement = crate::private_file::Replacement::prepare(path)?;
            replacement.keep_mode_of(path);
            replacement.commit(pkcs8.as_bytes())?;
        }
    }
    if let Some(provider) = binding {
        if let Err(error) = keystore::forget(provider, &public) {
            eprintln!("warning: the key file is now plain, but its OS keystore entry could not be removed: {error}");
        }
    }
    Ok(public)
}

pub fn run(action: Action) -> anyhow::Result<()> {
    match action {
        Action::Keygen {
            out,
            encrypt,
            keystore: os_keystore,
        } => {
            let provider = if os_keystore {
                Some(Provider::native()?)
            } else {
                None
            };
            println!("{}", keygen(&out, encrypt, provider, &Sources::current())?);
        }
        Action::PublicKey { key } => {
            let key = crate::signing::load_signer(&key)?;
            println!("{}", hex(&key.public_key_bytes()));
        }
        Action::Prove {
            challenge,
            authority,
            identity,
            key,
            out,
        } => {
            let mut bytes = Vec::new();
            std::fs::File::open(challenge)?
                .take(MAX_PROOF_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= MAX_PROOF_BYTES, "challenge too large");
            let challenge: Challenge = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                challenge.expires_at_ms as u128
                    > std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_millis(),
                "challenge expired; request a fresh challenge"
            );
            let signer = crate::signing::load_signer(&key)?;
            let proof = Proof::sign(challenge, authority, identity, &*signer)?;
            // Never overwrite a key or an unrelated existing file by mistake.
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out)?;
            serde_json::to_writer_pretty(file, &proof)?;
            println!("Enrollment proof saved. Submit it through the same signed-in profile.");
        }
        Action::Protect {
            key,
            out,
            keystore: os_keystore,
        } => {
            let provider = if os_keystore {
                Some(Provider::native()?)
            } else {
                None
            };
            let public = protect(&key, out.as_deref(), provider, &Sources::current())?;
            eprintln!(
                "The key file is now encrypted (dynodoc-key-v2). Its public key is unchanged:"
            );
            println!("{public}");
        }
        Action::Rewrap { key, out } => {
            let public = rewrap(&key, out.as_deref(), &Sources::current())?;
            eprintln!(
                "The key file is re-encrypted with the current key derivation. Its public key is unchanged:"
            );
            println!("{public}");
        }
        Action::UpgradeKey { key, out } => {
            let (signing, encryption) = upgrade(&key, out.as_deref(), &Sources::current())?;
            eprintln!("The key file is now dynodoc-key-v2 with a separate encryption key. Both public keys are unchanged (signing, then encryption):");
            println!("{signing}\n{encryption}");
        }
        Action::Rotate { key, which, out } => {
            let (signing, encryption) = rotate(&key, which, &out, &Sources::current())?;
            eprintln!(
                "{} written with a new {} key; the other key is unchanged. Enroll the new key, then add it to each encrypted project before deleting {} (signing, then encryption):",
                out.display(),
                if which == Which::Signing { "signing" } else { "encryption" },
                key.display()
            );
            println!("{signing}\n{encryption}");
        }
        Action::Unprotect {
            key,
            out,
            i_understand,
        } => {
            let public = unprotect(&key, out.as_deref(), i_understand, &Sources::current())?;
            eprintln!("The key file is now unencrypted. Its public key is unchanged:");
            println!("{public}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    pub(crate) const PASSPHRASE: &[u8] = b"synthetic test passphrase 0001";

    /// One shared passphrase file for every test that needs an encrypted key, so
    /// parallel tests agree on the process-wide `--passphrase-file` value.
    pub(crate) fn passphrase_file() -> &'static Path {
        static FILE: OnceLock<PathBuf> = OnceLock::new();
        FILE.get_or_init(|| {
            let path =
                std::env::temp_dir().join(format!("dynodoc-test-passphrase-{}", Uuid::new_v4()));
            crate::private_file::write_private_test(&path, [PASSPHRASE, b"\n"].concat()).unwrap();
            path
        })
    }

    pub(crate) fn sources() -> Sources {
        Sources {
            file: Some(passphrase_file().to_owned()),
            ..Default::default()
        }
    }

    fn dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dynodoc-keygen-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn public_of(key: &Ed25519KeyPair) -> String {
        hex(key.public_key().as_ref())
    }

    #[test]
    fn keygen_creates_a_loadable_private_key_once() {
        let dir = dir();
        let path = dir.join("signing-key.der");
        let none = Sources::default();
        let public = keygen(&path, false, None, &none).unwrap();
        assert_eq!(public.len(), 64);
        let loaded = crate::signing::load(&path).unwrap();
        assert_eq!(public, public_of(&loaded));
        // A second run neither overwrites the key nor prints another one.
        let before = std::fs::read(&path).unwrap();
        assert!(keygen(&path, false, None, &none).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_ne!(
            keygen(&dir.join("another.der"), false, None, &none).unwrap(),
            public
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn encrypted_keygen_round_trips_and_hides_the_private_key() {
        let dir = dir();
        let path = dir.join("encrypted-key.json");
        let public = keygen(&path, true, None, &sources()).unwrap();
        let file = std::fs::read(&path).unwrap();
        assert!(keyfile::is_container(&file));
        let text = String::from_utf8(file.clone()).unwrap();
        assert!(text.contains(&public), "the public key is readable");
        assert!(!text.contains(std::str::from_utf8(PASSPHRASE).unwrap()));
        crate::private_file::assert_owner_only(&path);
        // No source: a clear error, and nothing about the key. (Checked before the
        // first successful load, which would cache the key for this process.)
        let error = crate::signing::load_with(&path, &Sources::default())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("passphrase source"), "{error}");
        // A wrong passphrase file is the generic error.
        let wrong = dir.join("wrong");
        crate::private_file::write_private_test(
            &wrong,
            "not the right passphrase at all
",
        )
        .unwrap();
        let error = crate::signing::load_with(
            &path,
            &Sources {
                file: Some(wrong),
                ..Default::default()
            },
        )
        .err()
        .unwrap()
        .to_string();
        assert!(
            error.contains("wrong passphrase, or the file was changed"),
            "{error}"
        );
        let loaded = crate::signing::load_with(&path, &sources()).unwrap();
        assert_eq!(public_of(&loaded), public);
        // An existing file is never overwritten and the file is unchanged.
        assert!(keygen(&path, true, None, &sources()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), file);
        // A too-short new passphrase creates nothing.
        let short = dir.join("short");
        crate::private_file::write_private_test(&short, "short\n").unwrap();
        let target = dir.join("never.json");
        assert!(keygen(
            &target,
            true,
            None,
            &Sources {
                file: Some(short),
                ..Default::default()
            }
        )
        .is_err());
        assert!(!target.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rewrap_moves_a_pbkdf2_file_to_argon2id_and_keeps_the_key() {
        let dir = dir();
        let path = dir.join("old-key.json");
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let public = keyfile::public_key_of(key.as_ref()).unwrap();
        let old = keyfile::seal_with(
            key.as_ref(),
            PASSPHRASE,
            None,
            keyfile::KdfParams::Pbkdf2 {
                iterations: keyfile::MIN_ITERATIONS,
            },
            &[3u8; keyfile::SALT_BYTES],
            [4u8; keyfile::NONCE_BYTES],
        )
        .unwrap();
        crate::private_file::write_new(&path, &old).unwrap();
        let kdf_of = |bytes: &[u8]| {
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap()["kdf"]["name"].clone()
        };
        assert_eq!(kdf_of(&old), keyfile::KDF_NAME);

        assert_eq!(rewrap(&path, None, &sources()).unwrap(), public);
        let new = std::fs::read(&path).unwrap();
        assert_eq!(kdf_of(&new), keyfile::ARGON2ID_NAME);
        crate::private_file::assert_owner_only(&path);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        // Same passphrase, same key.
        let loaded = crate::signing::load_with(&path, &sources()).unwrap();
        assert_eq!(public_of(&loaded), public);
        // A plain key, and a key-store-bound file, are not rewrapped.
        let plain = dir.join("plain.der");
        keygen(&plain, false, None, &Sources::default()).unwrap();
        let error = rewrap(&plain, None, &sources()).unwrap_err().to_string();
        assert!(error.contains("not an encrypted key file"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn protect_in_place_keeps_the_key_and_the_owner_only_access() {
        let dir = dir();
        let path = dir.join("signing-key.der");
        let public = keygen(&path, false, None, &Sources::default()).unwrap();
        let plain = std::fs::read(&path).unwrap();
        let before_public = public_of(&crate::signing::load(&path).unwrap());
        assert_eq!(before_public, public);

        assert_eq!(protect(&path, None, None, &sources()).unwrap(), public);
        let encrypted = std::fs::read(&path).unwrap();
        assert!(keyfile::is_container(&encrypted));
        assert!(!encrypted.windows(32).any(|w| w == &plain[16..48]));
        crate::private_file::assert_owner_only(&path);
        // No temporary files are left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        // Same key, same public key, through the transparent loader.
        let loaded = crate::signing::load_with(&path, &sources()).unwrap();
        assert_eq!(public_of(&loaded), public);
        // A second protect refuses and leaves the file as it is.
        let error = protect(&path, None, None, &sources())
            .unwrap_err()
            .to_string();
        assert!(error.contains("already encrypted"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), encrypted);

        // Unprotect needs the explicit confirmation and then restores the plain key.
        let error = unprotect(&path, None, false, &sources())
            .unwrap_err()
            .to_string();
        assert!(error.contains("--i-understand"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), encrypted);
        assert_eq!(unprotect(&path, None, true, &sources()).unwrap(), public);
        assert_eq!(std::fs::read(&path).unwrap(), plain);
        crate::private_file::assert_owner_only(&path);
        assert!(unprotect(&path, None, true, &sources()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn protect_to_a_new_file_never_overwrites_and_failure_changes_nothing() {
        let dir = dir();
        let path = dir.join("signing-key.der");
        keygen(&path, false, None, &Sources::default()).unwrap();
        let plain = std::fs::read(&path).unwrap();
        let out = dir.join("protected.json");
        protect(&path, Some(&out), None, &sources()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), plain, "original untouched");
        let first = std::fs::read(&out).unwrap();
        // The destination exists now: refused, both files unchanged.
        assert!(protect(&path, Some(&out), None, &sources()).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), first);
        assert_eq!(std::fs::read(&path).unwrap(), plain);
        // No passphrase source: nothing is created, the key stays.
        let other = dir.join("other.json");
        assert!(protect(&path, Some(&other), None, &Sources::default()).is_err());
        assert!(!other.exists());
        assert!(protect(&path, None, None, &Sources::default()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), plain);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        // Unprotect into a new file leaves the encrypted source in place.
        let plain_copy = dir.join("plain-copy.der");
        unprotect(&out, Some(&plain_copy), true, &sources()).unwrap();
        assert_eq!(std::fs::read(&plain_copy).unwrap(), plain);
        assert_eq!(std::fs::read(&out).unwrap(), first);
        assert!(unprotect(&out, Some(&plain_copy), true, &sources()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keystore_bound_keys_need_no_passphrase_and_forget_on_unprotect() {
        let dir = dir();
        let path = dir.join("keystore-key.json");
        // No passphrase source at all: the secret is held by the (test) keystore.
        let none = Sources::default();
        let public = keygen(&path, true, Some(Provider::Memory), &none).unwrap();
        let file = std::fs::read(&path).unwrap();
        let text = String::from_utf8(file).unwrap();
        assert!(text.contains("test-memory"));
        let loaded = crate::signing::load_with(&path, &none).unwrap();
        assert_eq!(public_of(&loaded), public);
        // Converting back removes the stored secret; the file can no longer open.
        assert_eq!(unprotect(&path, None, true, &none).unwrap(), public);
        assert_eq!(
            public_of(&crate::signing::load_with(&path, &none).unwrap()),
            public
        );
        assert!(keystore::load(Provider::Memory, &public, None).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Real DPAPI on Windows: the wrapping secret is inside the file, protected for
    /// this account, and the key loads with no passphrase and no external state.
    #[cfg(windows)]
    #[test]
    fn dpapi_bound_key_works_on_this_windows_account() {
        let dir = dir();
        let path = dir.join("dpapi-key.json");
        let none = Sources::default();
        let public = keygen(&path, true, Some(Provider::WindowsDpapi), &none).unwrap();
        let file = std::fs::read(&path).unwrap();
        let text = String::from_utf8(file).unwrap();
        assert!(text.contains("windows-dpapi"));
        assert!(text.contains("\"blob\""));
        crate::private_file::assert_owner_only(&path);
        assert_eq!(
            public_of(&crate::signing::load_with(&path, &none).unwrap()),
            public
        );
        // The file is plain JSON with an opaque blob; copying only it elsewhere on
        // the same account still works, and editing the blob does not.
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let blob = value["keystore"]["blob"].as_str().unwrap().to_owned();
        // DPAPI blobs start with the same bytes ("AQAAANCM..."); change one inside.
        let mut chars: Vec<char> = blob.chars().collect();
        chars[40] = if chars[40] == 'A' { 'B' } else { 'A' };
        value["keystore"]["blob"] = chars.into_iter().collect::<String>().into();
        let damaged = dir.join("damaged.json");
        crate::private_file::write_private_test(&damaged, serde_json::to_vec(&value).unwrap())
            .unwrap();
        assert!(crate::signing::load_with(&damaged, &none).is_err());
        // Existing plain key -> DPAPI-bound -> plain, in place.
        let plain = dir.join("plain.der");
        keygen(&plain, false, None, &none).unwrap();
        let before = std::fs::read(&plain).unwrap();
        protect(&plain, None, Some(Provider::WindowsDpapi), &none).unwrap();
        assert!(keyfile::is_container(&std::fs::read(&plain).unwrap()));
        unprotect(&plain, None, true, &none).unwrap();
        assert_eq!(std::fs::read(&plain).unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn no_command_line_option_accepts_a_passphrase_value() {
        use clap::CommandFactory;
        #[derive(clap::Parser)]
        struct Wrapper {
            #[command(subcommand)]
            action: Action,
        }
        let command = Wrapper::command();
        for sub in command.get_subcommands() {
            for arg in sub.get_arguments() {
                let id = arg.get_id().as_str();
                assert!(
                    !id.contains("passphrase")
                        && !id.contains("password")
                        && !id.contains("secret"),
                    "{} {id}",
                    sub.get_name()
                );
            }
        }
        // And clap itself refuses an attempt to pass one.
        let attempt = <Wrapper as clap::Parser>::try_parse_from([
            "engine-cli",
            "keygen",
            "--out",
            "k",
            "--encrypt",
            "--passphrase",
            "hunter2-hunter2",
        ]);
        assert!(attempt.is_err());
    }

    /// dynodoc-key-v2 (decision 035, OQ-CR-5): a v1 file still opens with the encryption key
    /// derived from its signing key; `upgrade-key` carries both keys into v2 unchanged; then
    /// each key rotates without the other, under the same passphrase.
    #[test]
    fn v1_still_opens_upgrades_to_v2_and_each_key_rotates_alone() {
        let dir = dir();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let v1 = dir.join("v1.json");
        crate::private_file::write_private_test(
            &v1,
            keyfile::seal(pkcs8.as_ref(), PASSPHRASE, None).unwrap(),
        )
        .unwrap();
        let old = crate::signing::load_device_keys(&v1, &sources()).unwrap();
        assert!(old.legacy, "a v1 file derives its encryption key");
        let signing = public_of(&crate::signing::load_with(&v1, &sources()).unwrap());
        let encryption = old.encryption.public_hex();
        assert!(
            rotate(&v1, Which::Encryption, &dir.join("no.json"), &sources()).is_err(),
            "rotation needs v2"
        );

        let v2 = dir.join("v2.json");
        assert_eq!(
            upgrade(&v1, Some(&v2), &sources()).unwrap(),
            (signing.clone(), encryption.clone())
        );
        assert!(String::from_utf8(std::fs::read(&v2).unwrap())
            .unwrap()
            .contains("\"dynodoc-key-v2\""));
        let upgraded = crate::signing::load_device_keys(&v2, &sources()).unwrap();
        assert!(!upgraded.legacy);
        assert_eq!(upgraded.encryption.public_hex(), encryption);
        assert!(upgrade(&v2, None, &sources()).is_err(), "already v2");

        // A new encryption key keeps the signing key, and the reverse.
        let enc = dir.join("enc.json");
        let (s1, e1) = rotate(&v2, Which::Encryption, &enc, &sources()).unwrap();
        assert_eq!(s1, signing);
        assert_ne!(e1, encryption);
        let sig = dir.join("sig.json");
        let (s2, e2) = rotate(&enc, Which::Signing, &sig, &sources()).unwrap();
        assert_ne!(s2, signing);
        assert_eq!(e2, e1);
        let rotated = crate::signing::load_device_keys(&sig, &sources()).unwrap();
        assert_eq!(rotated.encryption.public_hex(), e1);
        assert_eq!(
            public_of(&crate::signing::load_with(&sig, &sources()).unwrap()),
            s2
        );
        // The new encryption key is random, not derived from either signing key.
        assert_ne!(
            e1,
            derived_encryption_key(pkcs8.as_ref())
                .map(|k| keyfile::encryption_public_of(k.as_bytes()).unwrap())
                .unwrap()
        );
        // The rotated file stays under the same passphrase; the original is untouched.
        assert_eq!(
            crate::signing::load_device_keys(&v2, &sources())
                .unwrap()
                .encryption
                .public_hex(),
            encryption
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// New encrypted keys are v2 with a random encryption key; a swapped encryption key or an
    /// edited v2 label fails with the generic message.
    #[test]
    fn encrypted_keygen_writes_v2_and_its_encryption_key_is_authenticated() {
        let dir = dir();
        let path = dir.join("new.json");
        let signing = keygen(&path, true, None, &sources()).unwrap();
        let keys = crate::signing::load_device_keys(&path, &sources()).unwrap();
        assert!(!keys.legacy);
        let text = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(text.contains(&keys.encryption.public_hex()));
        assert!(text.contains(&signing));
        let other =
            keyfile::encryption_public_of(new_encryption_key().unwrap().as_bytes()).unwrap();
        for edited in [
            text.replace(&keys.encryption.public_hex(), &other),
            text.replace("dynodoc-key-v2", "dynodoc-key-v1"),
        ] {
            let error = keyfile::Container::parse(edited.as_bytes())
                .and_then(|c| c.open_keys(PASSPHRASE))
                .err()
                .unwrap()
                .to_string();
            assert!(
                error.contains("wrong passphrase") || error.contains("not a valid"),
                "{error}"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
