//! Device signing keys on a hardware token through PKCS#11 (decision 039): a YubiKey 5.7 or
//! later (PIV, through Yubico's `ykcs11` or OpenSC), a smart card, an HSM, or SoftHSM2 for
//! tests. The Ed25519 private key is created on the token and never leaves it; the token
//! signs the same bytes a key file signs (`CKM_EDDSA`, pure Ed25519), so the server sees an
//! ordinary device key and signature.
//!
//! A key is named by a `pkcs11:token=<token label>;object=<key label>` URI wherever a key
//! file path is accepted by `device public-key`, `device prove`, `repository commit` and
//! `repository recover`. The module comes from `DYNODOC_PKCS11_MODULE`; the user PIN from
//! the passphrase sources (`--passphrase-file`, `DYNODOC_KEY_PASSPHRASE_FILE`, a prompt).
use anyhow::Context as _;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        eddsa::{EddsaParams, EddsaSignatureScheme},
        Mechanism,
    },
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use engine_core::repository::{Error as RepositoryError, Signer};
use ring::signature::{UnparsedPublicKey, ED25519};

/// The environment variable naming the PKCS#11 module (a `.so`, `.dylib` or `.dll`).
pub(crate) const MODULE_ENV: &str = "DYNODOC_PKCS11_MODULE";

/// What a `pkcs11:` URI names. Only the two attributes Dynodoc needs, unencoded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Locator {
    pub token: String,
    pub object: String,
}

/// Parse the part after `pkcs11:` (RFC 7512 path attributes `token` and `object`).
/// Percent-encoding and query attributes are refused rather than guessed at.
pub(crate) fn parse(uri: &str) -> anyhow::Result<Locator> {
    anyhow::ensure!(
        !uri.contains(['%', '?']),
        "use pkcs11:token=<label>;object=<label> without percent-encoding or a query"
    );
    let (mut token, mut object) = (None, None);
    for part in uri.split(';') {
        match part.split_once('=') {
            Some(("token", value)) if token.is_none() && !value.is_empty() => {
                token = Some(value.to_owned())
            }
            Some(("object", value)) if object.is_none() && !value.is_empty() => {
                object = Some(value.to_owned())
            }
            _ => anyhow::bail!("unsupported or repeated pkcs11 URI attribute"),
        }
    }
    Ok(Locator {
        token: token.context("the pkcs11 URI needs token=<label>")?,
        object: object.context("the pkcs11 URI needs object=<label>")?,
    })
}

/// The 32-byte key from `CKA_EC_POINT`: PKCS#11 3.0 stores the DER OCTET STRING
/// (`04 20 || key`); some modules store the 32 bytes bare.
pub(crate) fn ec_point(value: &[u8]) -> anyhow::Result<[u8; 32]> {
    let raw = match value {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        bare if bare.len() == 32 => bare,
        _ => anyhow::bail!("the token's public key is not an Ed25519 point"),
    };
    let mut key = [0; 32];
    key.copy_from_slice(raw);
    Ok(key)
}

/// Refuse a token's answer unless it is a valid signature of `message` by `public`: a
/// misconfigured module (another mechanism, another key) must not yield a bad commit.
pub(crate) fn checked(
    public: &[u8; 32],
    message: &[u8],
    signature: Vec<u8>,
) -> Result<Vec<u8>, RepositoryError> {
    UnparsedPublicKey::new(&ED25519, public)
        .verify(message, &signature)
        .map(|()| signature)
        .map_err(|_| RepositoryError::Invalid("the token returned an invalid Ed25519 signature"))
}

/// A logged-in session holding one Ed25519 private key. Logged out when dropped.
pub(crate) struct TokenSigner {
    session: Session,
    key: ObjectHandle,
    public: [u8; 32],
    // Kept so the module stays loaded and initialized for the session's lifetime.
    _context: Pkcs11,
}

impl Signer for TokenSigner {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public.to_vec()
    }
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        let mechanism = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519));
        let signature = self
            .session
            .sign(&mechanism, self.key, message)
            .map_err(|_| RepositoryError::Invalid("the token refused to sign"))?;
        checked(&self.public, message, signature)
    }
}

fn find(session: &Session, class: ObjectClass, label: &str) -> anyhow::Result<ObjectHandle> {
    let found = session.find_objects(&[
        Attribute::Class(class),
        Attribute::KeyType(KeyType::EC_EDWARDS),
        Attribute::Label(label.as_bytes().to_vec()),
    ])?;
    match found.as_slice() {
        [one] => Ok(*one),
        [] => anyhow::bail!("no Ed25519 key labelled {label:?} on the token"),
        _ => anyhow::bail!("more than one Ed25519 key labelled {label:?} on the token"),
    }
}

/// Open the key a `pkcs11:` URI names (the part after the scheme) and log in.
pub(crate) fn open(uri: &str) -> anyhow::Result<TokenSigner> {
    let locator = parse(uri)?;
    let module = std::env::var_os(MODULE_ENV)
        .filter(|v| !v.is_empty())
        .with_context(|| format!("set {MODULE_ENV} to the token's PKCS#11 module"))?;
    let context = Pkcs11::new(&module).context("cannot load the PKCS#11 module")?;
    context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let mut slot = None;
    for candidate in context.get_slots_with_token()? {
        if context.get_token_info(candidate)?.label().trim_end() == locator.token {
            anyhow::ensure!(
                slot.is_none(),
                "two tokens are labelled {:?}",
                locator.token
            );
            slot = Some(candidate);
        }
    }
    let slot = slot.with_context(|| format!("no token labelled {:?}", locator.token))?;
    let session = context.open_ro_session(slot)?;
    let pin = crate::passphrase::unlock(
        &crate::passphrase::Sources::current(),
        &format!("the PIN of token {:?}", locator.token),
    )?;
    let pin = AuthPin::new(
        std::str::from_utf8(pin.as_bytes())
            .context("the PIN must be UTF-8")?
            .into(),
    );
    session
        .login(UserType::User, Some(&pin))
        .context("the token refused the PIN")?;
    let public = find(&session, ObjectClass::PUBLIC_KEY, &locator.object)?;
    let point = session
        .get_attributes(public, &[AttributeType::EcPoint])?
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(point) => Some(point),
            _ => None,
        })
        .context("the token did not return the public key")?;
    let key = find(&session, ObjectClass::PRIVATE_KEY, &locator.object)?;
    Ok(TokenSigner {
        session,
        key,
        public: ec_point(&point)?,
        _context: context,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::repository::{device::Challenge, device::Proof, Commit, SignedCommit};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::cell::Cell;

    /// A token stand-in behind the same trait: the key is in memory, every signature goes
    /// through [`checked`] as the PKCS#11 signer's does, and a broken token can be faked.
    struct MockToken {
        key: Ed25519KeyPair,
        broken: bool,
        uses: Cell<u32>,
    }
    impl Signer for MockToken {
        fn public_key_bytes(&self) -> Vec<u8> {
            self.key.public_key().as_ref().to_vec()
        }
        fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, RepositoryError> {
            self.uses.set(self.uses.get() + 1);
            let mut signature = self.key.sign(message).as_ref().to_vec();
            if self.broken {
                signature[0] ^= 1;
            }
            let public: [u8; 32] = self.public_key_bytes().try_into().unwrap();
            checked(&public, message, signature)
        }
    }
    fn token(broken: bool) -> MockToken {
        MockToken {
            key: Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap(),
            broken,
            uses: Cell::new(0),
        }
    }

    #[test]
    fn uri_names_exactly_one_token_and_object() {
        assert_eq!(
            parse("token=Dynodoc;object=device").unwrap(),
            Locator {
                token: "Dynodoc".into(),
                object: "device".into()
            }
        );
        for bad in [
            "token=Dynodoc",
            "object=device",
            "token=a;token=b;object=c",
            "token=a;object=b;pin-value=1234",
            "token=a%20b;object=c",
            "token=a;object=b?module-path=/tmp/x.so",
            "token=;object=b",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ec_point_accepts_der_and_bare_and_nothing_else() {
        let key = [7u8; 32];
        let mut der = vec![0x04, 0x20];
        der.extend(key);
        assert_eq!(ec_point(&der).unwrap(), key);
        assert_eq!(ec_point(&key).unwrap(), key);
        assert!(ec_point(&der[..33]).is_err());
        assert!(ec_point(&[0x04, 0x41, 1, 2]).is_err());
    }

    #[test]
    fn token_key_enrolls_and_signs_commits_the_server_verifies() {
        let token = token(false);
        let challenge = Challenge {
            version: 1,
            id: uuid::Uuid::from_u128(1),
            authority: uuid::Uuid::from_u128(2),
            identity: uuid::Uuid::from_u128(3),
            public_key: hex::encode(token.public_key_bytes()),
            nonce: "11".repeat(32),
            expires_at_ms: 1,
        };
        let proof = Proof::sign(
            challenge.clone(),
            challenge.authority,
            challenge.identity,
            &token,
        )
        .unwrap();
        proof.verify().unwrap();
        let signed = SignedCommit::sign(
            Commit {
                version: 1,
                project: uuid::Uuid::from_u128(4),
                parents: vec![],
                files: Default::default(),
                author_key: String::new(),
                authored_at_ms: 1,
                message: "From the token".into(),
                recovery: None,
                same_file_resolutions: vec![],
                sealed: None,
                project_resolutions: Vec::new(),
                relocations: Vec::new(),
                merge_policy: None,
            },
            &token as &dyn Signer,
        )
        .unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.commit.author_key, challenge.public_key);
        assert_eq!(token.uses.get(), 2);
    }

    #[test]
    fn a_token_that_returns_a_bad_signature_is_refused() {
        let token = token(true);
        let error = SignedCommit::sign(
            Commit {
                version: 1,
                project: uuid::Uuid::from_u128(4),
                parents: vec![],
                files: Default::default(),
                author_key: String::new(),
                authored_at_ms: 1,
                message: String::new(),
                recovery: None,
                same_file_resolutions: vec![],
                sealed: None,
                project_resolutions: Vec::new(),
                relocations: Vec::new(),
                merge_policy: None,
            },
            &token,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid Ed25519 signature"));
    }

    /// `sync --device-key` and `mcp` (decision 043): a token key behind the shared signer
    /// signs a device-session proof the server's check accepts; a broken token signs none.
    #[test]
    fn a_shared_token_key_opens_device_sessions_and_a_broken_one_signs_nothing() {
        use engine_core::repository::device_session::{SessionChallenge, SessionProof};
        for broken in [false, true] {
            let shared = crate::signing::SharedSigner::new(token(broken));
            let challenge = SessionChallenge {
                version: 1,
                id: uuid::Uuid::from_u128(1),
                authority: uuid::Uuid::from_u128(2),
                public_key: hex::encode(shared.public_key_bytes()),
                project: uuid::Uuid::from_u128(4),
                scopes: vec!["history:read".into()],
                nonce: "11".repeat(32),
                issued_at_ms: 1,
                expires_at_ms: 2,
                token_ttl_seconds: 3600,
            };
            let proof = SessionProof::sign(
                challenge.clone(),
                "22".repeat(32),
                challenge.authority,
                challenge.project,
                &challenge.scopes,
                &shared,
            );
            match proof {
                Ok(proof) if !broken => proof.verify_signature().unwrap(),
                Err(_) if broken => {}
                other => panic!("broken={broken}: {other:?}"),
            }
        }
    }

    #[test]
    fn opening_a_token_without_a_module_names_the_variable() {
        // Skipped where a real module is configured for manual token runs.
        if std::env::var_os(MODULE_ENV).is_some() {
            return;
        }
        let error = open("token=Dynodoc;object=device").err().unwrap();
        assert!(error.to_string().contains(MODULE_ENV));
    }
}
