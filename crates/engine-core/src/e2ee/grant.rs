//! Key grants (cryptographic design section 7): HPKE base mode (RFC 9180, KEM 0x0020
//! DHKEM(X25519, HKDF-SHA256), KDF 0x0001, AEAD 0x0002 AES-256-GCM) delivering one secret to
//! one recipient key, signed by its creator so third parties can check it later.
//!
//! Two refinements of design 7.2, recorded in decision 035, break a hash cycle between a
//! grant and its epoch record: the HPKE `aad` leaves out `epoch_record` (the signature still
//! covers it), and the record's `recipients_digest` hashes each grant's `enc || ciphertext`
//! under its own label rather than the whole grant.
use super::{canonical, hex, keys::Key, sha256, unhex, Error};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR, OpModeS,
    Serializable,
};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

type K = X25519HkdfSha256;

pub const INFO_LABEL: &[u8] = b"dynodoc.key-grant\0v1\0";
pub const SIGNATURE_LABEL: &[u8] = b"dynodoc.key-grant-signature\0v1\0";
pub const DIGEST_LABEL: &[u8] = b"dynodoc.key-grant-digest\0v1\0";
/// The stored bound of `project_key_grant.grant_body`.
pub const MAX_GRANT_BYTES: usize = 4096;
/// A delegation lists at most this many epochs (one per epoch in the document's state).
pub const MAX_DELEGATED_EPOCHS: usize = 64;
pub const RECIPIENT_KINDS: [&str; 6] =
    ["device", "recovery", "escrow", "agent", "addin", "invitee"];

/// A device encryption key (the design's `DEK`): a static X25519 private key. Never leaves
/// the device unwrapped; wiped on drop.
pub struct DeviceKey(<K as Kem>::PrivateKey);

impl DeviceKey {
    pub fn generate() -> Result<Self, Error> {
        Self::from_secret(&Key::random()?)
    }
    /// The encryption key of a device whose Ed25519 signing seed is `seed` (decision 035):
    /// `HKDF-SHA-256(seed, info = "dynodoc.device-encryption-key\0v1\0")`, so one encrypted
    /// key file protects both keys.
    pub fn from_signing_seed(seed: &[u8; 32]) -> Result<Self, Error> {
        let mut out = [0u8; 32];
        super::keys::hkdf(
            seed,
            &[],
            &[b"dynodoc.device-encryption-key\0v1\0"],
            &mut out,
        )?;
        Self::from_secret(&Key::from_bytes(out))
    }
    /// From 32 secret bytes (clamped by X25519).
    pub fn from_secret(secret: &Key) -> Result<Self, Error> {
        <K as Kem>::PrivateKey::from_bytes(secret.as_bytes())
            .map(Self)
            .map_err(|_| Error::Malformed("device encryption key"))
    }
    pub fn secret(&self) -> Result<Key, Error> {
        Key::from_slice(&Zeroizing::new(self.0.to_bytes().to_vec()))
    }
    /// The public key, lowercase hexadecimal.
    pub fn public_hex(&self) -> String {
        hex(&<K as Kem>::sk_to_pk(&self.0).to_bytes())
    }
}
impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceKey(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    Project,
    Document { document: Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub kem: u16,
    pub kdf: u16,
    pub aead: u16,
}
pub const GRANT_SUITE: Suite = Suite {
    kem: 0x20,
    kdf: 1,
    aead: 2,
};

/// A delegation (design 7.5): document keys for an agent, an add-in pane or a guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub expires_at_ms: i64,
    /// `agent`, `addin` or `guest`.
    pub purpose: String,
    /// Advisory for honest clients: a symmetric key holder can also seal.
    pub read_only: bool,
}

/// One grant, as stored verbatim by the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub version: u8,
    pub project: Uuid,
    pub epoch: u32,
    pub scope: Scope,
    /// One of [`RECIPIENT_KINDS`].
    pub recipient_kind: String,
    /// The recipient device's encryption-key row for `device` grants, else `None`.
    pub recipient_device: Option<Uuid>,
    /// X25519 public key, lowercase hexadecimal.
    pub recipient_key: String,
    pub suite: Suite,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Delegation>,
    pub enc: String,
    pub ciphertext: String,
    /// The hash of the epoch record this grant belongs to (lowercase hex).
    pub epoch_record: String,
    pub created_by_key: String,
    pub created_at_ms: i64,
    pub signature: String,
}

/// One delegated document key of one epoch, with that epoch's keyed-identifier key so the
/// delegate can check the identifier inside each object it opens (decision 035).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedKey {
    pub cid: String,
    pub epoch: u32,
    pub key: String,
    /// The epoch's key identifier hint, which objects carry and readers check.
    pub key_id: String,
}

impl Grant {
    /// The HPKE `info` (design 7.2).
    pub fn info(&self) -> Vec<u8> {
        let mut info = INFO_LABEL.to_vec();
        info.extend_from_slice(self.project.as_bytes());
        info.extend_from_slice(&self.epoch.to_be_bytes());
        match &self.scope {
            Scope::Project => info.push(0),
            Scope::Document { document } => {
                info.push(1);
                info.extend_from_slice(document.as_bytes());
            }
        }
        info.extend_from_slice(self.recipient_device.unwrap_or(Uuid::nil()).as_bytes());
        info
    }

    fn without(&self, fields: &[&str]) -> Result<Vec<u8>, Error> {
        let mut value = serde_json::to_value(self).map_err(|_| Error::Malformed("grant"))?;
        if let Value::Object(map) = &mut value {
            for field in fields {
                map.remove(*field);
            }
        }
        canonical(&value)
    }

    /// The HPKE associated data: SHA-256 of the grant without its HPKE output, signature and
    /// epoch record reference.
    pub fn aad(&self) -> Result<[u8; 32], Error> {
        Ok(sha256(&[&self.without(&[
            "enc",
            "ciphertext",
            "signature",
            "epoch_record",
        ])?]))
    }

    /// The signed hash: the grant without its signature.
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        Ok(sha256(&[&self.without(&["signature"])?]))
    }

    /// `(recipient_key, digest of enc || ciphertext)`, one entry of an epoch record's
    /// recipient digest.
    pub fn digest_entry(&self) -> Result<([u8; 32], [u8; 32]), Error> {
        let enc = unhex::<32>(&self.enc, "grant enc")?;
        let ct = decode_hex(&self.ciphertext)?;
        Ok((
            unhex::<32>(&self.recipient_key, "recipient key")?,
            sha256(&[DIGEST_LABEL, &enc, &ct]),
        ))
    }

    /// Shape checks the service can run without any key.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != 1 || self.suite != GRANT_SUITE {
            return Err(Error::Unsupported("grant version or suite"));
        }
        if self.epoch == 0 || self.project.is_nil() || self.created_at_ms < 0 {
            return Err(Error::Malformed("grant"));
        }
        if !RECIPIENT_KINDS.contains(&self.recipient_kind.as_str())
            || (self.recipient_kind == "device") != self.recipient_device.is_some()
        {
            return Err(Error::Malformed("grant recipient"));
        }
        let delegated =
            matches!(self.recipient_kind.as_str(), "agent" | "addin") || self.delegation.is_some();
        if delegated && (self.delegation.is_none() || !matches!(self.scope, Scope::Document { .. }))
        {
            return Err(Error::Malformed(
                "delegation grant needs a document scope and terms",
            ));
        }
        if let Some(d) = &self.delegation {
            if !["agent", "addin", "guest"].contains(&d.purpose.as_str()) || d.expires_at_ms <= 0 {
                return Err(Error::Malformed("delegation terms"));
            }
        }
        unhex::<32>(&self.recipient_key, "recipient key")?;
        unhex::<32>(&self.enc, "grant enc")?;
        unhex::<32>(&self.epoch_record, "epoch record hash")?;
        unhex::<32>(&self.created_by_key, "creator key")?;
        unhex::<64>(&self.signature, "signature")?;
        let ct = decode_hex(&self.ciphertext)?;
        if (self.delegation.is_none() && ct.len() != 48) || ct.len() < 48 {
            return Err(Error::Malformed("grant ciphertext length"));
        }
        if serde_json::to_vec(self)
            .map(|b| b.len())
            .unwrap_or(usize::MAX)
            > MAX_GRANT_BYTES
        {
            return Err(Error::Limit("grant bytes"));
        }
        Ok(())
    }

    /// Fill `enc`, `ciphertext` and `signature` for `secret` (a 32-byte root, or the
    /// canonical delegation list).
    pub fn seal(self, secret: &[u8], creator: &Ed25519KeyPair) -> Result<Self, Error> {
        self.seal_with(secret, creator, &mut rand_core::OsRng)
    }

    /// [`Grant::seal`] with a fixed ephemeral key seed, for published test vectors only.
    pub fn seal_with_ikm(
        self,
        secret: &[u8],
        creator: &Ed25519KeyPair,
        ikm: [u8; 32],
    ) -> Result<Self, Error> {
        self.seal_with(secret, creator, &mut FixedIkm(ikm, 0))
    }

    fn seal_with<R: rand_core::CryptoRng + rand_core::RngCore>(
        mut self,
        secret: &[u8],
        creator: &Ed25519KeyPair,
        rng: &mut R,
    ) -> Result<Self, Error> {
        self.created_by_key = super::public_hex(creator);
        let recipient =
            <K as Kem>::PublicKey::from_bytes(&unhex::<32>(&self.recipient_key, "recipient key")?)
                .map_err(|_| Error::Malformed("recipient key"))?;
        let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, K, _>(
            &OpModeS::Base,
            &recipient,
            &self.info(),
            secret,
            &self.aad()?,
            rng,
        )
        .map_err(|_| Error::Malformed("recipient key"))?;
        self.enc = hex(&enc.to_bytes());
        self.ciphertext = hex(&ct);
        self.signature = String::new();
        let message = [SIGNATURE_LABEL, &self.hash()?].concat();
        self.signature = super::sign(creator, &message);
        self.validate()?;
        Ok(self)
    }

    /// Check the creator's signature. `creator_key` must come from the verified membership
    /// log, not from the service's response (design 7.3 step 1).
    pub fn verify(&self, creator_key: &str) -> Result<(), Error> {
        self.validate()?;
        if self.created_by_key != creator_key {
            return Err(Error::Signature);
        }
        super::verify(
            creator_key,
            &[SIGNATURE_LABEL, &self.hash()?].concat(),
            &self.signature,
        )
    }

    /// Verify, then open with the recipient's private key. Returns the raw plaintext.
    pub fn open(
        &self,
        creator_key: &str,
        recipient: &DeviceKey,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.verify(creator_key)?;
        if recipient.public_hex() != self.recipient_key {
            return Err(Error::Refused("grant is addressed to another key"));
        }
        let enc = <K as Kem>::EncappedKey::from_bytes(&unhex::<32>(&self.enc, "grant enc")?)
            .map_err(|_| Error::Malformed("grant enc"))?;
        hpke::single_shot_open::<AesGcm256, HkdfSha256, K>(
            &OpModeR::Base,
            &recipient.0,
            &enc,
            &self.info(),
            &decode_hex(&self.ciphertext)?,
            &self.aad()?,
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
    }

    /// Open a project or document root grant and check it against the epoch record's
    /// `key_id` (design 7.3 step 4).
    pub fn open_root(
        &self,
        creator_key: &str,
        recipient: &DeviceKey,
        record_key_id: &str,
    ) -> Result<Key, Error> {
        if self.delegation.is_some() {
            return Err(Error::Refused("a delegation grant carries document keys"));
        }
        let root = Key::from_slice(&self.open(creator_key, recipient)?)?;
        if matches!(self.scope, Scope::Project)
            && hex(&super::keys::key_id(self.epoch, &root)) != record_key_id
        {
            return Err(Error::Refused("grant key does not match its epoch record"));
        }
        Ok(root)
    }

    /// Open a delegation grant: the document's keys per epoch in its state, ready for
    /// [`super::state::read`].
    pub fn open_delegation(
        &self,
        creator_key: &str,
        recipient: &DeviceKey,
        now_ms: i64,
    ) -> Result<std::collections::BTreeMap<u32, super::state::EpochKeys>, Error> {
        let terms = self
            .delegation
            .as_ref()
            .ok_or(Error::Refused("not a delegation grant"))?;
        if terms.expires_at_ms <= now_ms {
            return Err(Error::Refused("delegation expired"));
        }
        let plain = self.open(creator_key, recipient)?;
        let list: Vec<DelegatedKey> =
            serde_json::from_slice(&plain).map_err(|_| Error::Malformed("delegation list"))?;
        if list.is_empty() || list.len() > MAX_DELEGATED_EPOCHS {
            return Err(Error::Malformed("delegation list"));
        }
        list.iter()
            .map(|k| {
                Ok((
                    k.epoch,
                    super::state::EpochKeys {
                        key_id: unhex::<8>(&k.key_id, "delegated key id")?,
                        doc: Key::from_bytes(unhex::<32>(&k.key, "delegated key")?),
                        cid: Key::from_bytes(unhex::<32>(&k.cid, "delegated identifier key")?),
                    },
                ))
            })
            .collect()
    }
}

/// The canonical plaintext of a delegation grant.
/// `(epoch, document key, identifier key, key id)` per epoch in the document's state.
pub fn delegation_plaintext(
    keys: &[(u32, &Key, &Key, [u8; 8])],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let list: Vec<DelegatedKey> = keys
        .iter()
        .map(|(epoch, key, cid, key_id)| DelegatedKey {
            cid: hex(cid.as_bytes()),
            epoch: *epoch,
            key: hex(key.as_bytes()),
            key_id: hex(key_id),
        })
        .collect();
    canonical(&list).map(Zeroizing::new)
}

/// `SHA-256(sorted (recipient_key || digest))` over an epoch's grants (design 6.3 step 4).
pub fn recipients_digest(grants: &[Grant]) -> Result<String, Error> {
    let mut entries = grants
        .iter()
        .map(Grant::digest_entry)
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    let joined: Vec<u8> = entries
        .iter()
        .flat_map(|(k, h)| k.iter().chain(h.iter()).copied())
        .collect();
    Ok(hex(&sha256(&[&joined])))
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2) || value.len() > 2 * MAX_GRANT_BYTES {
        return Err(Error::Malformed("hex"));
    }
    (0..value.len() / 2)
        .map(|i| {
            let pair = &value[2 * i..2 * i + 2];
            if pair
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                u8::from_str_radix(pair, 16).map_err(|_| Error::Malformed("hex"))
            } else {
                Err(Error::Malformed("hex"))
            }
        })
        .collect()
}

/// Supplies one fixed 32-byte ephemeral seed: published vectors only.
struct FixedIkm([u8; 32], usize);
impl rand_core::RngCore for FixedIkm {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.0[self.1 % 32];
            self.1 += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for FixedIkm {}

/// HPKE base-mode seal and open with this suite, for other constructions that deliver one
/// payload to one X25519 key (the ledger relay, decision 035). Returns `enc || ciphertext`.
pub(crate) fn hpke_seal(
    recipient_key: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ikm: Option<[u8; 32]>,
) -> Result<Vec<u8>, Error> {
    let recipient = <K as Kem>::PublicKey::from_bytes(recipient_key)
        .map_err(|_| Error::Malformed("recipient key"))?;
    let sealed = match ikm {
        Some(ikm) => hpke::single_shot_seal::<AesGcm256, HkdfSha256, K, _>(
            &OpModeS::Base,
            &recipient,
            info,
            plaintext,
            aad,
            &mut FixedIkm(ikm, 0),
        ),
        None => hpke::single_shot_seal::<AesGcm256, HkdfSha256, K, _>(
            &OpModeS::Base,
            &recipient,
            info,
            plaintext,
            aad,
            &mut rand_core::OsRng,
        ),
    };
    let (enc, ct) = sealed.map_err(|_| Error::Malformed("recipient key"))?;
    Ok([enc.to_bytes().as_slice(), &ct].concat())
}

pub(crate) fn hpke_open(
    recipient: &DeviceKey,
    info: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < 32 + 16 {
        return Err(Error::Malformed("sealed payload"));
    }
    let enc = <K as Kem>::EncappedKey::from_bytes(&sealed[..32])
        .map_err(|_| Error::Malformed("sealed payload"))?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, K>(
        &OpModeR::Base,
        &recipient.0,
        &enc,
        info,
        &sealed[32..],
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::Authentication)
}
