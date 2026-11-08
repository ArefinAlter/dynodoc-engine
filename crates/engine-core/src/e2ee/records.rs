//! Signed records of encrypted projects: device encryption-key bindings (design 5.2),
//! fingerprints (5.4), epoch records (6.4) and the hash-chained membership log (6.3, 10.4).
//!
//! [`Log::replay`] is the one authorization rule set: the service runs it before it appends
//! an entry, and clients run it on what the service returns, so a server that inserts a
//! rogue key or rewinds the log is detected by clients (design 10.4).
//!
//! Without `persistence` (the WebAssembly engine) signatures are not checked here: the host
//! checks every Ed25519 signature with Web Crypto first and then runs these same rules through
//! [`Log::append_presigned`] and [`verify_epochs_presigned`] (decision 041).
#[cfg(feature = "persistence")]
use super::verify;
use super::{canonical, hex, sha256, unhex, Error};
#[cfg(feature = "persistence")]
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const BINDING_LABEL: &[u8] = b"dynodoc.device-encryption-binding\0v1\0";
pub const FINGERPRINT_LABEL: &[u8] = b"dynodoc.device-fingerprint\0v1\0";
pub const EPOCH_LABEL: &[u8] = b"dynodoc.epoch-record\0v1\0";
pub const EPOCH_SIGNATURE_LABEL: &[u8] = b"dynodoc.epoch-record-signature\0v1\0";
pub const LOG_LABEL: &[u8] = b"dynodoc.membership-log\0v1\0";
pub const LOG_SIGNATURE_LABEL: &[u8] = b"dynodoc.membership-log-signature\0v1\0";
/// The stored bound of `project_e2ee_log.body` and `project_key_epoch.record`.
pub const MAX_ENTRY_BYTES: usize = 16384;
pub const MAX_RECORD_BYTES: usize = 8192;

/// Binds a device's X25519 encryption key to its enrolled Ed25519 signing key and account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub version: u8,
    pub authority: Uuid,
    pub identity: Uuid,
    pub signing_key: String,
    pub encryption_key: String,
    pub created_at_ms: i64,
}

impl Binding {
    pub fn message(&self) -> Result<Vec<u8>, Error> {
        if self.version != 1
            || self.authority.is_nil()
            || self.identity.is_nil()
            || self.created_at_ms <= 0
        {
            return Err(Error::Malformed("encryption-key binding"));
        }
        unhex::<32>(&self.signing_key, "signing key")?;
        unhex::<32>(&self.encryption_key, "encryption key")?;
        Ok([BINDING_LABEL, &canonical(self)?].concat())
    }
    #[cfg(feature = "persistence")]
    pub fn sign(&self, key: &Ed25519KeyPair) -> Result<String, Error> {
        if super::public_hex(key) != self.signing_key {
            return Err(Error::Refused("binding names another signing key"));
        }
        Ok(super::sign(key, &self.message()?))
    }
    #[cfg(feature = "persistence")]
    pub fn verify(&self, signature: &str) -> Result<(), Error> {
        verify(&self.signing_key, &self.message()?, signature)
    }
}

/// A device fingerprint: the hash (hex, for a QR payload) and 60 decimal digits in 12
/// groups of 5. Digits come from the hash and its SHA-256 (64 bytes; 12 big-endian 40-bit
/// chunks, each modulo 100000), decision 035.
pub fn fingerprint(signing_key: &str, encryption_key: &str) -> Result<(String, String), Error> {
    let first = sha256(&[
        FINGERPRINT_LABEL,
        &unhex::<32>(signing_key, "signing key")?,
        &unhex::<32>(encryption_key, "encryption key")?,
    ]);
    let second = sha256(&[&first]);
    let bytes = [first, second].concat();
    let groups: Vec<String> = bytes[..60]
        .chunks_exact(5)
        .map(|c| {
            let n = c.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            format!("{:05}", n % 100_000)
        })
        .collect();
    Ok((hex(&first), groups.join(" ")))
}

/// Why an epoch was opened (design 6.2).
pub const EPOCH_REASONS: [&str; 7] = [
    "project_created",
    "member_removed",
    "device_revoked",
    "scheduled",
    "suspected_compromise",
    "escrow_changed",
    "member_added",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochRecord {
    pub version: u8,
    pub project: Uuid,
    pub epoch: u32,
    /// Hash of the previous epoch's record; `None` for epoch 1.
    pub previous_epoch_record: Option<String>,
    pub reason: String,
    pub suite: u8,
    pub key_id: String,
    pub recipients_digest: String,
    /// The membership-log entry hash the author saw.
    pub membership_head: String,
    /// `full` only in Phase 1 (design 6.5).
    pub history_policy: String,
    pub created_by_key: String,
    pub created_at_ms: i64,
}

impl EpochRecord {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != 1 || self.suite != super::seal::SUITE {
            return Err(Error::Unsupported("epoch record version or suite"));
        }
        if self.project.is_nil()
            || self.epoch == 0
            || (self.epoch == 1) != self.previous_epoch_record.is_none()
            || !EPOCH_REASONS.contains(&self.reason.as_str())
            || self.history_policy != "full"
            || self.created_at_ms < 0
        {
            return Err(Error::Malformed("epoch record"));
        }
        if let Some(previous) = &self.previous_epoch_record {
            unhex::<32>(previous, "previous epoch record")?;
        }
        unhex::<8>(&self.key_id, "key id")?;
        unhex::<32>(&self.recipients_digest, "recipients digest")?;
        unhex::<32>(&self.membership_head, "membership head")?;
        unhex::<32>(&self.created_by_key, "creator key")?;
        if canonical(self)?.len() > MAX_RECORD_BYTES {
            return Err(Error::Limit("epoch record bytes"));
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        self.validate()?;
        Ok(sha256(&[EPOCH_LABEL, &canonical(self)?]))
    }
    #[cfg(feature = "persistence")]
    pub fn sign(&self, key: &Ed25519KeyPair) -> Result<String, Error> {
        if super::public_hex(key) != self.created_by_key {
            return Err(Error::Refused("record names another creator key"));
        }
        Ok(super::sign(
            key,
            &[EPOCH_SIGNATURE_LABEL, &self.hash()?].concat(),
        ))
    }
    #[cfg(feature = "persistence")]
    pub fn verify(&self, signature: &str) -> Result<(), Error> {
        verify(
            &self.created_by_key,
            &[EPOCH_SIGNATURE_LABEL, &self.hash()?].concat(),
            signature,
        )
    }
}

/// Membership-log entry types (the `project_e2ee_log.entry_type` check list).
pub const ENTRY_TYPES: [&str; 19] = [
    "genesis",
    "member_add",
    "member_remove",
    "role_change",
    "device_add",
    "device_revoke",
    "recovery_set",
    "escrow_set",
    "escrow_clear",
    "escrow_backfill",
    "escrow_recover",
    "epoch_open",
    "policy_change",
    "agent_grant",
    "agent_revoke",
    "migration_begin",
    "migration_complete",
    "reseal_live_state",
    "owner_transfer",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub version: u8,
    pub project: Uuid,
    pub index: u64,
    pub previous: Option<String>,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub body: Value,
    pub signer_key: String,
    pub created_at_ms: i64,
}

/// An entry with its signature, as appended and served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEntry {
    pub entry: Entry,
    pub signature: String,
}

impl Entry {
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        if self.version != 1
            || !ENTRY_TYPES.contains(&self.entry_type.as_str())
            || self.project.is_nil()
            || self.created_at_ms < 0
        {
            return Err(Error::Malformed("membership log entry"));
        }
        if (self.index == 0) != self.previous.is_none()
            || (self.index == 0) != (self.entry_type == "genesis")
        {
            return Err(Error::Malformed("membership log chain position"));
        }
        let bytes = canonical(self)?;
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(Error::Limit("membership log entry bytes"));
        }
        Ok(sha256(&[LOG_LABEL, &bytes]))
    }
    #[cfg(feature = "persistence")]
    pub fn sign(self, key: &Ed25519KeyPair) -> Result<SignedEntry, Error> {
        if super::public_hex(key) != self.signer_key {
            return Err(Error::Refused("entry names another signer key"));
        }
        let signature = super::sign(key, &[LOG_SIGNATURE_LABEL, &self.hash()?].concat());
        Ok(SignedEntry {
            entry: self,
            signature,
        })
    }
}

/// Roles that may change membership or open epochs (owner or manager, design 10.1).
fn manages(role: &str) -> bool {
    matches!(role, "owner" | "manager")
}
const ROLES: [&str; 6] = [
    "owner", "manager", "editor", "approver", "reviewer", "viewer",
];

/// The project's membership as the verified log states it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Log {
    pub project: Uuid,
    pub head: Option<[u8; 32]>,
    pub length: u64,
    /// identity -> role.
    pub members: BTreeMap<Uuid, String>,
    /// active signing key -> identity.
    pub signing_keys: BTreeMap<String, Uuid>,
    /// active encryption key -> (identity, signing key).
    pub encryption_keys: BTreeMap<String, (Uuid, String)>,
    /// recovery signer key -> (identity, recovery recipient key).
    pub recovery: BTreeMap<String, (Uuid, String)>,
    pub escrow: Option<String>,
    /// Every entry hash in order, so an epoch record's `membership_head` can be placed.
    pub hashes: Vec<[u8; 32]>,
    /// Epochs announced by `epoch_open` entries: epoch -> record hash.
    pub epochs: BTreeMap<u32, String>,
    pub sealed: bool,
}

fn field<'a>(body: &'a Value, name: &'static str) -> Result<&'a str, Error> {
    body.get(name)
        .and_then(Value::as_str)
        .ok_or(Error::Malformed(name))
}
fn identity(body: &Value) -> Result<Uuid, Error> {
    field(body, "identity")?
        .parse()
        .map_err(|_| Error::Malformed("identity"))
}

impl Log {
    pub fn new(project: Uuid) -> Self {
        Self {
            project,
            ..Self::default()
        }
    }

    /// Verify and replay a whole log from genesis.
    #[cfg(feature = "persistence")]
    pub fn replay(project: Uuid, entries: &[SignedEntry]) -> Result<Self, Error> {
        let mut log = Self::new(project);
        for entry in entries {
            log.append(entry)?;
        }
        Ok(log)
    }

    /// The identity and role behind an active signing key, if any.
    pub fn signer(&self, key: &str) -> Option<(Uuid, &str)> {
        let who = *self.signing_keys.get(key)?;
        self.members.get(&who).map(|role| (who, role.as_str()))
    }

    /// Verify one entry against this state (chain link, signature, authorization) and apply it.
    #[cfg(feature = "persistence")]
    pub fn append(&mut self, signed: &SignedEntry) -> Result<[u8; 32], Error> {
        let hash = self.link(&signed.entry)?;
        verify(
            &signed.entry.signer_key,
            &[LOG_SIGNATURE_LABEL, &hash].concat(),
            &signed.signature,
        )?;
        self.apply(&signed.entry, hash)
    }

    /// [`Log::append`] for a host that has already checked the entry's Ed25519 signature
    /// (over `LOG_SIGNATURE_LABEL || hash`, by `signer_key`) itself: chain link and
    /// authorization only. Never call it on an entry whose signature was not checked.
    pub fn append_presigned(&mut self, signed: &SignedEntry) -> Result<[u8; 32], Error> {
        let hash = self.link(&signed.entry)?;
        self.apply(&signed.entry, hash)
    }

    fn link(&self, e: &Entry) -> Result<[u8; 32], Error> {
        if e.project != self.project
            || e.index != self.length
            || e.previous != self.head.map(|h| hex(&h))
        {
            return Err(Error::Refused("membership log chain link"));
        }
        e.hash()
    }

    fn apply(&mut self, e: &Entry, hash: [u8; 32]) -> Result<[u8; 32], Error> {
        let body = &e.body;
        let actor = self.signer(&e.signer_key);
        let managing = actor.is_some_and(|(_, role)| manages(role));
        let owner = actor.is_some_and(|(_, role)| role == "owner");
        match e.entry_type.as_str() {
            "genesis" => {
                let who = identity(body)?;
                let key = field(body, "signing_key")?.to_owned();
                let enc = field(body, "encryption_key")?.to_owned();
                if key != e.signer_key {
                    return Err(Error::Refused("genesis must be signed by the owner's key"));
                }
                unhex::<32>(&enc, "encryption key")?;
                self.members.insert(who, "owner".into());
                self.signing_keys.insert(key.clone(), who);
                self.encryption_keys.insert(enc, (who, key));
            }
            "member_add" | "role_change" => {
                let who = identity(body)?;
                let role = field(body, "role")?;
                // Only an owner names another owner; a manager cannot change an owner.
                let target_is_owner = self.members.get(&who).is_some_and(|r| r == "owner");
                if !ROLES.contains(&role)
                    || !managing
                    || ((role == "owner" || target_is_owner) && !owner)
                {
                    return Err(Error::Refused(
                        "membership change needs an owner or manager",
                    ));
                }
                if (e.entry_type == "member_add") == self.members.contains_key(&who) {
                    return Err(Error::Refused(
                        "member already present, or absent for a role change",
                    ));
                }
                // The adder vouches for the devices it verified by fingerprint (design 10.2);
                // a member added without any is "pending key" until an invitee grant is used.
                let devices = body
                    .get("devices")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if e.entry_type == "role_change" && !devices.is_empty() {
                    return Err(Error::Malformed("role change with devices"));
                }
                for device in &devices {
                    let key = field(device, "signing_key")?.to_owned();
                    let enc = field(device, "encryption_key")?.to_owned();
                    unhex::<32>(&key, "signing key")?;
                    unhex::<32>(&enc, "encryption key")?;
                    if self.signing_keys.contains_key(&key) {
                        return Err(Error::Refused("signing key belongs to another member"));
                    }
                    self.signing_keys.insert(key.clone(), who);
                    self.encryption_keys.insert(enc, (who, key));
                }
                self.members.insert(who, role.into());
            }
            "member_remove" => {
                let who = identity(body)?;
                let target_is_owner = self.members.get(&who).is_some_and(|r| r == "owner");
                if !managing || (target_is_owner && !owner) || !self.members.contains_key(&who) {
                    return Err(Error::Refused("member removal needs an owner or manager"));
                }
                if target_is_owner && self.members.values().filter(|r| *r == "owner").count() == 1 {
                    return Err(Error::Refused("the last owner cannot be removed"));
                }
                self.members.remove(&who);
                self.signing_keys.retain(|_, id| *id != who);
                self.encryption_keys.retain(|_, (id, _)| *id != who);
                self.recovery.retain(|_, (id, _)| *id != who);
            }
            "device_add" => {
                let who = identity(body)?;
                let key = field(body, "signing_key")?.to_owned();
                let enc = field(body, "encryption_key")?.to_owned();
                unhex::<32>(&key, "signing key")?;
                unhex::<32>(&enc, "encryption key")?;
                let own = actor.is_some_and(|(id, _)| id == who);
                let recovered = self
                    .recovery
                    .get(&e.signer_key)
                    .is_some_and(|(id, _)| *id == who);
                if !self.members.contains_key(&who) || !(own || recovered || managing) {
                    return Err(Error::Refused(
                        "a device is added by its owner, their recovery key or a manager",
                    ));
                }
                if self.signing_keys.get(&key).is_some_and(|id| *id != who) {
                    return Err(Error::Refused("signing key belongs to another member"));
                }
                self.signing_keys.insert(key.clone(), who);
                self.encryption_keys.insert(enc, (who, key));
            }
            "device_revoke" => {
                let key = field(body, "signing_key")?;
                let who = *self
                    .signing_keys
                    .get(key)
                    .ok_or(Error::Refused("unknown device"))?;
                if !(actor.is_some_and(|(id, _)| id == who) || managing) {
                    return Err(Error::Refused(
                        "a device is revoked by its owner or a manager",
                    ));
                }
                self.signing_keys.remove(key);
                self.encryption_keys.retain(|_, (_, sk)| sk != key);
            }
            "recovery_set" => {
                let who = identity(body)?;
                let signer = field(body, "signer_key")?.to_owned();
                let recipient = field(body, "recipient_key")?.to_owned();
                unhex::<32>(&signer, "recovery signer")?;
                unhex::<32>(&recipient, "recovery recipient")?;
                if actor.map(|(id, _)| id) != Some(who) {
                    return Err(Error::Refused("recovery keys are set by their own member"));
                }
                self.recovery.retain(|_, (id, _)| *id != who);
                self.recovery.insert(signer, (who, recipient));
            }
            "epoch_open" => {
                let epoch = body
                    .get("epoch")
                    .and_then(Value::as_u64)
                    .ok_or(Error::Malformed("epoch"))?;
                let record = field(body, "record_hash")?.to_owned();
                unhex::<32>(&record, "record hash")?;
                let next = self.epochs.keys().next_back().copied().unwrap_or(0) + 1;
                if !managing || epoch != u64::from(next) {
                    return Err(Error::Refused(
                        "an epoch is opened by an owner or manager, one at a time",
                    ));
                }
                self.epochs.insert(next, record);
            }
            "escrow_set" | "escrow_clear" | "escrow_backfill" | "escrow_recover"
            | "policy_change" | "migration_begin" | "migration_complete" | "owner_transfer"
            | "reseal_live_state" => {
                if !(owner || managing && e.entry_type == "reseal_live_state") {
                    return Err(Error::Refused("this entry needs a project owner"));
                }
                match e.entry_type.as_str() {
                    "escrow_set" => self.escrow = Some(field(body, "recipient_key")?.to_owned()),
                    "escrow_clear" => self.escrow = None,
                    "migration_complete" => self.sealed = true,
                    "owner_transfer" => {
                        let who = identity(body)?;
                        if !self.members.contains_key(&who) {
                            return Err(Error::Refused("ownership moves to a member"));
                        }
                        self.members.insert(who, "owner".into());
                    }
                    _ => {}
                }
            }
            "agent_grant" | "agent_revoke" => {
                if !actor.is_some_and(|(_, role)| matches!(role, "owner" | "manager" | "editor")) {
                    return Err(Error::Refused("delegation needs an editor or above"));
                }
                field(body, "document")?;
            }
            _ => return Err(Error::Unsupported("membership log entry type")),
        }
        self.head = Some(hash);
        self.hashes.push(hash);
        self.length += 1;
        Ok(hash)
    }

    /// Every active encryption key of every current member, plus recovery recipients and the
    /// escrow recipient: the recipient set of a new epoch (design 6.3 step 1).
    pub fn recipients(&self) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = self.encryption_keys.keys().cloned().collect();
        out.extend(self.recovery.values().map(|(_, r)| r.clone()));
        out.extend(self.escrow.clone());
        out
    }
}

/// Verify an epoch record chain against a replayed log: consecutive epochs, links, each
/// signed by a key that manages the project and announced by an `epoch_open` entry.
#[cfg(feature = "persistence")]
pub fn verify_epochs(log: &Log, records: &[(EpochRecord, String)]) -> Result<(), Error> {
    for (record, signature) in records {
        record.verify(signature)?;
    }
    let records: Vec<EpochRecord> = records.iter().map(|(r, _)| r.clone()).collect();
    verify_epochs_presigned(log, &records)
}

/// [`verify_epochs`] for a host that has already checked each record's signature by its
/// `created_by_key` itself.
pub fn verify_epochs_presigned(log: &Log, records: &[EpochRecord]) -> Result<(), Error> {
    let mut previous: Option<[u8; 32]> = None;
    for (n, record) in records.iter().enumerate() {
        if record.project != log.project
            || u64::from(record.epoch) != n as u64 + 1
            || record.previous_epoch_record != previous.map(|h| hex(&h))
        {
            return Err(Error::Refused("epoch record chain"));
        }
        let hash = record.hash()?;
        if log.epochs.get(&record.epoch) != Some(&hex(&hash)) {
            return Err(Error::Refused(
                "epoch record not announced in the membership log",
            ));
        }
        let head = unhex::<32>(&record.membership_head, "membership head")?;
        if !log.hashes.contains(&head) {
            return Err(Error::Refused(
                "epoch record names an unknown membership head",
            ));
        }
        previous = Some(hash);
    }
    Ok(())
}

/// What a client remembers of a project's membership log and epoch chain between sessions
/// (design 10.4, decision 041), so a server that rolls them back, withholds part of them or
/// shows this client a different branch than before is detected. Signatures and rules are
/// [`Log`]'s and [`verify_epochs`]'s; this adds the checks that need memory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub length: u64,
    pub head: Option<String>,
    pub epochs: u32,
    pub epoch_head: Option<String>,
}

impl Pin {
    /// Accept a verified log and its verified epoch records, then remember them. Refuses a
    /// shorter log or epoch chain (rollback or replay), a different entry or record where the
    /// pinned one was (a fork), and epochs the log announces without their record (withheld).
    pub fn advance(&mut self, log: &Log, records: &[EpochRecord]) -> Result<(), Error> {
        if log.length < self.length {
            return Err(Error::Refused(
                "the membership log is older than one seen before",
            ));
        }
        if self.length > 0 {
            let at = usize::try_from(self.length - 1).map_err(|_| Error::Limit("log length"))?;
            if log.hashes.get(at).map(|h| hex(h)) != self.head {
                return Err(Error::Refused(
                    "the membership log differs from the one seen before",
                ));
            }
        }
        if records.len() != log.epochs.len() {
            return Err(Error::Refused(
                "epoch records announced in the log are withheld",
            ));
        }
        let epochs = u32::try_from(records.len()).map_err(|_| Error::Limit("epochs"))?;
        if epochs < self.epochs {
            return Err(Error::Refused(
                "the epoch chain is older than one seen before",
            ));
        }
        if self.epochs > 0 {
            let record = &records[self.epochs as usize - 1];
            if Some(hex(&record.hash()?)) != self.epoch_head {
                return Err(Error::Refused(
                    "the epoch chain differs from the one seen before",
                ));
            }
        }
        self.length = log.length;
        self.head = log.head.map(|h| hex(&h));
        self.epochs = epochs;
        self.epoch_head = records
            .last()
            .map(|r| r.hash().map(|h| hex(&h)))
            .transpose()?;
        Ok(())
    }

    /// A commit, grant or record names a log position this client must have seen: one the
    /// server withholds from it is refused.
    pub fn knows(log: &Log, membership_head: &str) -> Result<(), Error> {
        let head = unhex::<32>(membership_head, "membership head")?;
        if log.hashes.contains(&head) {
            Ok(())
        } else {
            Err(Error::Refused(
                "the server withholds membership log entries from this client",
            ))
        }
    }
}
