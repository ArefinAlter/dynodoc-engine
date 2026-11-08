//! `engine-cli e2ee`: the reference client of encrypted projects (pre-release, not
//! independently reviewed; decision 035). Every key stays on this device: the signing key file
//! (plain or encrypted `dynodoc-key-v1`) also yields the device encryption key, epoch roots
//! are opened from grants on each run and never written, and the service receives only
//! signed records, HPKE grants and sealed objects.
//!
//! The membership log is verified by replaying it with the same rules the service runs
//! (`engine_core::e2ee::records::Log`) before any grant is made; `--expect-fingerprint` and the
//! printed fingerprints are the out-of-band check of a new member's device (design 5.4).
use anyhow::{anyhow, bail, ensure, Context as _};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Subcommand};
use engine_core::e2ee::{
    commit::{self, Sealed},
    grant::{self, DeviceKey, Grant, Scope, GRANT_SUITE},
    keys::{self, Key},
    records::{self, Binding, Entry, EpochRecord, Log, SignedEntry},
    recovery,
    seal::{self, Context, Kind},
    state,
};
use engine_core::materializer::DocumentState;
use engine_core::repository::{Commit, FileEntry, SignedCommit};
use engine_core::shared_checkpoint::Address;
use engine_shared::DocumentId;
use reqwest::{Method, Url};
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use uuid::Uuid;

mod local_mcp;

#[derive(Args)]
pub struct Options {
    /// API base URL ending with `/` (HTTPS; loopback HTTP only with --allow-loopback-http).
    #[arg(long)]
    server: String,
    /// Private file holding an account or device-session bearer token.
    #[arg(long)]
    token_file: PathBuf,
    /// Enrolled Ed25519 signing key file of this device (plain or encrypted).
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    allow_loopback_http: bool,
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
pub enum Action {
    /// Register this device's encryption key, bound to its enrolled signing key.
    Enroll {
        /// The signing key's id (`engine-cli device` enrolment answer, or GET /devices).
        #[arg(long)]
        key_id: Uuid,
    },
    /// Print this device's fingerprint (compare it with the member who adds you).
    Fingerprint,
    /// Mode, epoch, verified log head, members and devices.
    Status {
        #[arg(long)]
        project: Uuid,
    },
    /// Make a project encrypted: genesis, epoch 1 for the log's devices, then complete.
    Enable {
        #[arg(long)]
        project: Uuid,
        /// Type the project name to accept that nobody can recover it without another device,
        /// member, recovery key or escrow.
        #[arg(long)]
        acknowledge_unrecoverable: Option<String>,
        /// Leave the project migrating (plaintext files still to seal or archive).
        #[arg(long)]
        no_complete: bool,
    },
    /// Add a member's verified device to the log and grant it every epoch (history `full`).
    AddMember {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        identity: Uuid,
        #[arg(long)]
        role: String,
        #[arg(long)]
        signing_key: String,
        #[arg(long)]
        encryption_key: String,
        /// The 60 digits the member read to you out of band.
        #[arg(long)]
        expect_fingerprint: String,
    },
    /// Remove a member and open the next epoch for everyone else, in one request.
    RemoveMember {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        identity: Uuid,
    },
    /// Open the next epoch without a membership change.
    Rotate {
        #[arg(long)]
        project: Uuid,
        #[arg(long, default_value = "scheduled")]
        reason: String,
    },
    /// Create a recovery key, register it and grant it every epoch. Written to a new private
    /// file; never printed and never sent.
    RecoveryCreate {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        out: PathBuf,
    },
    /// Register the organisation's escrow recipient (from `engine-cli escrow create`) as an
    /// owner, and grant it every epoch this device holds; later epochs include it.
    EscrowSet {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        recipient_key: String,
    },
    /// Restore a member's access with escrow: `t` custodians' share files reconstruct the escrow
    /// key in memory, its grants open, and every epoch is re-sealed to the member's new device
    /// (verified by fingerprint). Recorded as `escrow_recover` in the log, which members see.
    EscrowRecover {
        #[arg(long)]
        project: Uuid,
        #[arg(long = "share", required = true)]
        shares: Vec<PathBuf>,
        #[arg(long)]
        identity: Uuid,
        #[arg(long)]
        signing_key: String,
        #[arg(long)]
        encryption_key: String,
        /// The 60 digits read from the member's new device out of band.
        #[arg(long)]
        expect_fingerprint: String,
        /// The organisation's approval ticket for this recovery.
        #[arg(long)]
        ticket: String,
    },
    /// Use a recovery key: add this device with the recovery signer and grant it every epoch.
    RecoveryUse {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        recovery_key_file: PathBuf,
    },
    /// Verify the log, the epoch chain and that this device's grants open.
    Verify {
        #[arg(long)]
        project: Uuid,
    },
    /// Seal a document state (JSON) as a new sealed file, then stage and publish a commit.
    Put {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        state: PathBuf,
        /// The file's name; sealed in the commit's path map.
        #[arg(long)]
        name: String,
        #[arg(long)]
        message: String,
        /// An existing sealed file; a new one is created when omitted.
        #[arg(long)]
        document: Option<Uuid>,
    },
    /// Move a plaintext file into this encrypted project: seal its current state as a new
    /// file, decrypt it back and compare, then archive the original (migration M1).
    Migrate {
        #[arg(long)]
        project: Uuid,
        /// The plaintext file.
        #[arg(long)]
        document: Uuid,
    },
    /// Decrypt a published sealed file to a JSON state file (an explicit local export).
    Get {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        commit: String,
        #[arg(long)]
        document: Uuid,
        #[arg(long)]
        out: PathBuf,
    },
    /// Serve one delegated sealed file to a local AI assistant over MCP (stdio), read-only.
    /// `--key` is the agent's own key; the file must have been delegated to it by a person
    /// with `delegate`. The text is decrypted in memory on this device only.
    Mcp {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        commit: String,
        #[arg(long)]
        document: Uuid,
        /// The file's name as shown to the assistant (the real name is sealed under a key
        /// the delegation does not include).
        #[arg(long, default_value = "delegated file")]
        name: String,
    },
    /// Delegate one file, read-only, to a local agent's key for a limited time. Asks for
    /// your typed consent on this terminal (design 8.3); never from an agent's input.
    Delegate {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        document: Uuid,
        /// The agent's X25519 public key (`engine-cli e2ee --key AGENT_KEY fingerprint`).
        #[arg(long)]
        agent_key: String,
        #[arg(long, default_value_t = 1)]
        hours: u32,
    },
}

/// One run's context: the service, this device's keys and the bearer.
struct Client {
    http: reqwest::Client,
    base: Url,
    token: String,
    sign: Ed25519KeyPair,
    enc: DeviceKey,
    /// What this device saw of each project's log and epochs (`records::Pin`), beside the key.
    pins: PathBuf,
}

impl Client {
    async fn me(&self) -> anyhow::Result<String> {
        let me = self.get("auth/me").await?;
        Ok(me["identity_id"]
            .as_str()
            .ok_or_else(|| anyhow!("cannot read your account id"))?
            .to_owned())
    }
    fn signing(&self) -> String {
        use ring::signature::KeyPair;
        hex::encode(self.sign.public_key().as_ref())
    }
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let url = self.base.join(path)?;
        let mut request = self.http.request(method, url).bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if !status.is_success() {
            // The service's answers carry no secrets; show its reason.
            bail!(
                "{path}: {status}: {}",
                value.get("error").and_then(Value::as_str).unwrap_or(&text)
            );
        }
        Ok(value)
    }
    async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.call(Method::GET, path, None).await
    }
    async fn post(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.call(Method::POST, path, Some(body)).await
    }

    /// The whole log, verified by replay.
    async fn log(&self, project: Uuid) -> anyhow::Result<(Vec<SignedEntry>, Log)> {
        let mut entries: Vec<SignedEntry> = Vec::new();
        loop {
            let after = entries.len() as i64 - 1;
            let page = self
                .get(&format!("projects/{project}/e2ee/log?after={after}"))
                .await?;
            let batch: Vec<SignedEntry> = serde_json::from_value(page["entries"].clone())?;
            let more = page["more"].as_bool().unwrap_or(false);
            entries.extend(batch);
            if !more {
                break;
            }
        }
        let log = Log::replay(project, &entries)
            .map_err(|e| anyhow!("the membership log does not verify: {e}"))?;
        Ok((entries, log))
    }
    async fn epochs(&self, project: Uuid, log: &Log) -> anyhow::Result<Vec<(EpochRecord, String)>> {
        let page = self.get(&format!("projects/{project}/e2ee/epochs")).await?;
        let records: Vec<(EpochRecord, String)> = page["epochs"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| {
                Ok((
                    serde_json::from_value(e["record"].clone())?,
                    e["signature"].as_str().unwrap_or_default().to_owned(),
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        records::verify_epochs(log, &records)
            .map_err(|e| anyhow!("the epoch records do not verify: {e}"))?;
        // A server that rolls back, withholds or forks what this device saw before is caught.
        let mut pins: BTreeMap<Uuid, records::Pin> = match std::fs::read(&self.pins) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("{} is damaged", self.pins.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        let plain: Vec<EpochRecord> = records.iter().map(|(r, _)| r.clone()).collect();
        pins.entry(project)
            .or_default()
            .advance(log, &plain)
            .map_err(|e| anyhow!("{e}: the server may be presenting an altered history; do not share keys and tell the project owner"))?;
        std::fs::write(&self.pins, serde_json::to_vec_pretty(&pins)?)?;
        Ok(records)
    }
    /// Every epoch root this device holds, each checked against its record.
    async fn roots(
        &self,
        project: Uuid,
        log: &Log,
        records: &[(EpochRecord, String)],
        recipient: &DeviceKey,
    ) -> anyhow::Result<BTreeMap<u32, Key>> {
        let page = self
            .get(&format!(
                "projects/{project}/e2ee/grants?recipient_key={}",
                recipient.public_hex()
            ))
            .await?;
        let grants: Vec<Grant> = serde_json::from_value(page["grants"].clone())?;
        let mut out = BTreeMap::new();
        for g in grants
            .iter()
            .filter(|g| matches!(g.scope, Scope::Project) && g.delegation.is_none())
        {
            let Some((record, _)) = records.iter().find(|(r, _)| r.epoch == g.epoch) else {
                continue;
            };
            // The creator must be an active key of a manager in the verified log.
            ensure!(
                log.signer(&g.created_by_key).is_some()
                    || records
                        .iter()
                        .any(|(r, _)| r.created_by_key == g.created_by_key),
                "a grant's creator is not in the membership log"
            );
            if g.epoch_record != hex::encode(record.hash()?) {
                bail!("a grant names another epoch record");
            }
            out.insert(
                g.epoch,
                g.open_root(&g.created_by_key, recipient, &record.key_id)?,
            );
        }
        Ok(out)
    }
    fn entry(
        &self,
        project: Uuid,
        log: &Log,
        kind: &str,
        body: Value,
    ) -> anyhow::Result<SignedEntry> {
        self.entry_by(&self.sign, project, log, kind, body)
    }
    fn entry_by(
        &self,
        signer: &Ed25519KeyPair,
        project: Uuid,
        log: &Log,
        kind: &str,
        body: Value,
    ) -> anyhow::Result<SignedEntry> {
        use ring::signature::KeyPair;
        Ok(Entry {
            version: 1,
            project,
            index: log.length,
            previous: log.head.map(hex::encode),
            entry_type: kind.into(),
            body,
            signer_key: hex::encode(signer.public_key().as_ref()),
            created_at_ms: now_ms(),
        }
        .sign(signer)?)
    }
    /// The device row id of every encryption key in the directory.
    async fn devices(&self, project: Uuid) -> anyhow::Result<BTreeMap<String, Uuid>> {
        let d = self
            .get(&format!("projects/{project}/e2ee/directory"))
            .await?;
        Ok(d["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| {
                Some((
                    x["encryption_key"].as_str()?.to_owned(),
                    x["device"].as_str()?.parse().ok()?,
                ))
            })
            .collect())
    }
    #[allow(clippy::too_many_arguments)]
    /// A grant of `secret` to one recipient key named by the log.
    async fn grant_to(
        &self,
        project: Uuid,
        epoch: u32,
        record_hash: &str,
        key: &str,
        kind: &str,
        devices: &BTreeMap<String, Uuid>,
        secret: &[u8],
    ) -> anyhow::Result<Grant> {
        let device = (kind == "device")
            .then(|| devices.get(key).copied())
            .flatten();
        ensure!(
            kind != "device" || device.is_some(),
            "a device in the log is not in the directory"
        );
        Ok(Grant {
            version: 1,
            project,
            epoch,
            scope: Scope::Project,
            recipient_kind: kind.into(),
            recipient_device: device,
            recipient_key: key.into(),
            suite: GRANT_SUITE,
            delegation: None,
            enc: String::new(),
            ciphertext: String::new(),
            epoch_record: record_hash.into(),
            created_by_key: String::new(),
            created_at_ms: now_ms(),
            signature: String::new(),
        }
        .seal(secret, &self.sign)?)
    }
    /// Open the next epoch for the log's recipient set (after `removal`, if any).
    async fn open_epoch(
        &self,
        project: Uuid,
        reason: &str,
        removal: Option<SignedEntry>,
    ) -> anyhow::Result<u32> {
        let (_, mut log) = self.log(project).await?;
        let records = self.epochs(project, &log).await?;
        if let Some(r) = &removal {
            log.append(r)?;
        }
        let epoch = records.len() as u32 + 1;
        let root = Key::random()?;
        let devices = self.devices(project).await?;
        let kind_of = |key: &str| {
            if log.encryption_keys.contains_key(key) {
                "device"
            } else if log.escrow.as_deref() == Some(key) {
                "escrow"
            } else {
                "recovery"
            }
        };
        let mut grants = Vec::new();
        for key in log.recipients() {
            grants.push(
                self.grant_to(
                    project,
                    epoch,
                    &"0".repeat(64),
                    &key,
                    kind_of(&key),
                    &devices,
                    root.as_bytes(),
                )
                .await?,
            );
        }
        let record = EpochRecord {
            version: 1,
            project,
            epoch,
            previous_epoch_record: records
                .last()
                .map(|(r, _)| r.hash().map(hex::encode))
                .transpose()?,
            reason: reason.into(),
            suite: seal::SUITE,
            key_id: hex::encode(keys::key_id(epoch, &root)),
            recipients_digest: grant::recipients_digest(&grants)?,
            membership_head: log
                .head
                .map(hex::encode)
                .ok_or_else(|| anyhow!("empty membership log"))?,
            history_policy: "full".into(),
            created_by_key: self.signing(),
            created_at_ms: now_ms(),
        };
        let record_hash = hex::encode(record.hash()?);
        // The grants name the record; their HPKE output does not depend on it (decision 035).
        for g in &mut grants {
            g.epoch_record = record_hash.clone();
            g.signature.clear();
            g.signature = hex::encode(
                self.sign
                    .sign(&[grant::SIGNATURE_LABEL, &g.hash()?].concat())
                    .as_ref(),
            );
        }
        let log_entry = self.entry(
            project,
            &log,
            "epoch_open",
            json!({"epoch": epoch, "record_hash": record_hash}),
        )?;
        self.post(
            &format!("projects/{project}/e2ee/epochs"),
            json!({"record": record, "signature": record.sign(&self.sign)?, "log_entry": log_entry, "grants": grants, "removal": removal}),
        )
        .await?;
        Ok(epoch)
    }
    /// Seal `state` as the next version of `document` (a new sealed file when `None`) and
    /// publish a v4 commit; returns the file and the commit address.
    async fn publish(
        &self,
        project: Uuid,
        state: &DocumentState,
        name: &str,
        message: &str,
        document: Option<Uuid>,
    ) -> anyhow::Result<(Uuid, Address)> {
        let (_, log) = self.log(project).await?;
        let records = self.epochs(project, &log).await?;
        let roots = self.roots(project, &log, &records, &self.enc).await?;
        let (&epoch, root) = roots
            .iter()
            .next_back()
            .ok_or_else(|| anyhow!("this device holds no epoch of this project"))?;
        let document = match document {
            Some(d) => d,
            None => serde_json::from_value(
                self.post(&format!("projects/{project}/e2ee/documents"), json!({}))
                    .await?["id"]
                    .clone(),
            )?,
        };
        let written = state::write(
            state,
            project,
            document,
            epoch,
            &epoch_keys(root, epoch, project, document)?,
            None,
        )?;
        for chunk in written.objects.chunks(32) {
            let objects: Vec<Value> = chunk
                .iter()
                .map(|(a, b)| json!({"address": a, "bytes": STANDARD.encode(b)}))
                .collect();
            self.post(
                &format!("projects/{project}/staging/objects"),
                json!({"document": document, "objects": objects}),
            )
            .await?;
        }
        let sealed = Sealed {
            epoch,
            membership_head: log
                .head
                .map(hex::encode)
                .ok_or_else(|| anyhow!("empty membership log"))?,
            message: meta(root, epoch, project, commit::MESSAGE_NODE, json!(message))?,
            paths: meta(
                root,
                epoch,
                project,
                commit::PATHS_NODE,
                json!({document.to_string(): name}),
            )?,
        };
        let signed = SignedCommit::sign(
            Commit {
                version: 4,
                project,
                parents: vec![],
                files: BTreeMap::from([(
                    document.to_string(),
                    FileEntry {
                        document: DocumentId(document),
                        state: written.root.clone(),
                    },
                )]),
                author_key: String::new(),
                authored_at_ms: now_ms(),
                message: String::new(),
                recovery: None,
                same_file_resolutions: Vec::new(),
                merge_policy: None,
                project_resolutions: Vec::new(),
                relocations: Vec::new(),
                sealed: Some(Box::new(sealed)),
            },
            &self.sign,
        )?;
        let address = signed.verify()?;
        self.post(
            &format!("projects/{project}/staging/commits"),
            json!(signed),
        )
        .await?;
        self.post(
            &format!("projects/{project}/history/commits"),
            json!({"address": address}),
        )
        .await?;
        Ok((document, address))
    }

    /// Decrypt one file of a published sealed commit on this device.
    async fn read(
        &self,
        project: Uuid,
        commit: &str,
        document: Uuid,
    ) -> anyhow::Result<(DocumentState, BTreeMap<String, state::NodeRef>)> {
        let (_, log) = self.log(project).await?;
        let records = self.epochs(project, &log).await?;
        let roots = self.roots(project, &log, &records, &self.enc).await?;
        let held: BTreeMap<u32, state::EpochKeys> = roots
            .iter()
            .map(|(e, r)| Ok((*e, epoch_keys(r, *e, project, document)?)))
            .collect::<anyhow::Result<_>>()?;
        let signed: SignedCommit = serde_json::from_value(
            self.get(&format!("projects/{project}/history/commits/{commit}"))
                .await?,
        )?;
        ensure!(
            signed.verify()?.as_str() == commit,
            "the commit does not verify"
        );
        let root = signed
            .commit
            .files
            .values()
            .find(|f| f.document.0 == document)
            .ok_or_else(|| anyhow!("the commit has no such file"))?
            .state
            .clone();
        let objects = fetch(self, project, commit, document, &root).await?;
        Ok(state::read(&root, &objects, project, document, &held)?)
    }
    /// Grant every held epoch root to one more recipient key.
    async fn grant_all(&self, project: Uuid, key: &str, kind: &str) -> anyhow::Result<usize> {
        let (_, log) = self.log(project).await?;
        let records = self.epochs(project, &log).await?;
        let roots = self.roots(project, &log, &records, &self.enc).await?;
        let devices = self.devices(project).await?;
        let mut grants = Vec::new();
        for (record, _) in &records {
            if let Some(root) = roots.get(&record.epoch) {
                grants.push(
                    self.grant_to(
                        project,
                        record.epoch,
                        &hex::encode(record.hash()?),
                        key,
                        kind,
                        &devices,
                        root.as_bytes(),
                    )
                    .await?,
                );
            }
        }
        if !grants.is_empty() {
            self.post(
                &format!("projects/{project}/e2ee/grants"),
                json!({"grants": grants}),
            )
            .await?;
        }
        Ok(grants.len())
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn meta(root: &Key, epoch: u32, project: Uuid, node: &str, value: Value) -> anyhow::Result<String> {
    let ctx = Context {
        project,
        document: None,
        node,
        kind: Kind::Meta,
        epoch,
        revision: 0,
    };
    Ok(commit::encode(&seal::seal(
        &keys::meta_key(root)?,
        keys::key_id(epoch, root),
        &keys::cid_key(root)?,
        &ctx,
        &[],
        &value,
    )?))
}

fn epoch_keys(
    root: &Key,
    epoch: u32,
    project: Uuid,
    document: Uuid,
) -> anyhow::Result<state::EpochKeys> {
    Ok(state::EpochKeys {
        key_id: keys::key_id(epoch, root),
        doc: keys::doc_key(root, project, document)?,
        cid: keys::cid_key(root)?,
    })
}

/// A line typed on this terminal; refuses when standard input is not a terminal, so an agent
/// that drives this process cannot consent for the person.
fn typed(prompt: &str) -> anyhow::Result<String> {
    ensure!(
        std::io::stdin().is_terminal(),
        "this needs your typed answer on a terminal"
    );
    eprint!("{prompt}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

pub async fn run(options: Options) -> anyhow::Result<()> {
    let base = engine_mcp::parse_base(&options.server, options.allow_loopback_http)
        .map_err(|e| anyhow!("{e}"))?;
    let token = String::from_utf8(
        crate::signing::read_key_file(&options.token_file)
            .context("cannot read the --token-file")?,
    )?
    .trim()
    .to_owned();
    let keys =
        crate::signing::load_device_keys(&options.key, &crate::passphrase::Sources::current())?;
    if keys.legacy {
        eprintln!("note: this key file derives its encryption key from the signing key; `engine-cli device upgrade-key` gives it a separate one (dynodoc-key-v2) without changing either key");
    }
    let sign = Ed25519KeyPair::from_seed_unchecked(keys.seed.as_bytes())
        .map_err(|_| anyhow!("invalid signing key"))?;
    let enc = keys.encryption;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .user_agent("dynodoc-engine-cli/0.1 e2ee")
        .build()?;
    let c = Client {
        http,
        base,
        token,
        sign,
        enc,
        pins: options.key.with_extension("e2ee-pins.json"),
    };
    match options.action {
        Action::Fingerprint => {
            let (hash, digits) = records::fingerprint(&c.signing(), &c.enc.public_hex())?;
            println!("signing key      {}\nencryption key   {}\nfingerprint      {digits}\nqr payload       {hash}", c.signing(), c.enc.public_hex());
        }
        Action::Enroll { key_id } => {
            let caps = c.get("capabilities").await?;
            let authority: Uuid = serde_json::from_value(caps["installation"].clone())?;
            let identity: Uuid = c.me().await?.parse()?;
            let binding = Binding {
                version: 1,
                authority,
                identity,
                signing_key: c.signing(),
                encryption_key: c.enc.public_hex(),
                created_at_ms: now_ms(),
            };
            let signature = binding.sign(&c.sign)?;
            let r = c.post(&format!("devices/{key_id}/encryption-key"), json!({"public_key": c.enc.public_hex(), "binding": binding, "signature": signature})).await?;
            println!(
                "Registered. Fingerprint: {}",
                r["fingerprint"].as_str().unwrap_or_default()
            );
        }
        Action::Status { project } => {
            let s = c.get(&format!("projects/{project}/e2ee")).await?;
            let (_, log) = c.log(project).await?;
            let records = c.epochs(project, &log).await?;
            println!("Encrypted project (pre-release, not independently reviewed)\nmode {} epoch {} rotation pending {}", s["mode"], s["current_epoch"], s["rotation_pending"]);
            println!(
                "log verified: {} entries, head {}",
                log.length,
                log.head.map(hex::encode).unwrap_or_default()
            );
            println!(
                "epochs verified: {}; members {}; devices {}; recovery keys {}; escrow {}",
                records.len(),
                log.members.len(),
                log.encryption_keys.len(),
                log.recovery.len(),
                log.escrow.is_some()
            );
        }
        Action::Enable {
            project,
            acknowledge_unrecoverable,
            no_complete,
        } => {
            let identity = c.me().await?;
            let genesis = c.entry_by(&c.sign, project, &Log::new(project), "genesis", json!({"identity": identity, "signing_key": c.signing(), "encryption_key": c.enc.public_hex()}))?;
            c.post(
                &format!("projects/{project}/e2ee/begin"),
                json!({"genesis": genesis}),
            )
            .await?;
            let epoch = c.open_epoch(project, "project_created", None).await?;
            println!("Epoch {epoch} opened.");
            if !no_complete {
                let (_, log) = c.log(project).await?;
                let done = c.entry(project, &log, "migration_complete", json!({}))?;
                c.post(
                    &format!("projects/{project}/e2ee/complete"),
                    json!({"entry": done, "acknowledge_unrecoverable": acknowledge_unrecoverable}),
                )
                .await?;
                println!("This project is now an encrypted project (pre-release, not independently reviewed).");
            }
        }
        Action::AddMember {
            project,
            identity,
            role,
            signing_key,
            encryption_key,
            expect_fingerprint,
        } => {
            let (_, digits) = records::fingerprint(&signing_key, &encryption_key)?;
            let norm = |s: &str| s.chars().filter(char::is_ascii_digit).collect::<String>();
            ensure!(
                norm(&digits) == norm(&expect_fingerprint),
                "fingerprint differs: {digits}; do not add this device until you have verified it"
            );
            let (_, log) = c.log(project).await?;
            let add = c.entry(project, &log, "member_add", json!({"identity": identity, "role": role, "devices": [{"signing_key": signing_key, "encryption_key": encryption_key}]}))?;
            c.post(&format!("projects/{project}/e2ee/log"), json!(add))
                .await?;
            let n = c.grant_all(project, &encryption_key, "device").await?;
            println!("Added; {n} epoch grant(s) made for the new device.");
        }
        Action::RemoveMember { project, identity } => {
            let (_, log) = c.log(project).await?;
            let removal = c.entry(
                project,
                &log,
                "member_remove",
                json!({"identity": identity}),
            )?;
            let epoch = c
                .open_epoch(project, "member_removed", Some(removal))
                .await?;
            println!("Removed. Epoch {epoch} opened for the remaining devices. The person keeps what they already received; new content is protected.");
        }
        Action::Rotate { project, reason } => {
            let epoch = c.open_epoch(project, &reason, None).await?;
            println!("Epoch {epoch} opened.");
        }
        Action::RecoveryCreate { project, out } => {
            let rk = Key::random()?;
            let derived = recovery::derive(&rk)?;
            crate::private_file::write_new(
                &out,
                format!("{}\n", recovery::encode(&rk)).as_bytes(),
            )?;
            let identity = c.me().await?;
            let (_, log) = c.log(project).await?;
            use ring::signature::KeyPair;
            let set = c.entry(project, &log, "recovery_set", json!({"identity": identity, "signer_key": hex::encode(derived.signer.public_key().as_ref()), "recipient_key": derived.recipient.public_hex()}))?;
            c.post(&format!("projects/{project}/e2ee/log"), json!(set))
                .await?;
            let n = c
                .grant_all(project, &derived.recipient.public_hex(), "recovery")
                .await?;
            println!("Recovery key written to {} (keep it offline; it is shown nowhere else). {n} epoch grant(s) made.", out.display());
        }
        Action::EscrowSet {
            project,
            recipient_key,
        } => {
            let (_, log) = c.log(project).await?;
            let set = c.entry(
                project,
                &log,
                "escrow_set",
                json!({"recipient_key": recipient_key}),
            )?;
            c.post(&format!("projects/{project}/e2ee/log"), json!(set))
                .await?;
            let n = c.grant_all(project, &recipient_key, "escrow").await?;
            println!("Escrow recipient registered; {n} epoch grant(s) made. Members now see that the organisation can recover this project.");
        }
        Action::EscrowRecover {
            project,
            shares,
            identity,
            signing_key,
            encryption_key,
            expect_fingerprint,
            ticket,
        } => {
            let (_, digits) = records::fingerprint(&signing_key, &encryption_key)?;
            let norm = |s: &str| s.chars().filter(char::is_ascii_digit).collect::<String>();
            ensure!(
                norm(&digits) == norm(&expect_fingerprint),
                "fingerprint differs: {digits}; do not continue until you have verified the device"
            );
            let secret = engine_core::e2ee::escrow::combine(&crate::escrow::read_shares(&shares)?)?;
            let escrow_key = recovery::escrow_recipient(&secret)?;
            drop(secret);
            let (_, log) = c.log(project).await?;
            ensure!(
                log.escrow.as_deref() == Some(escrow_key.public_hex().as_str()),
                "these shares are not this project's escrow key"
            );
            ensure!(
                log.members.contains_key(&identity),
                "that person is not a member of this project"
            );
            let records = c.epochs(project, &log).await?;
            let roots = c.roots(project, &log, &records, &escrow_key).await?;
            ensure!(!roots.is_empty(), "no grant is addressed to the escrow key");
            let mut log = log;
            if !log.encryption_keys.contains_key(&encryption_key) {
                let add = c.entry(project, &log, "device_add", json!({"identity": identity, "signing_key": signing_key, "encryption_key": encryption_key}))?;
                c.post(&format!("projects/{project}/e2ee/log"), json!(add))
                    .await?;
                log.append(&add)?;
            }
            let entry = c.entry(project, &log, "escrow_recover", json!({"identity": identity, "signing_key": signing_key, "encryption_key": encryption_key, "ticket": ticket}))?;
            c.post(&format!("projects/{project}/e2ee/log"), json!(entry))
                .await?;
            let devices = c.devices(project).await?;
            let mut grants = Vec::new();
            for (record, _) in &records {
                if let Some(root) = roots.get(&record.epoch) {
                    grants.push(
                        c.grant_to(
                            project,
                            record.epoch,
                            &hex::encode(record.hash()?),
                            &encryption_key,
                            "device",
                            &devices,
                            root.as_bytes(),
                        )
                        .await?,
                    );
                }
            }
            c.post(
                &format!("projects/{project}/e2ee/grants"),
                json!({"grants": grants}),
            )
            .await?;
            println!(
                "Recovered with escrow: {} epoch(s) re-sealed to the member's new device; recorded in the membership log.",
                roots.len()
            );
        }
        Action::RecoveryUse {
            project,
            recovery_key_file,
        } => {
            let text = String::from_utf8(crate::signing::read_key_file(&recovery_key_file)?)?;
            let rk = recovery::decode(text.trim())?;
            let derived = recovery::derive(&rk)?;
            let (_, log) = c.log(project).await?;
            let records = c.epochs(project, &log).await?;
            let roots = c.roots(project, &log, &records, &derived.recipient).await?;
            ensure!(
                !roots.is_empty(),
                "no grant is addressed to this recovery key"
            );
            let identity = c.me().await?;
            let add = c.entry_by(&derived.signer, project, &log, "device_add", json!({"identity": identity, "signing_key": c.signing(), "encryption_key": c.enc.public_hex()}))?;
            c.post(&format!("projects/{project}/e2ee/log"), json!(add))
                .await?;
            let devices = c.devices(project).await?;
            let mut grants = Vec::new();
            for (record, _) in &records {
                if let Some(root) = roots.get(&record.epoch) {
                    grants.push(
                        c.grant_to(
                            project,
                            record.epoch,
                            &hex::encode(record.hash()?),
                            &c.enc.public_hex(),
                            "device",
                            &devices,
                            root.as_bytes(),
                        )
                        .await?,
                    );
                }
            }
            c.post(
                &format!("projects/{project}/e2ee/grants"),
                json!({"grants": grants}),
            )
            .await?;
            println!(
                "This device was added with your recovery key and holds {} epoch(s).",
                roots.len()
            );
        }
        Action::Verify { project } => {
            let (_, log) = c.log(project).await?;
            let records = c.epochs(project, &log).await?;
            let roots = c.roots(project, &log, &records, &c.enc).await?;
            println!(
                "log: {} entries verified; epochs: {} verified; this device opens {} of them",
                log.length,
                records.len(),
                roots.len()
            );
            ensure!(
                log.encryption_keys.contains_key(&c.enc.public_hex()),
                "this device is not in the membership log"
            );
        }
        Action::Put {
            project,
            state: path,
            name,
            message,
            document,
        } => {
            let state: DocumentState = serde_json::from_slice(&std::fs::read(&path)?)
                .context("the --state file is not a document state")?;
            let (document, address) = c
                .publish(project, &state, &name, &message, document)
                .await?;
            println!(
                "Published sealed commit {} for file {document}.",
                address.as_str()
            );
        }
        Action::Migrate { project, document } => {
            // Migration M1 (protocol 7): a sealed successor of a plaintext file, verified by
            // decrypting it back here, then the original archived. Erasing the original is the
            // separate two-person legacy erasure.
            let detail = c.get(&format!("documents/{document}")).await?;
            let state: DocumentState = serde_json::from_value(detail["state"].clone())
                .context("cannot read the plaintext file's state")?;
            let title = detail["title"]
                .as_str()
                .unwrap_or("Migrated file")
                .to_owned();
            let (successor, address) = c
                .publish(project, &state, &title, "Moved from a plaintext file", None)
                .await?;
            let (back, _) = c.read(project, address.as_str(), successor).await?;
            let same = engine_core::hashing::merkle_root(&back)?
                == engine_core::hashing::merkle_root(&state)?;
            ensure!(
                same && back == state,
                "the sealed copy differs from the original; the original was kept unchanged"
            );
            c.post(
                &format!("documents/{document}/metadata"),
                json!({"archived": true}),
            )
            .await?;
            println!(
                "Verification report\n  original   {document} (archived, still plaintext on the server)\n  successor  {successor}\n  commit     {}\n  blocks     {} identical after decryption\nAsk for the original's erasure: POST /documents/{document}/e2ee/legacy-erasure, then another administrator confirms it.",
                address.as_str(),
                back.nodes.len()
            );
        }
        Action::Get {
            project,
            commit,
            document,
            out,
        } => {
            let (opened, _) = c.read(project, &commit, document).await?;
            crate::private_file::write_new(&out, &serde_json::to_vec_pretty(&opened)?)?;
            println!(
                "Decrypted to {} (a local plaintext copy: Dynodoc's encryption does not cover it).",
                out.display()
            );
        }
        Action::Mcp {
            project,
            commit,
            document,
            name,
        } => {
            let (_, log) = c.log(project).await?;
            let records = c.epochs(project, &log).await?;
            let page = c
                .get(&format!(
                    "projects/{project}/e2ee/grants?recipient_key={}",
                    c.enc.public_hex()
                ))
                .await?;
            let grants: Vec<Grant> = serde_json::from_value(page["grants"].clone())?;
            let g = grants
                .iter()
                .rev()
                .find(|g| g.delegation.is_some() && g.scope == Scope::Document { document })
                .ok_or_else(|| anyhow!("no delegation of this file to this agent key; ask a member to run `e2ee delegate`"))?;
            // The delegator must be an active member device in the verified log.
            ensure!(
                log.signer(&g.created_by_key).is_some(),
                "the delegation's creator is not in the membership log"
            );
            let named = records.iter().any(|(r, _)| {
                r.epoch == g.epoch
                    && r.hash().map(hex::encode).ok().as_deref() == Some(g.epoch_record.as_str())
            });
            ensure!(named, "the delegation names an unknown epoch record");
            let held = g.open_delegation(&g.created_by_key, &c.enc, now_ms())?;
            let signed: SignedCommit = serde_json::from_value(
                c.get(&format!("projects/{project}/history/commits/{commit}"))
                    .await?,
            )?;
            ensure!(
                signed.verify()?.as_str() == commit,
                "the commit does not verify"
            );
            let root = signed
                .commit
                .files
                .values()
                .find(|f| f.document.0 == document)
                .ok_or_else(|| anyhow!("the commit has no such file"))?
                .state
                .clone();
            let objects = fetch(&c, project, &commit, document, &root).await?;
            let (opened, _) = state::read(&root, &objects, project, document, &held)?;
            tracing::info!(%project, %document, "local MCP server for one encrypted file ready on stdio (read only)");
            let backend = local_mcp::SealedBackend {
                document,
                name,
                state: opened,
            };
            engine_mcp::Server::new(backend, engine_mcp::Profile::read_only())
                .serve_stdio()
                .await
                .context("standard input/output failed")?;
        }
        Action::Delegate {
            project,
            document,
            agent_key,
            hours,
        } => {
            let s = c.get(&format!("projects/{project}/e2ee")).await?;
            ensure!(
                s["agent_delegation"] != "none",
                "this project's policy does not allow delegating keys to agents"
            );
            eprintln!(
                "This assistant will read the text of file {document} from your encrypted project and may send parts of it\n\
                 to the AI provider you configured in your assistant application. Dynodoc's encryption protects the file in\n\
                 Dynodoc's systems. It does not apply after the text leaves your device. Check that provider's terms first.\n\
                 Members of the project will see that you granted this access, read-only, for {hours} hour(s).\n\
                 Document text can contain instructions aimed at the assistant (prompt injection)."
            );
            ensure!(
                typed("Type ALLOW to grant read access, anything else cancels: ")? == "ALLOW",
                "cancelled"
            );
            let (_, log) = c.log(project).await?;
            let records = c.epochs(project, &log).await?;
            let roots = c.roots(project, &log, &records, &c.enc).await?;
            let expires = now_ms() + i64::from(hours.clamp(1, 24)) * 3_600_000;
            let entry = c.entry(project, &log, "agent_grant", json!({"document": document, "agent_key": agent_key, "scope": "read", "expires_at_ms": expires}))?;
            c.post(&format!("projects/{project}/e2ee/log"), json!(entry))
                .await?;
            let mut list = Vec::new();
            for (epoch, root) in &roots {
                list.push((
                    *epoch,
                    keys::doc_key(root, project, document)?,
                    keys::cid_key(root)?,
                    keys::key_id(*epoch, root),
                ));
            }
            let refs: Vec<(u32, &Key, &Key, [u8; 8])> =
                list.iter().map(|(e, d, c, k)| (*e, d, c, *k)).collect();
            let plain = grant::delegation_plaintext(&refs)?;
            let (record, _) = records.last().ok_or_else(|| anyhow!("no epoch yet"))?;
            let g = Grant {
                version: 1,
                project,
                epoch: record.epoch,
                scope: Scope::Document { document },
                recipient_kind: "agent".into(),
                recipient_device: None,
                recipient_key: agent_key,
                suite: GRANT_SUITE,
                delegation: Some(grant::Delegation {
                    expires_at_ms: expires,
                    purpose: "agent".into(),
                    read_only: true,
                }),
                enc: String::new(),
                ciphertext: String::new(),
                epoch_record: hex::encode(record.hash()?),
                created_by_key: String::new(),
                created_at_ms: now_ms(),
                signature: String::new(),
            }
            .seal(&plain, &c.sign)?;
            c.post(
                &format!("projects/{project}/e2ee/grants"),
                json!({"grants": [g]}),
            )
            .await?;
            println!("Delegated read access to {document} until {expires} (ms since 1970).");
        }
    }
    Ok(())
}

/// Every object reachable from a sealed state root of a published commit.
async fn fetch(
    c: &Client,
    project: Uuid,
    commit: &str,
    document: Uuid,
    root: &Address,
) -> anyhow::Result<BTreeMap<Address, Vec<u8>>> {
    let mut out = BTreeMap::new();
    let mut queue = vec![root.clone()];
    while let Some(address) = queue.pop() {
        if out.contains_key(&address) {
            continue;
        }
        ensure!(out.len() < 200_000, "too many objects");
        let o = c
            .get(&format!(
                "projects/{project}/history/commits/{commit}/objects/{document}/{}",
                address.as_str()
            ))
            .await?;
        let bytes = STANDARD.decode(o["bytes"].as_str().unwrap_or_default())?;
        queue.extend(engine_core::shared_checkpoint::references(
            &address, &bytes,
        )?);
        out.insert(address, bytes);
    }
    Ok(out)
}
