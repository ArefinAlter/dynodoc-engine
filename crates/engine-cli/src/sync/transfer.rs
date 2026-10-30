use super::*;

/// Follow only codec-reachable edges, never a server's free-form object inventory.
/// One state is resident at a time; all files in a commit share the read budget.
struct Graph<'a> {
    repo: &'a LocalRepository,
    remote: Option<(&'a Client, &'a Address)>,
    seen: BTreeSet<Address>,
    objects: usize,
    bytes: usize,
}
impl<'a> Graph<'a> {
    fn new(repo: &'a LocalRepository, remote: Option<(&'a Client, &'a Address)>) -> Self {
        Self {
            repo,
            remote,
            seen: BTreeSet::new(),
            objects: 0,
            bytes: 0,
        }
    }
    async fn state(
        &mut self,
        document: DocumentId,
        root: &Address,
    ) -> anyhow::Result<Vec<Address>> {
        self.seen.clear();
        typed::read_state(
            self,
            document,
            root,
            Limits {
                max_objects: GRAPH_OBJECTS,
                max_bytes: GRAPH_BYTES,
            },
            Default::default(),
        )
        .await?;
        Ok(std::mem::take(&mut self.seen).into_iter().collect())
    }
    async fn read(&mut self, document: DocumentId, address: &Address) -> anyhow::Result<Vec<u8>> {
        ensure!(
            self.objects < GRAPH_OBJECTS,
            "commit graph read count limit"
        );
        self.objects += 1;
        let key = ObjectKey {
            document,
            address: address.clone(),
        };
        let bytes = if !self
            .repo
            .missing(std::slice::from_ref(&key))
            .await?
            .is_empty()
        {
            let (client, commit) = self
                .remote
                .ok_or_else(|| anyhow!("selected local graph is incomplete"))?;
            #[derive(Deserialize)]
            struct Packet {
                address: Address,
                bytes: String,
            }
            let object: Packet = client
                .get(
                    &format!(
                        "history/commits/{}/objects/{}/{}",
                        commit.as_str(),
                        document.0,
                        address.as_str()
                    ),
                    &[],
                    1_500_000,
                )
                .await?;
            ensure!(
                object.address == *address,
                "object response address mismatch"
            );
            let bytes = STANDARD.decode(object.bytes)?;
            shared_checkpoint::validate_stored(address, &bytes)?;
            ensure!(
                bytes.len() <= GRAPH_BYTES.saturating_sub(self.bytes),
                "commit graph byte limit"
            );
            self.repo
                .import_objects(&[ObjectPacket {
                    key,
                    bytes: bytes.clone(),
                }])
                .await?;
            bytes
        } else {
            self.repo.object(&key).await?.bytes
        };
        ensure!(
            bytes.len() <= GRAPH_BYTES.saturating_sub(self.bytes),
            "commit graph byte limit"
        );
        self.bytes += bytes.len();
        self.seen.insert(address.clone());
        Ok(bytes)
    }
}
impl ObjectStore for Graph<'_> {
    async fn put(
        &mut self,
        _: DocumentId,
        _: &Address,
        _: &[u8],
    ) -> Result<bool, shared_checkpoint::Error> {
        Err(shared_checkpoint::Error::Invalid(
            "transfer reader is read-only",
        ))
    }
    async fn get(
        &mut self,
        document: DocumentId,
        address: &Address,
    ) -> Result<Vec<u8>, shared_checkpoint::Error> {
        self.read(document, address)
            .await
            .map_err(|e| shared_checkpoint::Error::Io(std::io::Error::other(e.to_string())))
    }
}

pub(super) async fn fetch(
    repo: &LocalRepository,
    client: &Client,
    candidate: &Address,
) -> anyhow::Result<usize> {
    let mut stack = vec![(candidate.clone(), false)];
    let mut visited = BTreeSet::new();
    let mut waiting = BTreeMap::<Address, SignedCommit>::new();
    let mut bytes = 0;
    let mut count = 0;
    while let Some((address, exit)) = stack.pop() {
        if exit {
            let signed = waiting
                .remove(&address)
                .ok_or_else(|| anyhow!("missing pending commit"))?;
            let mut graph = Graph::new(repo, Some((client, &address)));
            for file in signed.commit.files.values() {
                graph.state(file.document, &file.state).await?;
            }
            repo.import_commit(&signed).await?;
            count += 1;
            continue;
        }
        if !visited.insert(address.clone()) {
            continue;
        }
        ensure!(
            visited.len() <= MAX_COMMITS,
            "fetch commit limit; retained verified objects are reusable on retry"
        );
        match repo.commit(&address).await {
            Ok(signed) => {
                // Revalidate the requested head's graphs even on an exact retry.
                if &address == candidate {
                    repo.import_commit(&signed).await?;
                }
                continue;
            }
            Err(engine_core::repository::Error::Missing(_)) => {}
            Err(error) => return Err(error.into()),
        }
        let signed = client
            .published(&address)
            .await?
            .ok_or_else(|| anyhow!("published dependency unavailable; no branch or pin changed"))?;
        bytes += serde_json::to_vec(&signed)?.len();
        ensure!(bytes <= MAX_PLAN_BYTES, "fetch manifest byte limit");
        stack.push((address.clone(), true));
        for dependency in signed.commit.dependencies().into_iter().rev() {
            stack.push((dependency, false));
        }
        waiting.insert(address, signed);
    }
    Ok(count)
}

pub(super) async fn upload(
    repo: &LocalRepository,
    client: &Client,
    signed: &SignedCommit,
) -> anyhow::Result<()> {
    // Publication dependencies are now visible (topological push order). Reuse
    // their bytes only through an explicit authorized published-root acknowledgement.
    let mut dependencies = Vec::new();
    for address in signed.commit.dependencies() {
        let dependency = client
            .published(&address)
            .await?
            .ok_or_else(|| anyhow!("dependency disappeared before upload"))?;
        dependencies.push((address, dependency));
    }
    let mut graph = Graph::new(repo, None);
    for file in signed.commit.files.values() {
        let selected = graph.state(file.document, &file.state).await?;
        let mut missing = BTreeSet::new();
        for page in selected.chunks(256) {
            #[derive(Deserialize)]
            struct Missing {
                missing: Vec<Address>,
            }
            let result: Missing = serde_json::from_value(
                client
                    .post(
                        "staging/objects/missing",
                        json!({"document":file.document,"addresses":page}),
                    )
                    .await?,
            )?;
            ensure!(
                result.missing.len() <= page.len()
                    && result.missing.iter().all(|a| page.contains(a)),
                "unexpected missing-object response"
            );
            missing.extend(result.missing);
        }
        for (address, dependency) in &dependencies {
            if missing.is_empty() {
                break;
            }
            if !dependency
                .commit
                .files
                .values()
                .any(|f| f.document == file.document)
            {
                continue;
            }
            let mut after = String::new();
            let mut scanned = 0;
            loop {
                #[derive(Deserialize)]
                struct Page {
                    addresses: Vec<Address>,
                }
                let page: Page = client
                    .get(
                        &format!(
                            "history/commits/{}/objects/{}",
                            address.as_str(),
                            file.document.0
                        ),
                        &if after.is_empty() {
                            vec![("limit", "256".into())]
                        } else {
                            vec![("limit", "256".into()), ("after", after.clone())]
                        },
                        20 * 1024,
                    )
                    .await?;
                ensure!(page.addresses.len() <= 256, "published object page limit");
                if page.addresses.is_empty() {
                    break;
                }
                for a in &page.addresses {
                    ensure!(
                        a.as_str() > after.as_str(),
                        "nonmonotonic published object cursor"
                    );
                    after = a.as_str().to_owned();
                }
                scanned += page.addresses.len();
                ensure!(scanned <= GRAPH_OBJECTS, "published graph inventory limit");
                let reused: Vec<_> = page
                    .addresses
                    .into_iter()
                    .filter(|a| missing.contains(a))
                    .collect();
                if !reused.is_empty() {
                    client
                        .post(
                            &format!("history/commits/{}/acknowledge", address.as_str()),
                            json!({"document":file.document,"addresses":reused}),
                        )
                        .await?;
                    for a in reused {
                        missing.remove(&a);
                    }
                }
                if missing.is_empty() {
                    break;
                }
            }
        }
        // Pack by both count and decoded size; never load the full file into a transfer buffer.
        let mut batch = Vec::new();
        let mut bytes = 0;
        for address in missing {
            let object = repo
                .object(&ObjectKey {
                    document: file.document,
                    address,
                })
                .await?;
            if batch.len() == 64 || bytes + object.bytes.len() > 1024 * 1024 {
                client
                    .post(
                        "staging/objects",
                        json!({"document":file.document,"objects":batch}),
                    )
                    .await?;
                batch.clear();
                bytes = 0;
            }
            bytes += object.bytes.len();
            batch.push(json!({"address":object.key.address,"bytes":STANDARD.encode(object.bytes)}));
        }
        if !batch.is_empty() {
            client
                .post(
                    "staging/objects",
                    json!({"document":file.document,"objects":batch}),
                )
                .await?;
        }
    }
    Ok(())
}

use engine_core::repository::state_export::StateExportEnvelope;

/// Private temporary scratch directory for remote export.
/// Sets 0700 permissions on Unix and removes all contents recursively on Drop.
struct PrivateExportDir {
    path: PathBuf,
}

impl PrivateExportDir {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("dynodoc-export-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateExportDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Bounded remote-reachable object store fetching directly from client endpoints into scratch.
/// Never mutates or reads a local SQLite repository.
struct RemoteExportStore<'a> {
    client: &'a Client,
    commit: &'a Address,
    scratch_dir: PathBuf,
    objects: usize,
    bytes: usize,
}

impl<'a> RemoteExportStore<'a> {
    fn new(client: &'a Client, commit: &'a Address, scratch_dir: PathBuf) -> Self {
        Self {
            client,
            commit,
            scratch_dir,
            objects: 0,
            bytes: 0,
        }
    }

    async fn read(&mut self, document: DocumentId, address: &Address) -> anyhow::Result<Vec<u8>> {
        ensure!(
            self.objects < GRAPH_OBJECTS,
            "commit graph object limit reached ({GRAPH_OBJECTS})"
        );
        self.objects += 1;

        let scratch_file = self.scratch_dir.join(format!("{}.obj", address.as_str()));
        if scratch_file.exists() {
            let bytes = std::fs::read(&scratch_file)
                .with_context(|| format!("reading scratch object {}", address.as_str()))?;
            return Ok(bytes);
        }

        #[derive(Deserialize)]
        struct Packet {
            address: Address,
            bytes: String,
        }

        let object: Packet = self
            .client
            .get(
                &format!(
                    "history/commits/{}/objects/{}/{}",
                    self.commit.as_str(),
                    document.0,
                    address.as_str()
                ),
                &[],
                1_500_000,
            )
            .await
            .with_context(|| {
                format!(
                    "fetching remote object {} for document {}",
                    address.as_str(),
                    document.0
                )
            })?;

        ensure!(
            object.address == *address,
            "object response address mismatch: expected {}, got {}",
            address.as_str(),
            object.address.as_str()
        );

        let bytes = STANDARD
            .decode(object.bytes)
            .context("decoding base64 object payload")?;

        shared_checkpoint::validate_stored(address, &bytes)
            .with_context(|| format!("validating stored object {}", address.as_str()))?;

        ensure!(
            bytes.len() <= GRAPH_BYTES.saturating_sub(self.bytes),
            "commit graph byte limit exceeded ({GRAPH_BYTES})"
        );
        self.bytes += bytes.len();

        std::fs::write(&scratch_file, &bytes)
            .with_context(|| format!("writing scratch object {}", address.as_str()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&scratch_file, std::fs::Permissions::from_mode(0o600));
        }

        Ok(bytes)
    }
}

impl ObjectStore for RemoteExportStore<'_> {
    async fn put(
        &mut self,
        _: DocumentId,
        _: &Address,
        _: &[u8],
    ) -> Result<bool, shared_checkpoint::Error> {
        Err(shared_checkpoint::Error::Invalid(
            "remote export reader is read-only",
        ))
    }

    async fn get(
        &mut self,
        document: DocumentId,
        address: &Address,
    ) -> Result<Vec<u8>, shared_checkpoint::Error> {
        self.read(document, address)
            .await
            .map_err(|e| shared_checkpoint::Error::Io(std::io::Error::other(e.to_string())))
    }
}

/// Export an exact historical file from authorized remote history as normalized state.
///
/// Fetches only the reachable graph into private temporary storage, never trusts arbitrary
/// inventory, and never mutates a local repository. Validates every object and reconstructed root.
pub(crate) async fn export_file(
    client: &Client,
    project: Uuid,
    commit: &Address,
    path: &str,
    out: &Path,
) -> anyhow::Result<()> {
    ensure!(
        !out.exists(),
        "output file {} already exists; refusing overwrite",
        out.display()
    );

    // 1. Fetch published commit manifest
    let signed = client
        .published(commit)
        .await?
        .ok_or_else(|| anyhow!("commit {} not found on remote", commit.as_str()))?;

    // 2. Verify commit signature and address
    let actual_commit_address = signed.verify()?;
    ensure!(
        actual_commit_address == *commit,
        "commit address mismatch: expected {}, got {}",
        commit.as_str(),
        actual_commit_address.as_str()
    );

    // 3. Verify project match
    ensure!(
        signed.commit.project == project,
        "commit does not match requested project"
    );

    // 4. Exact file path match (no rename guessing)
    let file_entry = signed
        .commit
        .files
        .get(path)
        .ok_or_else(|| anyhow!("path '{}' not found in commit {}", path, commit.as_str()))?
        .clone();

    // 5. Create private temporary scratch directory with 0700 permissions
    let scratch = PrivateExportDir::new().context("creating private temporary directory")?;

    // 6. Fetch only reachable graph into scratch and reconstruct DocumentState
    let mut store = RemoteExportStore::new(client, commit, scratch.path().to_path_buf());
    let state = typed::read_state(
        &mut store,
        file_entry.document,
        &file_entry.state,
        Limits {
            max_objects: GRAPH_OBJECTS,
            max_bytes: GRAPH_BYTES,
        },
        Default::default(),
    )
    .await
    .map_err(|e| anyhow!("reconstructing historical document state: {e}"))?;

    // 7. Write normalized StateExportEnvelope to output path (fail-closed, 0600 mode)
    let envelope = StateExportEnvelope::new(path.to_string(), signed, state);
    envelope.write_to_path(out)?;

    Ok(())
}
