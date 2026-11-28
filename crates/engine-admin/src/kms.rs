//! `engine-admin kms`: customer-managed at-rest key operations (Phase 0, docs/END-TO-END-ENCRYPTION.md
//! 7.6; not end-to-end: the running service can unwrap these keys). Providers: the local
//! key-file provider, HashiCorp Vault Transit (the self-hosted reference, OQ-12), AWS KMS,
//! Google Cloud KMS and Azure Key Vault (`engine_core::at_rest::kms`, decision 041), with
//! credentials from the environment.
//!
//! Commands work on the `kms_key` and `data_key` tables (schema 97) with the operator's
//! migration login: create a project's data key, rewrap every data key after a KEK rotation
//! (no row data touched), rotate a project's data key (the old one stays decrypt-only), and
//! crypto-erase a project's keys, and seal a project's existing rows in place (`backfill`,
//! resumable). No unwrapped key is written anywhere or printed.
use anyhow::{bail, Context as _};
use clap::{Args, Subcommand};
use engine_core::at_rest::{Dek, KeyProvider, Purpose, WrapContext, Wrapped};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Args)]
pub struct ProviderArgs {
    /// `file` (a directory of `kek-<n>.key` files), `vault-transit`, `aws-kms`, `gcp-kms` or
    /// `azure-keyvault`. Cloud credentials come from the environment (`AWS_ACCESS_KEY_ID`,
    /// `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`; `GOOGLE_OAUTH_ACCESS_TOKEN`;
    /// `AZURE_ACCESS_TOKEN`; else the instance's metadata identity).
    #[arg(long)]
    provider: String,
    /// The key directory, Vault address, key ARN, Google key name
    /// (`projects/P/locations/L/keyRings/R/cryptoKeys/K`) or Azure key URL.
    #[arg(long)]
    key_ref: String,
    /// Vault Transit: the key name.
    #[arg(long, default_value = "dynodoc-data")]
    vault_key: String,
    #[arg(long, default_value = "transit")]
    vault_mount: String,
    /// Vault Transit: a private file holding the token.
    #[arg(long)]
    vault_token_file: Option<PathBuf>,
    #[arg(long)]
    allow_loopback_http: bool,
}

#[derive(Args)]
pub struct Options {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
pub enum Action {
    /// Register the provider key (once) and create the active data key of a project.
    CreateDataKey {
        #[command(flatten)]
        kms: ProviderArgs,
        /// Project UUID (omit to create the default installation-wide data key).
        #[arg(long)]
        project: Option<Uuid>,
    },
    /// After a KEK rotation in the provider: rewrap every data key of this key. Row data is
    /// not touched.
    Rewrap {
        #[command(flatten)]
        kms: ProviderArgs,
    },
    /// A new data key for a project; the old one stays decrypt-only for existing values.
    Rotate {
        #[command(flatten)]
        kms: ProviderArgs,
        #[arg(long)]
        project: Uuid,
    },
    /// Seal a project's existing plaintext rows with its active data key, in batches; safe
    /// to stop and run again (it resumes with the rows still plaintext).
    Backfill {
        #[command(flatten)]
        kms: ProviderArgs,
        #[arg(long)]
        project: Uuid,
        #[arg(long, default_value_t = 500)]
        batch: i64,
    },
    /// Crypto-erase: delete every data key of a project (database-only; does not contact
    /// cloud KMS). Values sealed under them, in the database and in backups, become unreadable.
    /// Irreversible; requires --confirm PROJECT (or use --dry-run to preview).
    Erase {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        confirm: Option<Uuid>,
        /// Show how many data keys would be deleted without changing the database.
        #[arg(long)]
        dry_run: bool,
    },
}

struct Config {
    provider: String,
    key_ref: String,
    vault_key: String,
    vault_mount: String,
    vault_token_file: Option<PathBuf>,
    allow_loopback_http: bool,
}

impl From<ProviderArgs> for Config {
    fn from(args: ProviderArgs) -> Self {
        Self {
            provider: args.provider,
            key_ref: args.key_ref,
            vault_key: args.vault_key,
            vault_mount: args.vault_mount,
            vault_token_file: args.vault_token_file,
            allow_loopback_http: args.allow_loopback_http,
        }
    }
}

fn provider(o: &Config) -> anyhow::Result<Box<dyn KeyProvider>> {
    let token = match &o.vault_token_file {
        Some(path) => Some(
            String::from_utf8(crate::key_read::read_key_file(path)?)?
                .trim()
                .to_owned(),
        ),
        None => None,
    };
    let env = |name: &str| match name {
        "DYNODOC_VAULT_TOKEN" => token.clone(),
        "DYNODOC_VAULT_KEY" => Some(o.vault_key.clone()),
        "DYNODOC_VAULT_MOUNT" => Some(o.vault_mount.clone()),
        _ => std::env::var(name).ok(),
    };
    if o.provider == "vault-transit" && token.is_none() {
        bail!("--vault-token-file is required");
    }
    Ok(engine_core::at_rest::kms::provider(
        &o.provider,
        &o.key_ref,
        o.allow_loopback_http,
        &env,
    )?)
}

pub async fn run(options: Options, pool: sqlx::PgPool) -> anyhow::Result<()> {
    if let Action::Erase {
        project,
        confirm,
        dry_run,
    } = options.action
    {
        let count: i64 = sqlx::query_scalar("select count(*) from data_key where project_id=$1")
            .bind(project)
            .fetch_one(&pool)
            .await
            .context("querying data_key count for project")?;
        if dry_run {
            println!("Dry run: would crypto-erase {count} data key(s) for project {project}.");
            return Ok(());
        }
        if confirm != Some(project) {
            bail!("refusing to crypto-erase project {project} without --confirm {project}");
        }
        let n = sqlx::query("delete from data_key where project_id=$1")
            .bind(project)
            .execute(&pool)
            .await?
            .rows_affected();
        if n == 0 {
            bail!("no data keys found for project {project}; nothing was erased");
        }
        println!("Crypto-erased: {n} data key(s) of {project} deleted. Values sealed under them cannot be read again.");
        return Ok(());
    }

    let installation: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(&pool)
        .await
        .context("failed to read installation id from device_authority; run `engine-admin migrate` first")?;

    let (provider_args, action) = match options.action {
        Action::CreateDataKey { kms, project } => (kms, KmsOp::CreateDataKey { project }),
        Action::Rewrap { kms } => (kms, KmsOp::Rewrap),
        Action::Rotate { kms, project } => (kms, KmsOp::Rotate { project }),
        Action::Backfill {
            kms,
            project,
            batch,
        } => (kms, KmsOp::Backfill { project, batch }),
        Action::Erase { .. } => unreachable!("handled above"),
    };

    let config = Config::from(provider_args);
    // Providers block (network or files): run them off the async runtime.
    let p: std::sync::Arc<dyn KeyProvider> = tokio::task::spawn_blocking(move || provider(&config))
        .await??
        .into();
    let info = p.describe();
    let existing_kms: Option<Uuid> = sqlx::query_scalar(
        "select id from kms_key where provider=$1 and key_ref=$2 and purpose='data' and status='active'",
    )
    .bind(info.provider)
    .bind(&info.key_ref)
    .fetch_optional(&pool)
    .await?;

    let wrap = |project: Option<Uuid>| {
        let p = p.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Wrapped> {
            Ok(p.wrap(
                &Dek::generate()?,
                &WrapContext::new(installation, project, Purpose::Data),
            )?)
        })
    };

    match action {
        KmsOp::CreateDataKey { project } => {
            let kms: Uuid = match existing_kms {
                Some(id) => id,
                None => sqlx::query_scalar(
                    "insert into kms_key(provider,key_ref,purpose) values($1,$2,'data') returning id",
                )
                .bind(info.provider)
                .bind(&info.key_ref)
                .fetch_one(&pool)
                .await?,
            };
            let w = wrap(project).await??;
            sqlx::query("insert into data_key(project_id,kms_key_id,kek_version,wrapped) values($1,$2,$3,$4)")
                .bind(project)
                .bind(kms)
                .bind(w.kek_version() as i32)
                .bind(w.as_bytes())
                .execute(&pool)
                .await
                .context("a project has one active data key; use rotate")?;
            println!(
                "Data key created under {} version {}.",
                info.provider,
                w.kek_version()
            );
        }
        KmsOp::Rotate { project } => {
            let kms = existing_kms.with_context(|| {
                format!(
                    "no active kms_key registered for provider={} key_ref={}; run `engine-admin kms create-data-key` first",
                    info.provider, info.key_ref
                )
            })?;
            let w = wrap(Some(project)).await??;
            let mut tx = pool.begin().await?;
            sqlx::query("update data_key set state='decrypt_only', retired_at=now() where project_id=$1 and state='active'").bind(project).execute(&mut *tx).await?;
            sqlx::query("insert into data_key(project_id,kms_key_id,kek_version,wrapped) values($1,$2,$3,$4)").bind(project).bind(kms).bind(w.kek_version() as i32).bind(w.as_bytes()).execute(&mut *tx).await?;
            tx.commit().await?;
            println!("New data key active; the previous one is decrypt-only.");
        }
        KmsOp::Rewrap => {
            let kms = existing_kms.with_context(|| {
                format!(
                    "no active kms_key registered for provider={} key_ref={}; run `engine-admin kms create-data-key` first",
                    info.provider, info.key_ref
                )
            })?;
            let rows: Vec<(i32, Option<Uuid>, i32, Vec<u8>)> = sqlx::query_as("select id,project_id,kek_version,wrapped from data_key where kms_key_id=$1 order by id").bind(kms).fetch_all(&pool).await?;
            let mut done = 0;
            for (id, project, version, bytes) in rows {
                let p = p.clone();
                let w = tokio::task::spawn_blocking(move || -> anyhow::Result<Wrapped> {
                    Ok(p.rewrap(
                        &Wrapped::new(version as u32, bytes)?,
                        &WrapContext::new(installation, project, Purpose::Data),
                    )?)
                })
                .await??;
                sqlx::query("update data_key set wrapped=$2,kek_version=$3 where id=$1")
                    .bind(id)
                    .bind(w.as_bytes())
                    .bind(w.kek_version() as i32)
                    .execute(&pool)
                    .await?;
                done += 1;
            }
            println!(
                "Rewrapped {done} data key(s) under version {}.",
                info.kek_version
            );
        }
        KmsOp::Backfill { project, batch } => {
            let _kms = existing_kms.with_context(|| {
                format!(
                    "no active kms_key registered for provider={} key_ref={}; run `engine-admin kms create-data-key` first",
                    info.provider, info.key_ref
                )
            })?;
            use engine_core::at_rest::store;
            store::install(store::AtRest::new(installation, p.clone()));
            let mut db = pool.acquire().await?;
            let (mut after, mut total) = (None, 0);
            loop {
                let (sealed, next) =
                    store::backfill_step(&mut db, project, after, batch.clamp(1, 5000)).await?;
                total += sealed;
                match next {
                    Some(position) => after = Some(position),
                    None => break,
                }
            }
            println!("Sealed {total} stored object(s) of {project} at rest. Run again to confirm: it seals only rows still in plaintext.");
        }
    }
    Ok(())
}

enum KmsOp {
    CreateDataKey { project: Option<Uuid> },
    Rewrap,
    Rotate { project: Uuid },
    Backfill { project: Uuid, batch: i64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        opts: Options,
    }

    #[test]
    fn erase_parses_without_provider_or_key_ref() {
        let project = Uuid::new_v4();
        let parsed = TestCli::try_parse_from([
            "kms",
            "erase",
            "--project",
            &project.to_string(),
            "--dry-run",
        ])
        .expect("erase should not require --provider or --key-ref");
        match parsed.opts.action {
            Action::Erase {
                project: p,
                confirm,
                dry_run,
            } => {
                assert_eq!(p, project);
                assert!(confirm.is_none());
                assert!(dry_run);
            }
            _ => panic!("expected Erase"),
        }
    }

    #[test]
    fn create_data_key_requires_provider_and_key_ref() {
        let err = TestCli::try_parse_from(["kms", "create-data-key"]);
        assert!(err.is_err());
    }
}
