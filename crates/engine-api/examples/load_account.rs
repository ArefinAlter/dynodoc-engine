//! Disposable environment for scripts/large-files/load.mjs: creates a database, migrates
//! it, creates a runtime login with the runtime grants, and a synthetic account. The
//! runtime URL and a session token go to files, never to the terminal. `--drop` removes
//! the database and the login again.
//! DYNODOC_LOAD_TEST=disposable DATABASE_URL=<owner URL> PASETO_LOCAL_KEY=<64 hex> \
//!   cargo run --release -p engine-api --example load_account -- DIR [--drop]
use engine_api::auth::{store, token};
use sqlx::postgres::{PgConnectOptions, PgPool};

const DATABASE: &str = "large_files_load";
const ROLE: &str = "large_files_load_runtime";

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    anyhow::ensure!(
        std::env::var("DYNODOC_LOAD_TEST").as_deref() == Ok("disposable"),
        "explicit disposable database acknowledgement required"
    );
    let dir = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("usage: load_account DIR [--drop]"))?,
    );
    let owner: PgConnectOptions = std::env::var("DATABASE_URL")?.parse()?;
    let admin = PgPool::connect_with(owner.clone()).await?;
    if std::env::args().any(|a| a == "--drop") {
        sqlx::query(&format!("drop database if exists {DATABASE} with (force)"))
            .execute(&admin)
            .await?;
        sqlx::query(&format!("drop role if exists {ROLE}"))
            .execute(&admin)
            .await?;
        eprintln!("dropped {DATABASE} and {ROLE}");
        return Ok(());
    }
    let key = hex::decode(std::env::var("PASETO_LOCAL_KEY")?)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("PASETO_LOCAL_KEY must be 32 bytes of hex"))?;
    sqlx::query(&format!("create database {DATABASE}"))
        .execute(&admin)
        .await?;
    let pool = PgPool::connect_with(owner.clone().database(DATABASE)).await?;
    engine_core::database::MIGRATOR.run(&pool).await?;
    let password = uuid::Uuid::new_v4().simple().to_string();
    sqlx::raw_sql(&format!("create role {ROLE} login password '{password}' nosuperuser nocreatedb nocreaterole noreplication nobypassrls"))
        .execute(&admin)
        .await?;
    engine_core::database::grant_runtime(&pool, ROLE).await?;
    let identity = store::upsert_identity(&pool, "load-test@example.test", Some("Load test"))
        .await?
        .id
        .0;
    let host = owner.get_host().to_string();
    let port = owner.get_port();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("runtime-url"),
        format!("postgres://{ROLE}:{password}@{host}:{port}/{DATABASE}"),
    )?;
    std::fs::write(dir.join("token"), token::mint(&key, identity, 24 * 3600)?)?;
    eprintln!(
        "created {DATABASE}; runtime URL and token written to {}",
        dir.display()
    );
    Ok(())
}
