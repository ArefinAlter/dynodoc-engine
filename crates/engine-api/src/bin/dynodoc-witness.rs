//! `dynodoc-witness`: a transparency witness on its own host and key (design phase
//! W3, decision 032). It cosigns a log's checkpoint only when it extends the one it
//! last cosigned. Configuration, all required except the listen address:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `DYNODOC_WITNESS_NAME` | this witness's key name, for example `witness.partner.example/w1` |
//! | `DYNODOC_WITNESS_KEY_FILE` | Ed25519 PKCS#8 DER private key, distinct from every log and authority key |
//! | `DYNODOC_WITNESS_LOGS` | space-separated log verifier keys (`origin+keyid+base64`) |
//! | `DYNODOC_WITNESS_STATE` | SQLite state file; restoring an old copy is a security incident |
//! | `DYNODOC_WITNESS_LISTEN` | address to bind, default `127.0.0.1:8090`; put TLS in front |
use anyhow::Context;
use engine_api::witness_service::{router, WitnessApp};
use engine_core::transparency::{
    witness::{Witness, WitnessState},
    KeyKind, Signer, VerifierKey,
};
use std::sync::Arc;

fn var(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let name = var("DYNODOC_WITNESS_NAME")?;
    let key =
        std::fs::read(var("DYNODOC_WITNESS_KEY_FILE")?).context("reading the witness key file")?;
    anyhow::ensure!(key.len() <= 4096, "witness key file too large");
    let signer = Signer::from_pkcs8(&name, KeyKind::Cosigner, &key)
        .map_err(|e| anyhow::anyhow!("witness key: {e}"))?;
    let logs = var("DYNODOC_WITNESS_LOGS")?
        .split_whitespace()
        .map(|v| VerifierKey::parse(v).map_err(|e| anyhow::anyhow!("log key {v}: {e}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    anyhow::ensure!(!logs.is_empty(), "DYNODOC_WITNESS_LOGS names no log");
    let origins = logs
        .iter()
        .map(|k| {
            (
                hex::encode(ring::digest::digest(
                    &ring::digest::SHA256,
                    k.name().as_bytes(),
                )),
                k.name().to_string(),
            )
        })
        .collect();
    let witness = Witness::new(signer, logs).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("witness verifier key: {}", witness.verifier_key());
    let state = WitnessState::open(std::path::Path::new(&var("DYNODOC_WITNESS_STATE")?))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let listen =
        std::env::var("DYNODOC_WITNESS_LISTEN").unwrap_or_else(|_| "127.0.0.1:8090".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "dynodoc-witness listening");
    axum::serve(
        listener,
        router(WitnessApp {
            witness: Arc::new(witness),
            state,
            origins: Arc::new(origins),
        }),
    )
    .await?;
    Ok(())
}
