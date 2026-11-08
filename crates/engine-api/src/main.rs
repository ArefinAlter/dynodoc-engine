//! dynodoc API server (binary entry point).
//!
//! Reads configuration, verifies the schema and restricted Postgres login, and
//! serves [`engine_api::app`]. The server exposes the full REST + SSE
//! surface (stage 18) on top of the `/auth/*` identity routes (stage 17): documents,
//! the governance-gated write path, the per-document event stream, and the public
//! audit endpoints.

#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use std::{future::IntoFuture, net::SocketAddr};

use anyhow::Context as _;
use engine_api::{app, config::StartupConfig, AppState};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,engine_api=debug".into()),
        )
        .init();

    // Fail before connecting, listing every configuration problem at once: missing
    // configuration is never a dev bypass.
    let StartupConfig {
        auth: config,
        database_url,
        retention,
        identity_key,
        session,
        scim_rate_per_minute,
        fanout,
        pool: pool_config,
        shutdown_drain_seconds,
        objects,
        reauth_seconds,
    } = StartupConfig::from_env()?;
    let statement_timeout = format!(
        "set statement_timeout = '{}ms'",
        pool_config.statement_timeout_ms
    );
    let pool = PgPoolOptions::new()
        .max_connections(pool_config.max_connections)
        .acquire_timeout(std::time::Duration::from_millis(
            pool_config.acquire_timeout_ms,
        ))
        .after_connect(move |connection, _| {
            let statement_timeout = statement_timeout.clone();
            Box::pin(async move {
                for statement in [
                    "set search_path = pg_catalog, public, pg_temp",
                    statement_timeout.as_str(),
                    "set lock_timeout = '5s'",
                    "set idle_in_transaction_session_timeout = '30s'",
                ] {
                    sqlx::query(statement).execute(&mut *connection).await?;
                }
                Ok(())
            })
        })
        .connect(database_url.expose())
        .await
        .context("could not connect to Postgres")?;

    engine_core::database::check_runtime(&pool)
        .await
        .context("runtime database boundary check failed")?;

    let mut state = AppState::new(pool, config);
    engine_api::transparency::Transparency::from_env().map_err(|e| anyhow::anyhow!(e))?;
    state.identity_key = identity_key;
    state.session_policy = session;
    state.scim_rate_per_minute = scim_rate_per_minute;
    state.fanout.mode = fanout;
    state.objects = std::sync::Arc::new(objects);
    state.reauth_seconds = reauth_seconds;
    if let Some(path) = std::env::var_os("DYNODOC_REF_SIGNING_KEY_FILE") {
        use engine_core::repository::server_authority;
        let key = server_authority::load_key(std::path::Path::new(&path))?;
        let mut authority_connection = state.pool.acquire().await?;
        // Fail closed: the mounted key must be the newest authority epoch's key.
        // A revoked epoch still starts (everything else must keep working) but
        // issues no receipt until the operator installs a recovery epoch.
        let active = server_authority::check_signer(&mut authority_connection, &key).await?;
        if let Some(marker) = &active.revocation {
            tracing::warn!(epoch = active.epoch, reason = %marker.reason, "receipt authority epoch is revoked; shared branches cannot advance");
        }
        state.ref_signer = Some(std::sync::Arc::new(key));
    }
    // At-rest envelope encryption (Phase 0, decision 041): projects with an active data key
    // store checkpoint objects as DYNOENC envelopes. Off unless a provider is named.
    if let Some(kind) = std::env::var_os("DYNODOC_AT_REST_PROVIDER") {
        use engine_core::at_rest::{kms, store};
        let kind = kind
            .into_string()
            .map_err(|_| anyhow::anyhow!("DYNODOC_AT_REST_PROVIDER"))?;
        let key_ref = std::env::var("DYNODOC_AT_REST_KEY_REF")
            .context("DYNODOC_AT_REST_KEY_REF is required with DYNODOC_AT_REST_PROVIDER")?;
        let installation: uuid::Uuid =
            sqlx::query_scalar("select id from device_authority where singleton")
                .fetch_one(&state.pool)
                .await?;
        let provider = tokio::task::spawn_blocking(move || {
            kms::provider(&kind, &key_ref, false, &|name| std::env::var(name).ok())
        })
        .await??;
        if !store::install(store::AtRest::new(installation, provider.into())) {
            anyhow::bail!("at-rest encryption configured twice");
        }
        tokio::spawn(async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                if let Some(a) = store::active() {
                    a.purge_expired();
                }
            }
        });
    }
    // Copy detection runs beside the edit path, never inside it.
    engine_api::copies::spawn(state.clone());
    // Large imports interrupted by a restart continue at their committed cursor.
    engine_api::ingest::resume(state.clone());
    // Expired sign-in rows and old metrics are pruned on one replica at a time.
    let _ = engine_api::retention::spawn(state.clone(), retention);
    // Streams on this replica also get the events other replicas write (DYNODOC_EVENT_FANOUT).
    let _ = engine_api::fanout::spawn(state.clone());
    // Objects an erasure could not delete at once are retried (decision 043).
    let _ = engine_api::object_store::spawn_sweep(state.clone());
    // Local Prometheus-text metrics on a listener of their own, only when asked for (decision 043).
    if let Some(addr) = std::env::var("DYNODOC_METRICS_ADDR")
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        let addr: SocketAddr = addr
            .trim()
            .parse()
            .context("DYNODOC_METRICS_ADDR must be an address such as 127.0.0.1:9464")?;
        engine_api::metrics::spawn(state.clone(), addr).await?;
    }

    let host = std::env::var("API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("API_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    tracing::info!(%addr, "engine-api listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // On SIGTERM or Ctrl-C: stop accepting, let in-flight requests finish, and exit after
    // SHUTDOWN_DRAIN_SECONDS at most (live event streams never end by themselves).
    let (stopping, mut stopped) = tokio::sync::watch::channel(false);
    let server = axum::serve(listener, app(state))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = stopping.send(true);
        })
        .into_future();
    let drain = async move {
        let _ = stopped.wait_for(|stop| *stop).await;
        tracing::info!(seconds = shutdown_drain_seconds, "engine-api draining");
        tokio::time::sleep(std::time::Duration::from_secs(shutdown_drain_seconds)).await;
    };
    tokio::select! {
        served = server => served?,
        () = drain => tracing::info!("drain period over; closing the remaining connections"),
    }
    Ok(())
}

/// SIGTERM (Unix) or Ctrl-C.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}
