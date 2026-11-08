//! Local metrics in the Prometheus text format, pull only (decisions 042 and 043, section 3 of
//! each; roadmap P2-6). One listener design for every process: `GET /metrics` and nothing else,
//! on a loopback address only (anything else is refused), for a local scraper. Nothing is ever
//! pushed and nothing leaves the host.
//!
//! - The API, when `DYNODOC_METRICS_ADDR` is set ([`spawn`]): its process counters (responses by
//!   status class and by error code, the request pool, the retention pass, the process start),
//!   then the database aggregates.
//! - Operator processes (`engine-cli transparency log-worker --metrics` and
//!   `engine-cli history-metrics`, [`serve`]): the database aggregates of the transparency log,
//!   history pruning, holds and the object collector.
//!
//! Labels come from fixed lists in code or public log metadata, never from a request: no path,
//! query, identity, project, document, person, address or secret appears in a label.
use crate::AppState;
use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use serde_json::Value;
use sqlx::PgPool;
use std::{fmt::Write as _, net::SocketAddr};

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The API's metrics router (only `GET /metrics`): process counters, then database aggregates.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(serve_api))
        .with_state(state)
}

async fn serve_api(State(state): State<AppState>) -> impl IntoResponse {
    let mut text = render_process(&state);
    text.push_str(&database_text(&state.pool).await);
    ([(header::CONTENT_TYPE, CONTENT_TYPE)], text)
}

/// The database aggregates, or a comment line when they cannot be read (logged, not served).
async fn database_text(pool: &PgPool) -> String {
    render_database(pool).await.unwrap_or_else(|error| {
        tracing::error!(%error, "metrics query failed");
        "# database metrics unavailable\n".to_string()
    })
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// One sample per line in the text exposition format, with `HELP` and `TYPE` lines.
fn family(out: &mut String, name: &str, kind: &str, help: &str, samples: &[(String, f64)]) {
    metric(out, name, kind, help);
    for (labels, value) in samples {
        let _ = writeln!(out, "{name}{labels} {value}");
    }
}

fn one(value: f64) -> Vec<(String, f64)> {
    vec![(String::new(), value)]
}

/// The API process counters (decision 043 section 3).
pub fn render_process(state: &AppState) -> String {
    let mut out = String::new();
    metric(&mut out, "dynodoc_build_info", "gauge", "The API build.");
    let _ = writeln!(
        out,
        "dynodoc_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    metric(
        &mut out,
        "dynodoc_process_start_time_seconds",
        "gauge",
        "Start of this API process, Unix seconds.",
    );
    let _ = writeln!(
        out,
        "dynodoc_process_start_time_seconds {}",
        START.get_or_init(chrono::Utc::now).timestamp()
    );
    metric(
        &mut out,
        "dynodoc_http_responses_total",
        "counter",
        "Responses by status class since start.",
    );
    for (class, n) in crate::counters::CLASSES
        .iter()
        .zip(state.counters.classes())
    {
        let _ = writeln!(out, "dynodoc_http_responses_total{{class=\"{class}\"}} {n}");
    }
    metric(
        &mut out,
        "dynodoc_http_errors_total",
        "counter",
        "Error responses by error code since start.",
    );
    if let Value::Object(codes) = state.counters.snapshot() {
        for (code, n) in codes {
            let _ = writeln!(out, "dynodoc_http_errors_total{{code=\"{code}\"}} {n}");
        }
    }
    metric(
        &mut out,
        "dynodoc_db_pool_connections",
        "gauge",
        "Open request-pool connections, by state.",
    );
    let (size, idle) = (state.pool.size(), state.pool.num_idle() as u32);
    let _ = writeln!(
        out,
        "dynodoc_db_pool_connections{{state=\"idle\"}} {idle}\ndynodoc_db_pool_connections{{state=\"busy\"}} {}",
        size.saturating_sub(idle)
    );
    let retention = state.retention.snapshot();
    metric(
        &mut out,
        "dynodoc_retention_passes_total",
        "counter",
        "Retention passes by outcome since start.",
    );
    for (outcome, key) in [
        ("ran", "runs"),
        ("skipped", "skipped_lock_held"),
        ("failed", "failures"),
    ] {
        let _ = writeln!(
            out,
            "dynodoc_retention_passes_total{{outcome=\"{outcome}\"}} {}",
            retention[key].as_u64().unwrap_or(0)
        );
    }
    metric(
        &mut out,
        "dynodoc_retention_rows_pruned_total",
        "counter",
        "Rows the retention pass removed since start, by table.",
    );
    if let Some(pruned) = retention["pruned"].as_object() {
        for (table, n) in pruned {
            let _ = writeln!(
                out,
                "dynodoc_retention_rows_pruned_total{{table=\"{table}\"}} {n}"
            );
        }
    }
    out
}
/// The installation-wide aggregates (decision 042 section 3), read from the database on each
/// scrape.
pub async fn render_database(pool: &PgPool) -> anyhow::Result<String> {
    let mut out = String::new();
    let (lag, size, age): (i64, Option<i64>, Option<f64>) = sqlx::query_as(
        "select (select count(*) from transparency_outbox o where not exists(select 1 from transparency_leaf l where l.outbox_seq=o.seq)),
                (select max(size) from transparency_checkpoint),
                (select extract(epoch from now()-max(created_at))::float8 from transparency_checkpoint)",
    )
    .fetch_one(pool)
    .await?;
    family(
        &mut out,
        "dynodoc_transparency_outbox_lag",
        "gauge",
        "Outbox rows not yet integrated into the log.",
        &one(lag as f64),
    );
    family(
        &mut out,
        "dynodoc_transparency_tree_size",
        "gauge",
        "Leaves in the latest signed checkpoint.",
        &one(size.unwrap_or(0) as f64),
    );
    family(
        &mut out,
        "dynodoc_transparency_checkpoint_age_seconds",
        "gauge",
        "Seconds since the latest checkpoint was signed (-1 before the first).",
        &one(age.unwrap_or(-1.0)),
    );
    let leaves: Vec<(String, i64)> = sqlx::query_as(
        "select o.leaf_type,count(*) from transparency_leaf l join transparency_outbox o on o.seq=l.outbox_seq group by o.leaf_type order by 1",
    )
    .fetch_all(pool)
    .await?;
    family(
        &mut out,
        "dynodoc_transparency_leaves_total",
        "counter",
        "Integrated leaves by type.",
        &leaves
            .into_iter()
            .map(|(t, n)| (format!("{{type=\"{t}\"}}"), n as f64))
            .collect::<Vec<_>>(),
    );
    // Witness key names are public log metadata (they appear on every cosigned checkpoint).
    let witnesses: Vec<(String, i64)> = sqlx::query_as(
        "select witness,max(size) from transparency_cosignature group by witness order by 1",
    )
    .fetch_all(pool)
    .await?;
    family(
        &mut out,
        "dynodoc_transparency_witness_cosigned_size",
        "gauge",
        "Largest checkpoint each witness cosigned.",
        &witnesses
            .into_iter()
            .map(|(w, n)| {
                (
                    format!("{{witness=\"{}\"}}", w.replace(['"', '\\', '\n'], "_")),
                    n as f64,
                )
            })
            .collect::<Vec<_>>(),
    );
    let (horizons, quarantined, skeleton_rows, skeleton_bytes, released_states, remaining, batches): (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "select (select count(*) from project_history_horizon),
                (select count(*) from project_history_horizon where quarantine_until>now()),
                (select count(*) from project_history_skeleton),
                (select coalesce(sum(charged_bytes),0)::bigint from project_history_skeleton),
                (select count(*) from project_history_released_state),
                (select count(*) from project_history_skeleton s join project_published_commit c on c.project_id=s.project_id and c.address=s.address),
                (select count(*) from project_history_horizon_batch)",
    )
    .fetch_one(pool)
    .await?;
    family(
        &mut out,
        "dynodoc_history_horizons",
        "gauge",
        "Shared history horizons recorded.",
        &one(horizons as f64),
    );
    family(
        &mut out,
        "dynodoc_history_horizons_quarantined",
        "gauge",
        "Horizons still in quarantine.",
        &one(quarantined as f64),
    );
    family(
        &mut out,
        "dynodoc_history_skeleton_rows",
        "gauge",
        "Skeleton rows kept for released commits.",
        &one(skeleton_rows as f64),
    );
    family(
        &mut out,
        "dynodoc_history_skeleton_bytes",
        "gauge",
        "Bytes charged for skeleton rows.",
        &one(skeleton_bytes as f64),
    );
    family(
        &mut out,
        "dynodoc_history_released_states",
        "gauge",
        "Document states released by horizons.",
        &one(released_states as f64),
    );
    family(
        &mut out,
        "dynodoc_history_unreleased_bodies",
        "gauge",
        "Released commits whose bodies a release batch has not deleted yet.",
        &one(remaining as f64),
    );
    family(
        &mut out,
        "dynodoc_history_release_batches_total",
        "counter",
        "Release batches run.",
        &one(batches as f64),
    );
    let holds: Vec<(String, i64)> = sqlx::query_as(
        "select case when legal then 'legal' when commit_address is null then 'project' else 'commit' end,count(*) from project_history_hold where released_at is null group by 1 order by 1",
    )
    .fetch_all(pool)
    .await?;
    family(
        &mut out,
        "dynodoc_history_hold_count",
        "gauge",
        "History holds in force, by kind.",
        &["commit", "legal", "project"]
            .iter()
            .map(|k| {
                let n = holds.iter().find(|(h, _)| h == k).map_or(0, |(_, n)| *n);
                (format!("{{kind=\"{k}\"}}"), n as f64)
            })
            .collect::<Vec<_>>(),
    );
    let released: i64 = sqlx::query_scalar(
        "select count(*) from project_history_hold where released_at is not null",
    )
    .fetch_one(pool)
    .await?;
    family(
        &mut out,
        "dynodoc_history_hold_released_total",
        "counter",
        "History holds released by a person.",
        &one(released as f64),
    );
    let (collections, objects): (i64, i64) = sqlx::query_as(
        "select count(*),coalesce(sum(cardinality(addresses)),0)::bigint from shared_object_collection",
    )
    .fetch_one(pool)
    .await?;
    family(
        &mut out,
        "dynodoc_object_collection_chunks_total",
        "counter",
        "Object collector chunks applied.",
        &one(collections as f64),
    );
    family(
        &mut out,
        "dynodoc_object_collected_total",
        "counter",
        "Checkpoint objects the collector deleted.",
        &one(objects as f64),
    );
    Ok(out)
}

static START: std::sync::OnceLock<chrono::DateTime<chrono::Utc>> = std::sync::OnceLock::new();

/// Bind a metrics listener. Refuses any address that is not loopback: the endpoint has no
/// authentication and is for a local scraper only.
async fn bind(addr: SocketAddr) -> anyhow::Result<tokio::net::TcpListener> {
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "metrics listen only on a loopback address (for example 127.0.0.1:9464)"
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics listening");
    Ok(listener)
}

/// Serve the API's [`router`] on `addr` in the background until the process ends. Call once at
/// start.
pub async fn spawn(state: AppState, addr: SocketAddr) -> anyhow::Result<()> {
    START.get_or_init(chrono::Utc::now);
    let listener = bind(addr).await?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router(state)).await {
            tracing::warn!(%error, "metrics listener stopped");
        }
    });
    Ok(())
}

/// Serve the database aggregates at `GET /metrics` on `addr` until the process ends (operator
/// processes, which have no API state).
pub async fn serve(pool: PgPool, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = bind(addr).await?;
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let pool = pool.clone();
            async move {
                (
                    [(header::CONTENT_TYPE, CONTENT_TYPE)],
                    database_text(&pool).await,
                )
            }
        }),
    );
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn families_follow_the_text_format() {
        let mut out = String::new();
        super::family(
            &mut out,
            "x_total",
            "counter",
            "Help.",
            &[("{a=\"b\"}".into(), 2.0)],
        );
        assert_eq!(
            out,
            "# HELP x_total Help.\n# TYPE x_total counter\nx_total{a=\"b\"} 2\n"
        );
    }
}
