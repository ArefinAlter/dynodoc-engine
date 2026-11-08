//! Live event fan-out across API replicas (docs/SELF-HOSTED-EDITION.md 6.2, decision 037).
//!
//! `DYNODOC_EVENT_FANOUT`:
//!
//! - `local` (the default): a stream sees the events written through its own process, as before.
//! - `postgres`: one dedicated connection (its own pool of one, never the request pool) listens on
//!   `dynodoc_event` (migration 0112, `<document>:<first>:<last>` per inserting statement). For a
//!   document with live streams here, the range is read from `event` and sent through the
//!   document's channel ([`crate::stream::Subscriptions`]). After the listener reconnects, every
//!   live document catches up from the last sequence sent to the current head (notifications sent
//!   while disconnected are not queued). Readiness fails while it is disconnected.
//! - `poll`: every 500 ms, the head of each document with live streams is read and the new range
//!   sent. Higher latency; no LISTEN (for a transaction-mode pooler in front of PostgreSQL).
//!
//! Events are always read from storage, so the payload carries no content; a channel sends only
//! the event that follows the last one it sent, so duplicates (the local fast path and the
//! notification of the same write) are sent once.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use engine_shared::DocumentId;
use sqlx::postgres::{PgListener, PgPoolOptions};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{stream::CatchUp, AppState};

/// Notification channel of migration 0112.
pub const CHANNEL: &str = "dynodoc_event";
/// Notifications for one document arriving this close together are read as one range.
const COALESCE: Duration = Duration::from_millis(20);
/// Head polling interval in `poll` mode.
const POLL: Duration = Duration::from_millis(500);
/// Rows read per query while sending a range.
const PAGE: i64 = 100;

/// How events reach streams on other replicas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Local,
    Postgres,
    Poll,
}

impl Mode {
    /// Parse `DYNODOC_EVENT_FANOUT` (`None`: not a known mode).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "local" => Some(Self::Local),
            "postgres" => Some(Self::Postgres),
            "poll" => Some(Self::Poll),
            _ => None,
        }
    }
}

/// The fan-out mode and, in `postgres` mode, whether the listener is connected (readiness).
#[derive(Clone, Debug, Default)]
pub struct Fanout {
    pub mode: Mode,
    pub connected: Arc<AtomicBool>,
}

impl Fanout {
    /// Whether this replica can deliver other replicas' events now.
    pub fn ready(&self) -> bool {
        self.mode != Mode::Postgres || self.connected.load(Ordering::Acquire)
    }
}

/// Start fan-out for `state.fanout.mode` (nothing in `local` mode). The listener's connection is
/// made from the request pool's connect options (the same runtime login).
pub fn spawn(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    if state.fanout.mode == Mode::Local {
        return None;
    }
    let (queue, ranges) = mpsc::unbounded_channel();
    if !state.subscriptions.share(queue.clone()) {
        return None;
    }
    tokio::spawn(deliver(state.clone(), ranges));
    Some(match state.fanout.mode {
        Mode::Postgres => tokio::spawn(listen(state, queue)),
        _ => tokio::spawn(poll(state, queue)),
    })
}

/// Queue a catch-up for every document with live streams: from the last sequence sent to its
/// head. Documents whose position is not known yet are left to their next event.
async fn catch_up(state: &AppState, queue: &mpsc::UnboundedSender<CatchUp>) {
    let live: Vec<(Uuid, i64)> = state
        .subscriptions
        .live()
        .into_iter()
        .filter_map(|(d, seen)| seen.map(|s| (d, s)))
        .collect();
    if live.is_empty() {
        return;
    }
    let ids: Vec<Uuid> = live.iter().map(|(d, _)| *d).collect();
    let heads: Vec<(Uuid, i64)> = match sqlx::query_as(
        "select document_id,max(seq) from event where document_id=any($1) group by document_id",
    )
    .bind(&ids)
    .fetch_all(&state.pool)
    .await
    {
        Ok(heads) => heads,
        Err(error) => {
            tracing::warn!(%error, "event fan-out: head read failed");
            return;
        }
    };
    for (document, head) in heads {
        if let Some((_, seen)) = live.iter().find(|(d, _)| *d == document) {
            if head > *seen {
                let _ = queue.send(CatchUp {
                    document,
                    from: seen + 1,
                    to: head,
                });
            }
        }
    }
}

/// `postgres` mode: listen, reconnect, catch up after every (re)connection.
async fn listen(state: AppState, queue: mpsc::UnboundedSender<CatchUp>) {
    let options = state.pool.connect_options().as_ref().clone();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_lazy_with(options);
    loop {
        let mut listener = match PgListener::connect_with(&pool).await {
            Ok(listener) => listener,
            Err(error) => {
                state.fanout.connected.store(false, Ordering::Release);
                tracing::warn!(%error, "event fan-out: listener connection failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if let Err(error) = listener.listen(CHANNEL).await {
            tracing::warn!(%error, "event fan-out: LISTEN failed");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        state.fanout.connected.store(true, Ordering::Release);
        tracing::info!("event fan-out: listening");
        catch_up(&state, &queue).await;
        loop {
            match listener.try_recv().await {
                Ok(Some(notification)) => {
                    if let Some(range) = parse(notification.payload()) {
                        if state.subscriptions.is_live(range.document) {
                            let _ = queue.send(range);
                        }
                    }
                }
                // The connection was lost and made again (LISTEN renewed): what was sent in
                // between is not queued for this session, so read it.
                Ok(None) => catch_up(&state, &queue).await,
                Err(error) => {
                    state.fanout.connected.store(false, Ordering::Release);
                    tracing::warn!(%error, "event fan-out: listener lost");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    break;
                }
            }
        }
    }
}

/// `poll` mode: catch up every [`POLL`].
async fn poll(state: AppState, queue: mpsc::UnboundedSender<CatchUp>) {
    loop {
        tokio::time::sleep(POLL).await;
        catch_up(&state, &queue).await;
    }
}

/// Read the queued ranges (coalesced per document) and send them in order.
async fn deliver(state: AppState, mut ranges: mpsc::UnboundedReceiver<CatchUp>) {
    while let Some(first) = ranges.recv().await {
        let mut wanted: HashMap<Uuid, (i64, i64)> = HashMap::new();
        let mut add = |r: CatchUp| {
            let entry = wanted.entry(r.document).or_insert((r.from, r.to));
            *entry = (entry.0.min(r.from), entry.1.max(r.to));
        };
        add(first);
        let until = tokio::time::Instant::now() + COALESCE;
        while let Ok(Some(more)) = tokio::time::timeout_at(until, ranges.recv()).await {
            add(more);
        }
        for (document, (from, to)) in wanted {
            // Start right after what this channel already sent, whatever the range said.
            let mut next = state
                .subscriptions
                .seen(document)
                .map_or(from, |seen| seen + 1);
            while next <= to {
                let page = match engine_core::log::read_range_page(
                    &state.pool,
                    DocumentId(document),
                    next,
                    to,
                    PAGE,
                )
                .await
                {
                    Ok(page) if !page.is_empty() => page,
                    Ok(_) => break,
                    Err(error) => {
                        tracing::warn!(%error, "event fan-out: range read failed");
                        break;
                    }
                };
                let last = page.last().map_or(to, |e| e.seq);
                match state.subscriptions.deliver(document, page) {
                    Some(sent) if sent >= last => next = sent + 1,
                    // Nobody listens any more, or a gap in storage: the streams resume from storage.
                    _ => break,
                }
            }
        }
    }
}

/// `<uuid>:<first>:<last>`, first <= last, both positive.
fn parse(payload: &str) -> Option<CatchUp> {
    let mut parts = payload.split(':');
    let document = Uuid::parse_str(parts.next()?).ok()?;
    let from: i64 = parts.next()?.parse().ok()?;
    let to: i64 = parts.next()?.parse().ok()?;
    (parts.next().is_none() && 0 < from && from <= to).then_some(CatchUp { document, from, to })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_and_modes_parse_strictly() {
        let id = Uuid::new_v4();
        assert_eq!(
            parse(&format!("{id}:3:5")),
            Some(CatchUp {
                document: id,
                from: 3,
                to: 5
            })
        );
        for bad in [
            format!("{id}:5:3"),
            format!("{id}:0:1"),
            format!("{id}:1"),
            format!("{id}:1:2:3"),
            "nope:1:2".into(),
            format!("{id}:a:2"),
        ] {
            assert_eq!(parse(&bad), None, "{bad}");
        }
        assert_eq!(Mode::parse("postgres"), Some(Mode::Postgres));
        assert_eq!(Mode::parse("redis"), None);
        let fanout = Fanout {
            mode: Mode::Postgres,
            ..Default::default()
        };
        assert!(!fanout.ready());
        fanout.connected.store(true, Ordering::Release);
        assert!(fanout.ready());
        assert!(Fanout::default().ready());
    }
}
