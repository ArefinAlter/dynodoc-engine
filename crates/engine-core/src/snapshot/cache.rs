//! Optional write-state cache. Call only while holding the document write lock and
//! after authorizing the caller. See `docs/WRITE-STATE-CACHE.md` for invalidation,
//! PostgreSQL tuple-token assumptions and deliberate shared-storage bypass.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use super::SnapshotError;
use crate::{
    log,
    materializer::{DocumentState, Materializer},
};
use engine_shared::{DocumentId, Event};
use futures::TryStreamExt;
use serde_json::Value;
use sqlx::PgConnection;

const MAX_ENTRIES: usize = 64;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 16 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct Entry {
    seq: i64,
    chain: Vec<u8>,
    checkpoint: Option<Value>,
    tail: Vec<u8>,
    state: Arc<DocumentState>,
    bytes: usize,
    used: u64,
    born: Instant,
}

/// Diagnostics only; serialization size is a bound/proxy, not actual resident memory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub hits: u64,
    pub misses: u64,
    pub entries: usize,
    pub serialized_bytes: usize,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<DocumentId, Entry>,
    stats: Stats,
    tick: u64,
}

/// One bounded latest verified prefix per document; clones share process-local state.
/// A poisoned mutex discards its entries before reuse.
#[derive(Clone, Default)]
pub struct CurrentStateCache(Arc<Mutex<Inner>>);

#[derive(sqlx::FromRow)]
struct Point {
    head: i64,
    head_chain: Option<Vec<u8>>,
    prefix_chain: Option<Vec<u8>>,
    checkpoint: Option<Value>,
    prefix_token: Vec<u8>,
    full_token: Vec<u8>,
    cacheable: bool,
}

// These hashes detect changes to rows that the reference reader would verify.
// They are cache-coherence tokens, not attestations. Avoid transferring/parsing
// the large state/payload JSON on a hit. The selected snapshot/receipt tuple IDs
// change on SQL updates, even if a privileged writer preserves their stored hashes.
async fn point(
    db: &mut PgConnection,
    doc: DocumentId,
    prefix: Option<i64>,
) -> Result<Point, SnapshotError> {
    Ok(sqlx::query_as(
        "select coalesce(h.seq,0) as head,h.chain_hash as head_chain,b.chain_hash as prefix_chain,
          case when s.id is null then null else
            jsonb_build_array(s.id,s.through_seq,s.xmin::text,s.ctid::text,r.xmin::text,r.ctid::text)
          end as checkpoint,
          t.prefix_token,t.full_token,
          coalesce(h.seq,0)>0 and
          (s.id is null or (r.snapshot_id is not null and not(s.state ? '$dynodoc_state')))
          and not exists(select 1 from shared_checkpoint where document_id=$1 and through_seq<=h.seq) as cacheable
         from (select 1) singleton
         left join lateral(select seq,chain_hash from event where document_id=$1 order by seq desc limit 1) h on true
         left join lateral(select id,through_seq,state,xmin,ctid from snapshot
           where document_id=$1 and through_seq<=coalesce(h.seq,0) order by through_seq desc limit 1) s on true
         left join snapshot_verification r on r.snapshot_id=s.id
         left join lateral(select chain_hash from event where document_id=$1 and seq=coalesce($2,h.seq)) b on true
         left join lateral(select
           sha256(convert_to(coalesce(string_agg(e.seq::text||':'||e.xmin::text||':'||e.ctid::text,',' order by e.seq)
             filter(where e.seq<=coalesce($2,h.seq)),''),'UTF8')) as prefix_token,
           sha256(convert_to(coalesce(string_agg(e.seq::text||':'||e.xmin::text||':'||e.ctid::text,',' order by e.seq),''),'UTF8')) as full_token
           from event e where e.document_id=$1 and e.seq>coalesce(s.through_seq,0) and e.seq<=coalesce(h.seq,0)) t on true"
    ).bind(doc.0).bind(prefix).fetch_one(db).await?)
}

fn estimate(state: &DocumentState) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(data.len());
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    if serde_json::to_writer(&mut count, state).is_err() {
        usize::MAX
    } else {
        count.0
    }
}

impl CurrentStateCache {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.0.lock() {
            Ok(inner) => inner,
            Err(poisoned) => {
                let mut inner = poisoned.into_inner();
                *inner = Inner::default();
                self.0.clear_poison();
                inner
            }
        }
    }

    pub fn stats(&self) -> Stats {
        self.lock().stats
    }

    pub fn purge_document(&self, document: DocumentId) {
        let mut inner = self.lock();
        if let Some(old) = inner.entries.remove(&document) {
            inner.stats.serialized_bytes -= old.bytes;
            inner.stats.entries = inner.entries.len();
        }
    }

    fn entry(&self, doc: DocumentId) -> Option<Entry> {
        let entry = self.lock().entries.get(&doc).cloned()?;
        if entry.born.elapsed() >= MAX_AGE {
            self.purge_document(doc);
            return None;
        }
        Some(entry)
    }

    fn count(&self, doc: DocumentId, hit: bool) {
        let mut inner = self.lock();
        inner.tick = inner.tick.saturating_add(1);
        let tick = inner.tick;
        if let Some(entry) = inner.entries.get_mut(&doc) {
            entry.used = tick;
        }
        if hit {
            inner.stats.hits = inner.stats.hits.saturating_add(1);
        } else {
            inner.stats.misses = inner.stats.misses.saturating_add(1);
        }
    }

    fn insert(&self, doc: DocumentId, mut entry: Entry) {
        if entry.bytes > MAX_ENTRY_BYTES {
            self.purge_document(doc);
            return;
        }
        let mut inner = self.lock();
        if let Some(old) = inner.entries.remove(&doc) {
            inner.stats.serialized_bytes -= old.bytes;
        }
        while inner.entries.len() >= MAX_ENTRIES
            || inner.stats.serialized_bytes + entry.bytes > MAX_BYTES
        {
            let Some(oldest) = inner
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(id, _)| *id)
            else {
                break;
            };
            if let Some(old) = inner.entries.remove(&oldest) {
                inner.stats.serialized_bytes -= old.bytes;
            }
        }
        inner.tick = inner.tick.saturating_add(1);
        entry.used = inner.tick;
        inner.stats.serialized_bytes += entry.bytes;
        inner.entries.insert(doc, entry);
        inner.stats.entries = inner.entries.len();
    }

    /// Read the current state under the caller's document write lock. Never records
    /// the caller's future mutations: rollback is detected from database tokens.
    pub async fn read(
        &self,
        db: &mut PgConnection,
        doc: DocumentId,
    ) -> Result<(DocumentState, i64), SnapshotError> {
        let cached = self.entry(doc);
        let point = point(db, doc, cached.as_ref().map(|entry| entry.seq)).await?;
        if !point.cacheable {
            self.purge_document(doc);
            let result = super::read_current_state(db, doc).await?;
            self.count(doc, false);
            return Ok(result);
        }
        let reusable = cached.as_ref().filter(|entry| {
            entry.seq <= point.head
                && point.prefix_chain.as_ref() == Some(&entry.chain)
                && entry.checkpoint == point.checkpoint
                && entry.tail == point.prefix_token
        });
        let (state, seq) = if let Some(entry) = reusable {
            let mut state = (*entry.state).clone();
            let mut seq = entry.seq;
            let mut previous = entry.chain.clone();
            if seq < point.head {
                let mut tail = sqlx::query_as::<_, Event>(
                    "select * from event where document_id=$1 and seq>$2 and seq<=$3 order by seq",
                )
                .bind(doc.0)
                .bind(seq)
                .bind(point.head)
                .fetch(&mut *db);
                while let Some(event) = tail.try_next().await? {
                    log::verify_event(&event, doc, seq + 1, &previous)?;
                    Materializer::fold_into(&mut state, std::slice::from_ref(&event)).map_err(
                        |source| SnapshotError::Replay {
                            document: doc,
                            source,
                        },
                    )?;
                    seq = event.seq;
                    previous = event.chain_hash;
                }
                if seq != point.head {
                    return Err(SnapshotError::InvalidRevision(point.head));
                }
            }
            (state, seq)
        } else {
            self.purge_document(doc);
            super::read_current_state(db, doc).await?
        };
        self.count(doc, reusable.is_some());
        if reusable.is_none_or(|entry| entry.seq != seq) && seq == point.head {
            if let Some(chain) = point.head_chain {
                let bytes = estimate(&state);
                if bytes > MAX_ENTRY_BYTES {
                    self.purge_document(doc);
                    return Ok((state, seq));
                }
                self.insert(
                    doc,
                    Entry {
                        seq,
                        chain,
                        checkpoint: point.checkpoint,
                        tail: point.full_token,
                        bytes,
                        state: Arc::new(state.clone()),
                        used: 0,
                        born: Instant::now(),
                    },
                );
            }
        }
        Ok((state, seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u128) -> DocumentId {
        DocumentId(uuid::Uuid::from_u128(n))
    }
    fn entry(bytes: usize) -> Entry {
        Entry {
            seq: 1,
            chain: vec![0; 32],
            checkpoint: None,
            tail: vec![],
            state: Arc::new(DocumentState::default()),
            bytes,
            used: 0,
            born: Instant::now(),
        }
    }

    #[test]
    fn cache_pressure_evicts_least_recently_used_and_respects_bytes() {
        let cache = CurrentStateCache::default();
        for n in 1..=MAX_ENTRIES as u128 {
            cache.insert(id(n), entry(1));
        }
        cache.count(id(1), true);
        cache.insert(id(100), entry(1));
        assert!(cache.entry(id(1)).is_some());
        assert!(cache.entry(id(2)).is_none());
        assert_eq!(cache.stats().entries, MAX_ENTRIES);
        assert_eq!(cache.stats().serialized_bytes, MAX_ENTRIES);
        let cache = CurrentStateCache::default();
        for n in 1..=3 {
            cache.insert(id(n), entry(12 * 1024 * 1024));
        }
        assert_eq!(cache.stats().entries, 2);
        assert_eq!(cache.stats().serialized_bytes, 24 * 1024 * 1024);
        assert!(cache.entry(id(1)).is_none());
        cache.insert(id(4), entry(MAX_ENTRY_BYTES + 1));
        assert!(cache.entry(id(4)).is_none());
        assert_eq!(cache.stats().entries, 2);
    }

    #[test]
    fn expiry_erasure_and_poison_recovery_discard_entries() {
        let cache = CurrentStateCache::default();
        let mut expired = entry(1);
        expired.born = Instant::now()
            .checked_sub(MAX_AGE + Duration::from_secs(1))
            .unwrap();
        cache.insert(id(1), expired);
        assert!(cache.entry(id(1)).is_none());
        assert_eq!(cache.stats().serialized_bytes, 0);
        cache.insert(id(2), entry(1));
        cache.purge_document(id(2));
        assert_eq!(cache.stats().entries, 0);
        cache.insert(id(3), entry(1));
        let result = std::panic::catch_unwind(|| {
            let _guard = cache.0.lock().unwrap();
            panic!("synthetic poison");
        });
        assert!(result.is_err());
        assert_eq!(cache.stats(), Stats::default());
        assert!(cache.entry(id(3)).is_none());
        cache.insert(id(4), entry(1));
        assert!(cache.entry(id(4)).is_some());
    }
}
