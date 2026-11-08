//! The witness side of C2SP `tlog-witness` (design sections 4.2 and 4.9, phase W3,
//! decision 032).
//!
//! An `add-checkpoint` request body is the line `old <size>`, up to 63 consistency
//! proof hashes in base64 one per line, a blank line, and the signed checkpoint note.
//! A witness cosigns only a checkpoint signed by a log it is configured for whose tree
//! extends the one it last cosigned for that origin, and it checks and stores the new
//! state in one transaction so two racing submissions can never roll it back. Answers:
//! 200 with the cosignature line, 400 malformed or smaller, 403 no trusted log
//! signature, 404 unknown origin, 409 with the witness's size when `old` differs, 422
//! when the proof does not connect the roots. (Editor's copy of the protocol; the
//! exact text is unverified, see the module documentation of `transparency`.)
use super::{
    encoding::{b64, unb64},
    merkle::{empty_root, verify_consistency, Hash},
    note::{Checkpoint, KeyKind, Note, NoteSignature, Signer, VerifierKey},
    Error,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::{path::Path, time::Duration};

pub const MAX_PROOF_HASHES: usize = 63;
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// One `add-checkpoint` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddCheckpoint {
    pub old_size: u64,
    pub proof: Vec<Hash>,
    pub note: Note,
}

/// Why a witness did not cosign; [`Refusal::status`] is the HTTP answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("malformed add-checkpoint request: {0}")]
    Malformed(&'static str),
    #[error("this witness is not configured for that log")]
    UnknownLog,
    #[error("no trusted log signature on the checkpoint")]
    Untrusted,
    #[error("the witness last cosigned size {size}")]
    Conflict { size: u64 },
    #[error("the checkpoint is smaller than the one the witness cosigned")]
    Smaller,
    #[error("the consistency proof does not connect the witnessed tree to the new one")]
    Inconsistent,
    #[error("witness state: {0}")]
    Storage(String),
}

impl Refusal {
    pub fn status(&self) -> u16 {
        match self {
            Self::Malformed(_) | Self::Smaller => 400,
            Self::Untrusted => 403,
            Self::UnknownLog => 404,
            Self::Conflict { .. } => 409,
            Self::Inconsistent => 422,
            Self::Storage(_) => 500,
        }
    }
}

impl AddCheckpoint {
    pub fn encode(&self) -> String {
        let mut out = format!("old {}\n", self.old_size);
        for hash in &self.proof {
            out.push_str(&b64(hash));
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&self.note.encode());
        out
    }

    pub fn parse(body: &[u8]) -> Result<Self, Refusal> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(Refusal::Malformed("request too large"));
        }
        let text = std::str::from_utf8(body).map_err(|_| Refusal::Malformed("not UTF-8"))?;
        let (head, note) = text
            .split_once("\n\n")
            .ok_or(Refusal::Malformed("no blank line before the checkpoint"))?;
        let mut lines = head.split('\n');
        let old = lines
            .next()
            .and_then(|l| l.strip_prefix("old "))
            .ok_or(Refusal::Malformed("first line must be `old <size>`"))?;
        if old.is_empty() || (old.len() > 1 && old.starts_with('0')) {
            return Err(Refusal::Malformed("size"));
        }
        let old_size = old.parse().map_err(|_| Refusal::Malformed("size"))?;
        let mut proof = Vec::new();
        for line in lines {
            let hash: Hash = unb64(line)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or(Refusal::Malformed("proof hash"))?;
            proof.push(hash);
        }
        if proof.len() > MAX_PROOF_HASHES {
            return Err(Refusal::Malformed("too many proof hashes"));
        }
        let note =
            Note::parse(note.as_bytes()).map_err(|_| Refusal::Malformed("checkpoint note"))?;
        Ok(Self {
            old_size,
            proof,
            note,
        })
    }
}

/// A witness: its cosigning key and the logs (origin = key name) it witnesses.
pub struct Witness {
    signer: Signer,
    logs: Vec<VerifierKey>,
}

impl Witness {
    pub fn new(signer: Signer, logs: Vec<VerifierKey>) -> Result<Self, Error> {
        if signer.verifier_key().kind() != KeyKind::Cosigner
            || logs.iter().any(|k| k.kind() != KeyKind::Log)
        {
            return Err(Error::WrongSignerKind);
        }
        Ok(Self { signer, logs })
    }

    pub fn verifier_key(&self) -> VerifierKey {
        self.signer.verifier_key()
    }

    /// The decision for one request against the witnessed state of its origin
    /// (`None` before the first cosignature). Pure: the caller stores the result in
    /// the same transaction it read `current` in.
    pub fn decide(
        &self,
        current: Option<(u64, Hash)>,
        request: &AddCheckpoint,
        now: u64,
    ) -> Result<(Checkpoint, NoteSignature), Refusal> {
        let checkpoint =
            Checkpoint::parse(request.note.text()).map_err(|_| Refusal::Malformed("checkpoint"))?;
        let key = self
            .logs
            .iter()
            .find(|k| k.name() == checkpoint.origin)
            .ok_or(Refusal::UnknownLog)?;
        if !matches!(request.note.verify(key), Ok(Some(_))) {
            return Err(Refusal::Untrusted);
        }
        let (size, root) = current.unwrap_or((0, empty_root()));
        if request.old_size != size {
            return Err(Refusal::Conflict { size });
        }
        if checkpoint.size < size {
            return Err(Refusal::Smaller);
        }
        let consistent = if checkpoint.size == size {
            checkpoint.root == root && request.proof.is_empty()
        } else if size == 0 {
            request.proof.is_empty()
        } else {
            verify_consistency(
                size,
                checkpoint.size,
                &root,
                &checkpoint.root,
                &request.proof,
            )
            .is_ok()
        };
        if !consistent {
            return Err(Refusal::Inconsistent);
        }
        let line = self
            .signer
            .cosign_checkpoint(request.note.text(), now)
            .map_err(|_| Refusal::Malformed("checkpoint"))?;
        Ok((checkpoint, line))
    }
}

/// The witness's durable state: one row per origin with the size and root it last
/// cosigned and that cosigned note (served for monitoring). Losing or restoring an
/// old copy of this file is a security event (design T5).
#[derive(Clone)]
pub struct WitnessState {
    pool: SqlitePool,
}

fn storage(error: sqlx::Error) -> Refusal {
    Refusal::Storage(error.to_string())
}

impl WitnessState {
    pub async fn open(path: &Path) -> Result<Self, Refusal> {
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(path)
                    .create_if_missing(true)
                    .journal_mode(SqliteJournalMode::Wal)
                    .synchronous(SqliteSynchronous::Full)
                    .busy_timeout(Duration::from_secs(5)),
            )
            .await
            .map_err(storage)?;
        sqlx::raw_sql("create table if not exists witness_state(origin text primary key,size integer not null check(size>=0),root blob not null check(length(root)=32),note text not null,updated_ms integer not null)")
            .execute(&pool)
            .await
            .map_err(storage)?;
        Ok(Self { pool })
    }

    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Check and persist atomically; returns the cosignature line to answer with.
    pub async fn add_checkpoint(
        &self,
        witness: &Witness,
        request: &AddCheckpoint,
        now: u64,
    ) -> Result<String, Refusal> {
        let origin = Checkpoint::parse(request.note.text())
            .map_err(|_| Refusal::Malformed("checkpoint"))?
            .origin;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        let row: Option<(i64, Vec<u8>)> =
            sqlx::query_as("select size,root from witness_state where origin=?")
                .bind(&origin)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        let current = row
            .map(|(size, root)| {
                Ok::<_, Refusal>((
                    u64::try_from(size).map_err(|_| Refusal::Storage("size".into()))?,
                    root.try_into()
                        .map_err(|_| Refusal::Storage("root".into()))?,
                ))
            })
            .transpose()?;
        let (checkpoint, line) = witness.decide(current, request, now)?;
        let cosigned = request
            .note
            .clone()
            .with_signature(line.clone())
            .map_err(|_| Refusal::Malformed("the note already carries this witness's line"))?;
        sqlx::query("insert into witness_state(origin,size,root,note,updated_ms) values(?,?,?,?,?) on conflict(origin) do update set size=excluded.size,root=excluded.root,note=excluded.note,updated_ms=excluded.updated_ms")
            .bind(&origin)
            .bind(checkpoint.size as i64)
            .bind(checkpoint.root.to_vec())
            .bind(cosigned.encode())
            .bind((now as i64).saturating_mul(1000))
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)?;
        Ok(line.encode())
    }

    /// The checkpoint this witness last cosigned for `origin`, with its line.
    pub async fn latest(&self, origin: &str) -> Result<Option<String>, Refusal> {
        sqlx::query_scalar("select note from witness_state where origin=?")
            .bind(origin)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)
    }

    /// The size this witness last cosigned for `origin`.
    pub async fn size(&self, origin: &str) -> Result<u64, Refusal> {
        let size: Option<i64> = sqlx::query_scalar("select size from witness_state where origin=?")
            .bind(origin)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?;
        Ok(size.map_or(0, |s| s as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparency::{leaf::Leaf, log::Log, tiles::MemoryTileStore, Origin};

    const ORIGIN: &str = "log.example/dynodoc/v1/transparency";

    fn log_signer() -> Signer {
        Signer::from_seed(ORIGIN, KeyKind::Log, &[1; 32]).unwrap()
    }

    fn witness() -> Witness {
        Witness::new(
            Signer::from_seed("witness.example/w1", KeyKind::Cosigner, &[2; 32]).unwrap(),
            vec![log_signer().verifier_key()],
        )
        .unwrap()
    }

    fn leaf(i: u8) -> Leaf {
        Leaf::EventHeads {
            root: [i; 32],
            count: 1,
            interval: u64::from(i),
        }
    }

    fn log(n: u8) -> Log<MemoryTileStore> {
        let mut log = Log::open(Origin::new(ORIGIN).unwrap(), MemoryTileStore::new()).unwrap();
        for i in 0..n {
            log.append(&leaf(i)).unwrap();
        }
        log
    }

    fn request(log: &Log<MemoryTileStore>, old: u64) -> AddCheckpoint {
        AddCheckpoint {
            old_size: old,
            proof: if old == 0 {
                vec![]
            } else {
                log.consistency_proof(old, log.size()).unwrap()
            },
            note: log.signed_checkpoint(&log_signer()).unwrap(),
        }
    }

    async fn state() -> (WitnessState, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("dynodoc-witness-{}.sqlite", uuid::Uuid::new_v4()));
        (WitnessState::open(&path).await.unwrap(), path)
    }

    #[test]
    fn requests_round_trip_and_malformed_ones_are_refused() {
        let log = log(5);
        let req = request(&log, 3);
        assert_eq!(AddCheckpoint::parse(req.encode().as_bytes()).unwrap(), req);
        for bad in ["old 03\n\nx", "new 3\n\n", "old 3\nnot-base64\n\n"] {
            assert!(matches!(
                AddCheckpoint::parse(bad.as_bytes()),
                Err(Refusal::Malformed(_))
            ));
        }
    }

    #[tokio::test]
    async fn cosigns_only_consistent_extensions_signed_by_the_trusted_log() {
        let (state, path) = state().await;
        let w = witness();
        // First checkpoint, then a consistent extension: both cosigned, and the
        // cosignature verifies under the witness's key.
        let small = log(3);
        state
            .add_checkpoint(&w, &request(&small, 0), 100)
            .await
            .unwrap();
        let big = log(9);
        let line = state
            .add_checkpoint(&w, &request(&big, 3), 101)
            .await
            .unwrap();
        let cosigned =
            Note::parse(state.latest(ORIGIN).await.unwrap().unwrap().as_bytes()).unwrap();
        assert_eq!(
            cosigned.verify(&w.verifier_key()).unwrap().unwrap().time,
            Some(101)
        );
        assert!(line.starts_with("\u{2014} witness.example/w1 "));
        // Stale `old`: 409 with the witnessed size.
        assert_eq!(
            state.add_checkpoint(&w, &request(&log(12), 3), 102).await,
            Err(Refusal::Conflict { size: 9 })
        );
        // A forked log: same origin and key, different leaves; the proof from 9 fails.
        let mut fork = Log::open(Origin::new(ORIGIN).unwrap(), MemoryTileStore::new()).unwrap();
        for i in 0..12u8 {
            fork.append(&leaf(if i == 4 { 200 } else { i })).unwrap();
        }
        assert_eq!(
            state.add_checkpoint(&w, &request(&fork, 9), 103).await,
            Err(Refusal::Inconsistent)
        );
        // A tampered proof for an honest extension is refused too.
        let honest = log(12);
        let mut tampered = request(&honest, 9);
        tampered.proof[0][0] ^= 1;
        assert_eq!(
            state.add_checkpoint(&w, &tampered, 104).await,
            Err(Refusal::Inconsistent)
        );
        // Truncation: a smaller tree.
        let short = log(5);
        let truncated = AddCheckpoint {
            old_size: 9,
            proof: vec![],
            note: short.signed_checkpoint(&log_signer()).unwrap(),
        };
        assert_eq!(
            state.add_checkpoint(&w, &truncated, 105).await,
            Err(Refusal::Smaller)
        );
        // Same size, different root (a rewrite).
        let mut rewrite = Log::open(Origin::new(ORIGIN).unwrap(), MemoryTileStore::new()).unwrap();
        for i in 0..9u8 {
            rewrite.append(&leaf(i + 50)).unwrap();
        }
        let mut same = request(&rewrite, 9);
        same.proof.clear();
        assert_eq!(
            state.add_checkpoint(&w, &same, 106).await,
            Err(Refusal::Inconsistent)
        );
        // Signed by another key under the same origin name: 403; unknown origin: 404.
        let impostor = Signer::from_seed(ORIGIN, KeyKind::Log, &[9; 32]).unwrap();
        let mut forged = request(&honest, 9);
        forged.note = honest.signed_checkpoint(&impostor).unwrap();
        assert_eq!(
            state.add_checkpoint(&w, &forged, 107).await,
            Err(Refusal::Untrusted)
        );
        let other = Signer::from_seed(
            "other.example/dynodoc/v1/transparency",
            KeyKind::Log,
            &[3; 32],
        )
        .unwrap();
        let mut elsewhere = Log::open(
            Origin::new("other.example/dynodoc/v1/transparency").unwrap(),
            MemoryTileStore::new(),
        )
        .unwrap();
        elsewhere.append(&leaf(1)).unwrap();
        let unknown = AddCheckpoint {
            old_size: 0,
            proof: vec![],
            note: elsewhere.signed_checkpoint(&other).unwrap(),
        };
        assert_eq!(
            state.add_checkpoint(&w, &unknown, 108).await,
            Err(Refusal::UnknownLog)
        );
        // State unchanged by every refusal; the honest extension still goes through.
        assert_eq!(state.size(ORIGIN).await.unwrap(), 9);
        state
            .add_checkpoint(&w, &request(&honest, 9), 109)
            .await
            .unwrap();
        assert_eq!(state.size(ORIGIN).await.unwrap(), 12);
        state.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn concurrent_submissions_never_roll_the_state_back() {
        let (state, path) = state().await;
        let w = std::sync::Arc::new(witness());
        state
            .add_checkpoint(&w, &request(&log(4), 0), 1)
            .await
            .unwrap();
        let mut tasks = Vec::new();
        for n in [6u8, 8, 10] {
            let (state, w) = (state.clone(), w.clone());
            tasks.push(tokio::spawn(async move {
                state.add_checkpoint(&w, &request(&log(n), 4), 2).await
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                winners += 1;
            }
        }
        // Each request claims old=4: exactly one wins, the others see 409.
        assert_eq!(winners, 1);
        assert!(state.size(ORIGIN).await.unwrap() > 4);
        state.close().await;
        let _ = std::fs::remove_file(&path);
    }
}
