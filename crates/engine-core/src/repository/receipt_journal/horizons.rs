//! Journal version 2 (docs/DESIGN-COMMIT-PRUNING.md section 7.1 and
//! docs/DESIGN-WITNESSES-AND-TRANSPARENCY.md sections 4.7 and 4.11): the remote
//! horizon chains this client accepted, and the transparency checkpoints and
//! inclusion bundles it verified. Every row is immutable. A server that later serves
//! a shorter horizon chain (rollback) or a different record at an accepted sequence
//! (fork) is refused, and so is a second root for a log size already recorded (a
//! split view).
use super::ReceiptJournal;
use crate::{
    repository::{
        horizon::{
            self,
            policy::{LoadOptions, Policy},
            Envelope, Error, Role, Scope,
        },
        Error as RepoError,
    },
    shared_checkpoint::Address,
    transparency::{self, InclusionBundle, KnownCheckpoints, Note, VerifiedCheckpoint},
};
use uuid::Uuid;

pub(super) const SCHEMA_V2: &str = "
create table if not exists horizons(authority text not null,project text not null,sequence integer not null check(sequence>=1),address text not null check(length(address)=64),body blob not null check(length(body)<=69632),policy blob not null check(length(policy)<=65536),primary key(authority,project,sequence));
create trigger if not exists horizons_no_update before update on horizons begin select raise(abort,'immutable horizon'); end;
create trigger if not exists horizons_no_delete before delete on horizons begin select raise(abort,'immutable horizon'); end;
create table if not exists checkpoints(origin text not null,size integer not null check(size>=0),root blob not null check(length(root)=32),note blob not null check(length(note)<=65536),primary key(origin,size));
create trigger if not exists checkpoints_no_update before update on checkpoints begin select raise(abort,'immutable checkpoint'); end;
create trigger if not exists checkpoints_no_delete before delete on checkpoints begin select raise(abort,'immutable checkpoint'); end;
create table if not exists inclusions(receipt text primary key check(length(receipt)=64),origin text not null,size integer not null check(size>=1),bundle blob not null check(length(bundle)<=65536));
create trigger if not exists inclusions_no_update before update on inclusions begin select raise(abort,'immutable inclusion'); end;
create trigger if not exists inclusions_no_delete before delete on inclusions begin select raise(abort,'immutable inclusion'); end;
update receipt_journal_meta set version=2 where singleton=1;
";

/// Horizons one remote chain may hold for one project.
pub const MAX_REMOTE_HORIZONS: usize = 1024;
/// A shared horizon needs the authority and at least one owner (design CP-Q2).
const SHARED_MIN_SIGNATURES: u32 = 2;

fn db(error: sqlx::Error) -> Error {
    RepoError::from(error).into()
}

/// The outcome of [`ReceiptJournal::accept_horizons`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedHorizons {
    /// Horizons this journal had accepted before the call.
    pub known: usize,
    /// Horizons accepted now, oldest first.
    pub new: Vec<Envelope>,
}

impl ReceiptJournal {
    /// Accept a remote's complete horizon chain for `project`, each envelope with the
    /// normalized policy bytes the remote served for it.
    ///
    /// Refuses unless: every policy loads with at least two required signatures and
    /// hashes to the record's reference; the chain is contiguous from 1 and every
    /// record carries that many valid distinct signatures (H1, H2, scope `Shared`);
    /// every record is signed in role `authority` by a key `trusted` accepts (the
    /// pinned receipt authority or a key its verified rotation chain leads to); and
    /// the chain extends what this journal accepted before, byte for byte. Nothing is
    /// stored unless everything verifies.
    pub async fn accept_horizons(
        &self,
        authority: Uuid,
        project: Uuid,
        chain: &[(Envelope, Vec<u8>)],
        trusted: &(dyn Fn(&str) -> bool + Sync),
    ) -> Result<AcceptedHorizons, Error> {
        if chain.len() > MAX_REMOTE_HORIZONS {
            return Err(Error::Limit("remote horizons"));
        }
        let mut policies = Vec::with_capacity(chain.len());
        for (envelope, bytes) in chain {
            let policy = Policy::load(
                bytes,
                LoadOptions {
                    min_signatures: SHARED_MIN_SIGNATURES,
                },
            )
            .map_err(|_| {
                Error::Format("a remote horizon policy does not load as a shared policy")
            })?;
            if policy.policy_ref() != envelope.horizon.policy || envelope.horizon.project != project
            {
                return Err(Error::Format(
                    "a remote horizon names another policy or project",
                ));
            }
            if !envelope
                .signatures
                .iter()
                .any(|s| s.role == Role::Authority && trusted(&s.key))
            {
                return Err(horizon::Error::Violated(
                    horizon::Invariant::H2,
                    format!(
                        "horizon {} is not signed by the pinned receipt authority",
                        envelope.horizon.sequence
                    ),
                ));
            }
            policies.push(policy);
        }
        let envelopes: Vec<Envelope> = chain.iter().map(|(e, _)| e.clone()).collect();
        horizon::validate_chain(&envelopes, Scope::Shared, |reference| {
            policies
                .iter()
                .find(|p| p.policy_ref() == *reference)
                .map(|p| p.signatures_required)
        })?;
        let mut tx = self.write().await?;
        let stored: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "select sequence,body from horizons where authority=? and project=? order by sequence",
        )
        .bind(authority.to_string())
        .bind(project.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        if stored.len() > envelopes.len() {
            return Err(Error::Plan(
                "remote horizon rollback: the remote serves fewer horizons than this journal accepted",
            ));
        }
        for ((_, body), envelope) in stored.iter().zip(&envelopes) {
            if *body != envelope.bytes()? {
                return Err(Error::Plan(
                    "remote horizon fork: a different record at a sequence this journal accepted",
                ));
            }
        }
        let known = stored.len();
        for ((envelope, _), policy) in chain.iter().zip(&policies).skip(known) {
            sqlx::query("insert into horizons(authority,project,sequence,address,body,policy) values(?,?,?,?,?,?)")
                .bind(authority.to_string())
                .bind(project.to_string())
                .bind(envelope.horizon.sequence as i64)
                .bind(envelope.horizon.address()?.as_str())
                .bind(envelope.bytes()?)
                .bind(policy.canonical_bytes())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(AcceptedHorizons {
            known,
            new: envelopes.into_iter().skip(known).collect(),
        })
    }

    /// The remote horizon chain accepted for `project`, oldest first.
    pub async fn horizons(&self, authority: Uuid, project: Uuid) -> Result<Vec<Envelope>, Error> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "select body from horizons where authority=? and project=? order by sequence",
        )
        .bind(authority.to_string())
        .bind(project.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(|b| Envelope::from_bytes(b)).collect()
    }

    /// Remember a checkpoint the caller verified at level L2 or better
    /// ([`transparency::Assessment::trusted_checkpoint`]); `note` is its signed note.
    /// A different root for a size already recorded is a split view: refused.
    pub async fn record_checkpoint(
        &self,
        verified: &VerifiedCheckpoint,
        note: &Note,
    ) -> Result<(), RepoError> {
        let checkpoint = verified.checkpoint();
        if transparency::Checkpoint::parse(note.text()).ok().as_ref() != Some(checkpoint) {
            return Err(RepoError::Invalid(
                "checkpoint note differs from the verified checkpoint",
            ));
        }
        let mut tx = self.write().await?;
        sqlx::query("insert into checkpoints(origin,size,root,note) values(?,?,?,?) on conflict(origin,size) do nothing")
            .bind(&checkpoint.origin)
            .bind(checkpoint.size as i64)
            .bind(checkpoint.root.to_vec())
            .bind(note.encode().into_bytes())
            .execute(&mut *tx)
            .await?;
        let root: Vec<u8> =
            sqlx::query_scalar("select root from checkpoints where origin=? and size=?")
                .bind(&checkpoint.origin)
                .bind(checkpoint.size as i64)
                .fetch_one(&mut *tx)
                .await?;
        if root != checkpoint.root {
            return Err(RepoError::Invalid(
                "transparency split view: this journal holds another root for that log size",
            ));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Every checkpoint recorded for `policy`'s log, verified again under `policy`,
    /// as the set [`transparency::assess`] compares a new checkpoint with.
    pub async fn known_checkpoints(
        &self,
        policy: &transparency::Policy,
    ) -> Result<KnownCheckpoints, RepoError> {
        let notes: Vec<Vec<u8>> =
            sqlx::query_scalar("select note from checkpoints where origin=? order by size")
                .bind(policy.origin().as_str())
                .fetch_all(&self.pool)
                .await?;
        let mut known = KnownCheckpoints::new(policy.origin());
        for note in notes {
            let note =
                Note::parse(&note).map_err(|_| RepoError::Invalid("stored checkpoint note"))?;
            let verified = policy.verify_checkpoint(&note).map_err(|_| {
                RepoError::Invalid("stored checkpoint no longer verifies under this policy")
            })?;
            known
                .record(&verified)
                .map_err(|_| RepoError::Invalid("stored checkpoints disagree"))?;
        }
        Ok(known)
    }

    /// The newest recorded checkpoint note of `origin`.
    pub async fn latest_checkpoint(&self, origin: &str) -> Result<Option<Note>, RepoError> {
        let note: Option<Vec<u8>> = sqlx::query_scalar(
            "select note from checkpoints where origin=? order by size desc limit 1",
        )
        .bind(origin)
        .fetch_optional(&self.pool)
        .await?;
        note.map(|n| Note::parse(&n).map_err(|_| RepoError::Invalid("stored checkpoint note")))
            .transpose()
    }

    /// Keep the inclusion bundle that placed `receipt` in the log.
    pub async fn record_inclusion(
        &self,
        receipt: &Address,
        origin: &str,
        bundle: &InclusionBundle,
    ) -> Result<(), RepoError> {
        let bytes = bundle.to_json();
        let mut tx = self.write().await?;
        sqlx::query("insert into inclusions(receipt,origin,size,bundle) values(?,?,?,?) on conflict(receipt) do nothing")
            .bind(receipt.as_str())
            .bind(origin)
            .bind(bundle.size as i64)
            .bind(&bytes)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::horizon::{
        Counts, HorizonRecord, PolicyRef, Roots, Tier, RECORD_KIND, RECORD_VERSION,
    };
    use ring::signature::Ed25519KeyPair;

    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn policy() -> (Policy, Vec<u8>) {
        let policy = Policy::load(
            br#"{"version":1,"id":"team","tier":"history","window":{"keep_last_commits":5},"protect":{"branch_heads":true},"signatures":{"required":2}}"#,
            LoadOptions { min_signatures: 2 },
        )
        .unwrap();
        let bytes = policy.canonical_bytes();
        (policy, bytes)
    }

    fn record(
        project: Uuid,
        sequence: u64,
        previous: Option<Address>,
        policy: PolicyRef,
        salt: u8,
    ) -> HorizonRecord {
        let digest = |tag: u8| horizon::address_of(&[tag; 32]);
        HorizonRecord {
            version: RECORD_VERSION,
            kind: RECORD_KIND.into(),
            project,
            sequence,
            previous,
            created_at_ms: 1_791_000_000_000 + u64::from(salt),
            tier: Tier::History,
            policy,
            heads_digest: digest(salt),
            counts: Counts::default(),
            roots: Roots {
                skeleton: digest(1),
                frontier: digest(2),
                released_states: digest(3),
            },
            archive: None,
            holds: vec![],
            evidence: vec![],
        }
    }

    fn envelope(record: HorizonRecord, authority: &Ed25519KeyPair) -> Envelope {
        let signatures = vec![
            horizon::sign(&record, Role::Authority, authority).unwrap(),
            horizon::sign(&record, Role::Owner, &key(9)).unwrap(),
        ];
        Envelope::assemble(record, signatures).unwrap()
    }

    #[tokio::test]
    async fn horizon_chains_are_pinned_and_rollback_fork_and_foreign_signers_refused() {
        let path =
            std::env::temp_dir().join(format!("dynodoc-journal-v2-{}.sqlite", Uuid::new_v4()));
        let journal = ReceiptJournal::open(&path).await.unwrap();
        let (authority, project) = (Uuid::new_v4(), Uuid::new_v4());
        let (policy, bytes) = policy();
        let pinned = key(1);
        let pinned_hex =
            crate::repository::hex(ring::signature::KeyPair::public_key(&pinned).as_ref());
        let trusted = move |k: &str| k == pinned_hex;
        let first = envelope(record(project, 1, None, policy.policy_ref(), 1), &pinned);
        let second = envelope(
            record(
                project,
                2,
                Some(first.horizon.address().unwrap()),
                policy.policy_ref(),
                2,
            ),
            &pinned,
        );
        let accepted = journal
            .accept_horizons(
                authority,
                project,
                &[(first.clone(), bytes.clone())],
                &trusted,
            )
            .await
            .unwrap();
        assert_eq!((accepted.known, accepted.new.len()), (0, 1));
        let accepted = journal
            .accept_horizons(
                authority,
                project,
                &[
                    (first.clone(), bytes.clone()),
                    (second.clone(), bytes.clone()),
                ],
                &trusted,
            )
            .await
            .unwrap();
        assert_eq!((accepted.known, accepted.new.len()), (1, 1));
        // Rollback: the remote now serves only the first.
        assert!(matches!(
            journal
                .accept_horizons(authority, project, &[(first.clone(), bytes.clone())], &trusted)
                .await,
            Err(Error::Plan(m)) if m.contains("rollback")
        ));
        // Fork: a different, validly signed record at sequence 2.
        let forked = envelope(
            record(
                project,
                2,
                Some(first.horizon.address().unwrap()),
                policy.policy_ref(),
                7,
            ),
            &pinned,
        );
        assert!(matches!(
            journal
                .accept_horizons(
                    authority,
                    project,
                    &[(first.clone(), bytes.clone()), (forked, bytes.clone())],
                    &trusted,
                )
                .await,
            Err(Error::Plan(m)) if m.contains("fork")
        ));
        // A chain signed by another "authority" key is refused before anything is read.
        let other = envelope(
            record(Uuid::new_v4(), 1, None, policy.policy_ref(), 1),
            &key(2),
        );
        assert!(journal
            .accept_horizons(
                authority,
                other.horizon.project,
                &[(other, bytes.clone())],
                &trusted
            )
            .await
            .is_err());
        // A one-signature shared policy is below the floor.
        let weak = Policy::load(
            br#"{"version":1,"id":"weak","tier":"history","window":{"keep_last_commits":5},"protect":{"branch_heads":true}}"#,
            LoadOptions::default(),
        )
        .unwrap();
        let lone = envelope(
            record(Uuid::new_v4(), 1, None, weak.policy_ref(), 1),
            &pinned,
        );
        assert!(journal
            .accept_horizons(
                authority,
                lone.horizon.project,
                &[(lone, weak.canonical_bytes())],
                &trusted
            )
            .await
            .is_err());
        assert_eq!(
            journal.horizons(authority, project).await.unwrap(),
            vec![first, second]
        );
        journal.close().await;
        let _ = std::fs::remove_file(&path);
    }
}
