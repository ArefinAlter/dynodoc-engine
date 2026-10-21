# Write-state cache: validation before reuse

Design before implementation, 21 October 2026. The existing checked checkpoint-plus-tail
reader is the reference. Measure it first with `begin_write_bench` and the synthetic
1,000/8,000-block corpus and 500-event tail. Record the build profile, environment and
limits with the results. The agent read cache is a separate facility.

The API may opt in with `DYNODOC_WRITE_STATE_CACHE=on`; the default remains the checked
reader. Each process keeps at most 64 latest document states, 32 MiB of serialized state
in total, 16 MiB per entry, with five-minute reuse eligibility. Serialization size is an estimate,
not a resident-memory guarantee. Running requests own additional state clones.

`begin_write` must first take the existing document/project locks and re-read the actor's
current role. No authorization decision is cached. Under that lock, a cached committed
prefix is reusable only when its document, sequence, chain hash, selected checkpoint and
verification receipt still match. A changed head requires verified replay of every new
event before the state can validate a write.

A head hash alone is insufficient: a privileged SQL writer can alter an earlier tail row
without changing the stored head. Cache coherence therefore also compares a SHA-256 token
of the sequence and PostgreSQL tuple versions (`xmin`, `ctid`) of every cached tail row,
and the selected inline snapshot and receipt tuple versions. Updated/deleted/reordered
rows or a changed receipt/checkpoint force the ordinary checked reader. This token is a
process-local invalidation aid, not a new audit format or signature. It relies on normal
PostgreSQL tuple semantics and a short lifetime; physical database-file rewrites and a
complete database replacement are outside this process-local cache's guarantee.

For now any applicable shared checkpoint or shared-storage snapshot bypasses the cache.
Reusing their root without validating the underlying content-addressed blocks would weaken
the checked reader. A missing/mismatching legacy receipt also falls back to that reader,
which must reject it. Old history before an attested checkpoint has the same independent
full-audit requirements as the current reader.

Populate only with a checked prefix, before applying the request's new operations. There
is no optimistic post-write advancement. Rollback, a concurrent process, deployment's
transactional snapshot, periodic snapshots and `snapshot_verification::take_in_connection`
are covered by the database tokens rather than a best-effort notification. Even if a caller
uses a cache inside a transaction it later rolls back, the next lookup must match committed
rows and cannot reuse the rolled-back point. Restarts start empty. Erasure purges the local
entry; other processes must first find and authorize the document row and cannot serve a
deleted document. Expired entries are rejected and freed on access or eviction; expiry is not a physical
memory-erasure deadline for an idle process. A poisoned cache is discarded before reuse.

Validation must compare cached reads with both the ordinary checked reader and a full
verified fold after rollback and serialized concurrent writers; exercise another cache,
checkpoint insertion and receipt removal, tail corruption, restart, bounds and shared
checkpoint bypass. A speed claim requires a measured comparison, including incremental
writes, rather than a warm no-op lookup alone. Production rollout remains an operator step.

## Baseline before implementation

The disposable Linux x86-64 PostgreSQL 16 debug-build run on 21 October measured
117.365 ms (1,000 blocks) and 821.013 ms (8,000 blocks), median of nine warm
checked-reader calls, each with a 500-event tail. Snapshot JSONB text was
1,068,086 and 9,005,124 bytes. The document lock and role lookup are excluded.
These are local debug measurements, not release or production estimates; the full
result is in `benchmarks/write-state-cache-baseline-2026-10-21.json`. The larger
fixture motivates a 16 MiB per-entry cap rather than the agent read cache's 8 MiB cap.
