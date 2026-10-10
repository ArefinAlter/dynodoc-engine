# Engine project status

## Latest increment: bounded checkpoint batches (10 October 2026)

Part 2c batches PostgreSQL checkpoint writes (64 objects / 1 MiB encoded) and index
reads (16 objects), retaining v1 hashes, exact-byte validation, document scope and
atomic rollback/erasure. Publishers serialize overlapping historical graphs before
object writes. Unchanged batches issue no INSERT. Complete state still resides in
memory and publication still scans it while blocking document appends.

Four controlled 8,000-block / three-checkpoint traces preserve identical paired
roots and canonical bytes. Publication falls from 14.6-20.9 s to 2.1-2.9 s; the
append-lock wait remains 2.1-2.9 s. Graph reads use 619 object SELECTs instead of
9,817. Shared relations use about 10.9 MB; compressed legacy snapshots use 0.64 MB
for repeated text and 20.78 MB for varied text. These are synthetic local traces,
not native large-file or concurrent-service acceptance. The shared writer remains
off by default. [Measurements/limits](SHARED-CHECKPOINTS.md).

Application fmt/Clippy, 224 Rust tests and unchanged OpenAPI pass. Standalone
lint, all 224 tests, docs and unchanged OpenAPI pass. Both source CI runs passed,
including 62 signed-in workflows, 16 public browser tests and 274 frontend unit
tests. Application source: `40a80be`; standalone: `c8ac6bc`. Both are pushed to main;
the disposable database/volume has been removed. [Verification/publication record](ENGINE-EVOLUTION-HANDOFF.md).
No new migration or deployment; schema 25 remains required for mixed readers.

Next: incremental/staged publication with a short final lock, bounded text/asset
chunks and compression/backend measurements, shared version/draft references,
then durable local commits and resumable exchange. Offline convergence, independent
provenance and native/scale acceptance remain open.

## Previous increment: part 2b (10 October 2026)

Normal current/history and API write readers select legacy/shared checkpoints and
stream the suffix. Shared graphs are verified; corrupt selected data fails. The
optional periodic shared writer reuses objects, with savepoint rollback and legacy
fallback on capacity errors only. Duplicate builders skip work. PostgreSQL values
use bounded batches. Named/deployed versions and draft/merge bases remain full JSON.
Schema 25 is required; events, HTTP contracts and MIT packaging remain compatible.

The writer defaults to legacy. The 8,000-block PostgreSQL spike lowered read SELECTs
9,885 -> 2,385, but shared publication took 15.3-17.4 seconds per edit and blocks
FOR UPDATE appends for much of the transaction. Compressed legacy snapshots used
less disk in the repetitive six-checkpoint fixture (2.92 MB vs shared 11.26 MB).
These figures gate rollout; canonical-byte savings alone do not justify it.
See [measurements](SHARED-CHECKPOINTS.md) and [handoff](ENGINE-EVOLUTION-HANDOFF.md).

Application's 220 tests/fmt/Clippy/OpenAPI and Rust CI passed. Standalone task lint,
all 220 tests, task docs and unchanged OpenAPI also passed. The first standalone
run hit the existing 100 ms SSE deadline; the full rerun passed unchanged.
Published source: application `12be6a2`, standalone `970d78a`. Both source CI runs
and application frontend/browser CI passed (62 signed-in, 16 public browser, 274
frontend unit tests). The handoff links the runs. The disposable database/volume
were removed; existing local services remain. No VPS deployment.

Next: batch/incremental publication and short final locking, compression/backend
measurement, bounded large text/assets, versioned draft references, then durable
local commits/exchange. Offline convergence, independent provenance, complete
native adapters and large-file/service acceptance remain separate staged work.

## Previous completed increment

Updated 10 October 2026. The engine serves document repositories around existing
editors; questionnaire validation is one supported adapter. Read [the product
contract](PRODUCT-SPEC.md), [ordered plan](ENGINE-EVOLUTION-PLAN.md),
[current handoff](ENGINE-EVOLUTION-HANDOFF.md) and
[shared checkpoint contract/benchmark](SHARED-CHECKPOINTS.md).

Part 2a is synchronized from application `7a8e28e`. It adds opt-in shared checkpoint objects covering full materialized state,
stable-key radix indexes, document-scoped memory/PostgreSQL stores and immutable
schema 25 manifests. Publication reconstructs/verifies all reachable data in the
same transaction; rollback/retry and audited erasure preserve existing boundaries.
An operator CLI opts in. Existing default JSON snapshots and draft/version bases,
event hashes, HTTP schema and MIT packaging remain compatible.

Application checks passed 216 Rust tests, fmt/Clippy and unchanged OpenAPI;
standalone task lint, 216 tests and task docs also passed (existing Rustdoc link
warnings). Both source CI runs passed; application CI also passed 62 signed-in and
16 public browser tests. Engine source is `6ccdc22`. The checksum portability fix
and final handoff follow that implementation commit. The synthetic
8,000-block/21-checkpoint trace used 7.83 MB of unique object bytes versus 135.24 MB
of full-state copies. Native files, database overhead and load are unmeasured.

SQL migration checkouts are pinned to committed LF bytes; all 22 scripts match the
application and validated against the same isolated database. No migration Git blob
was edited. All 216 engine tests passed again after restoring canonical LF checkout
bytes. Both disposable databases/volumes were removed.

Next: normal-path shared checkpoint adoption and draft/version references; bounded
large text/assets and durable backend measurements; then local commits/branches
and missing-object exchange. Complete offline convergence, signed/witnessed heads,
full native-host capture and large-file/service capacity remain unfinished. No
production deployment; the application VPS remains at its recorded schema 24.

Part 1 previously added streamed historical replay and verification, checkpoint
cadence metadata reads and dependency-counterexample tests (204 tests). The full
prior source and CI record remains in the handoff.
