# Engine project status

## Hosted deployment verified (10 October 2026)

The application now runs source `536a448` (implementation `0478bf2`) on the VPS,
schema 25, with matching history and six-editor pairing/install clients. This
standalone repository's engine source remains `a44b8ad`; no new algorithm, Rust,
event encoding or object codec change was needed for rollout.

All 22 read-only delivery/auth checks and clean-browser installation/login navigation
passed. Synthetic Workspace/Projects shells pass through public Nginx. Existing
data fingerprints and unrelated services were preserved. Upgrade and compatible
rollback API startup passed on an isolated empty database; temporary containers and
network are removed. Shared checkpoint writes remain disabled. The documentation
head `7bfd16c` also passed full engine CI before release.

See [the deployment handoff](ENGINE-EVOLUTION-HANDOFF.md) and the application
[release record](https://github.com/ArefinAlter/dynodoc/blob/main/docs/operations/2026-10-10-history-connector-release.md).
Installed Microsoft/Google host acceptance, actual production sign-in and marketplace
publication remain open. The next independent engine increment is bounded text/assets,
compression/incremental publication and shared version/draft references in part 2,
before portable commits/branches and resumable exchange.

## Latest increment: history ranges and editor pairing (10 October 2026)

Synchronized the new API range operations, overlap resolution/private recovery,
and hash-only browser approval/scoped connection completion from the application.
No migrations or event/codec changes. Existing storage limitations remain unchanged.
Standalone task lint, all 231 Rust tests, docs and OpenAPI pass.
Final source commits application 0478bf2 and engine a44b8ad are published.
All final source CI gates pass: 231 Rust tests per repository, 280 frontend unit
tests and 16 public / 66 authenticated-stack browser tests. Both owned disposable
databases and API/web test servers are removed/stopped. See the handoff for links.
Application native export UI and all six test packages/auth clients are maintained
in ArefinAlter/dynodoc. This repository contains their API contract, not the clients.

Next priorities: matching API/web test deployment and installed-host acceptance;
bounded text/assets and shared version/draft references, then portable commits,
parents/branches, resumable exchange and offline convergence. The later VPS rollout
is recorded above.

## Previous increment: permission-controlled historical recovery (10 October 2026)

The product now explicitly includes retrieving old or unnamed revisions and
recovering selected content through current role/approval rules. The implementation
adds a checked preview and private recovery draft using any retained event revision,
with source hash/sequence, idempotent retry and the existing review/merge path.
The web Version history panel offers checkpoint download and block selection;
Activity links to the state before an edit. Canonical history is never rewound.

Application fmt/Clippy and 229 Rust tests pass, followed by the five review tests
after the source-label guard. Frontend lint, 274 unit tests, production build and
the new signed-in recovery workflow pass. API schemas are regenerated. Standalone
source is synchronized and lint, all 229 tests, docs and OpenAPI pass. Application
source d83bf86 and engine source fdba931 are pushed to main. Both source CI runs
passed, including 274 frontend unit tests, 16 public browser tests and 63 signed-in
workflows. The owned disposable database and API/web servers are removed/stopped.
[Contract and limits](HISTORY-RECOVERY.md), [continuation handoff](ENGINE-EVOLUTION-HANDOFF.md).
No migration or VPS deployment. Shared checkpoint writes remain opt-in. This is
whole-block state recovery; commit revert/cherry-pick and native historical file
fidelity remain unfinished. Bounded chunks and shared references remain next.

## Previous increment: content writes during checkpoints (10 October 2026)

Part 2d makes the core/API writer lock compatible with checkpoint erasure guards.
Writers still serialize before permission/state/sequence checks; checkpoints retain
an exact immutable revision. Stronger management/erasure locks and atomic graph
publication remain. No new schema or staged-object protocol. Shared writes stay
opt-in while full-state, chunking, compression and concurrent API load work remain.

A controlled 8,000-block / 6.4 MB trace with ten real core writers records commit
times of 38-212 ms instead of 1.93-2.04 s under the old entry lock. All ten current
commits overlap publication, with identical checkpoint roots and verified final
states/chains. Checkpoint work itself remains about two seconds; the trace excludes
full API validation/materialization and native-host processing. See
[the lock audit, tests and measurements](CHECKPOINT-CONCURRENCY.md).

Both repositories pass fmt/Clippy, all 226 Rust tests and unchanged OpenAPI;
standalone docs pass with existing link warnings. Application source c19dbda and
engine source cc12b29 are pushed to main. Both source CI runs passed, including
274 frontend unit tests, 16 public browser tests and 62 signed-in workflows. The
disposable database/volume is removed. Exact continuation steps
are in [the handoff](ENGINE-EVOLUTION-HANDOFF.md). No VPS deployment.

Next: versioned bounded text/asset chunks, compressed packing and incremental
materialization, shared version/draft references, then durable local commits and
resumable exchange. Native/offline/provenance/scale acceptance remains unfinished.

## Previous increment: bounded checkpoint batches (10 October 2026)

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
