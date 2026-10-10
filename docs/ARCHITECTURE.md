# Architecture

Canonical content is an append-only `event` chain per document. Current node rows
and snapshots are derived materializations. `log::append_in_tx` locks the document
row before allocating sequence numbers and hashes canonical, length-framed semantic
content and actor identity. Genesis uses a zero predecessor hash.

`Materializer` folds operations into stable-ID state, including tombstones.
`SnapshotEngine` stores replay checkpoints and an ordered node Merkle commitment.
Periodic writes default to full JSONB, with an opt-in shared writer. Normal reads
select the nearest legacy/shared checkpoint, preferring shared on ties. The
`shared_checkpoint` module stores versioned objects and stable-key radix maps; see
[its format and limits](SHARED-CHECKPOINTS.md). No legacy state/event is rewritten.
Restoration appends operations; it never resets the chain.

`richtext` in shared defines versioned patches; core generates and checks them.
The patch has before/after hashes, a style table and path-addressed edits. Counts
are Unicode scalars. Paths refer to the checked base, not stable nested IDs.
Full-field events remain the fallback when a patch is unsupported or larger.

`workspace_merge` compares ancestor, team and personal states. Supported disjoint
text/format changes combine. Competing values, overlapping wording and ambiguous
structural operations surface conflicts. Read `tests/richtext_test.rs` and
`tests/fixtures/richtext-fixtures.json` for executable examples.

Events and migration files are public compatibility contracts. Add new migrations;
never rewrite applied ones. Readers of historical events must remain compatible.
The API exposes only authorized states. Content hashes do not cover every metadata
or access-control operation; the operational audit is a separate log.

The `engine-api` adapter retains the original product schema so migrations and
recorded histories remain compatible. Further extraction of product-specific
adapters is a future change with explicit compatibility tests.

## Current collaboration adapters

`workspace_merge::merge_strict` adds explicit existing-block choices for unrelated
content. `similarity` computes bounded deterministic word/block fingerprints and
MinHash/LSH summaries; `engine-api::copies` indexes/detects relationships and checks
access before displaying them. Similarity does not establish authenticated origin.

`access`/`people` map the product role ladder onto the preserved core capabilities,
with per-document rules. `reviews` handles submitted drafts, approvals/comments
and permission-checked merges; `notifications` stores per-recipient operational
notices. Migrations `0020`/`0021` extend these adapters without new content events.
Projects now inherit review defaults through their containing root; file overrides win. Multi-file branches/releases remain future work.


Projects/provenance increment: project settings/member changes serialize with
content writes. Bundles and their draft/receipt share one transaction, exact base
hashes are checked, and retry lookup rechecks membership. Stored uploader identity
is distinct from client observation claims and the responsible canonical merger.
Scoped keys cannot merge or access another document. Audited resource erasure
removes bundle children while ordinary history remains immutable. See
[the sync contract](PROVENANCE-SYNC.md).

Migration 0024 expands connector credentials to all six Microsoft/Google hosts.
Creation validates document kind; existing host/file/account/session/review scope
and append-only events remain unchanged. Native adapters remain application code.


## Evolution part 1

`snapshot::read_state_at` is the common historical reader. It selects the greatest
checkpoint sequence no greater than the requested revision, then streams only that
suffix into the ordinary materializer. It rejects invalid revisions and suffix gaps
and reports checkpoint/replay counts. Callers retain access checks and document
write locks where needed. Snapshots are trusted derived data here; the path is not
an independent verification of the snapshot's commitment. A missing checkpoint
still requires genesis replay, and complete state remains resident in memory.

`log::verify_chain` independently streams event rows, keeping current payload/hash
working data instead of the entire history. It still needs a trusted externally
retained head to detect replacement of the entire chain. Snapshot cadence queries
only sequence metadata. Neither change supplies shared-object storage or hard tail
bounds. See the evolution plan for typed objects, ancestry and offline convergence.

Automatic operation independence includes reads, writes and validation constraints,
not just target IDs. Unique-name and crossed-move regressions document concrete
counterexamples. The engine does not yet infer a general cross-format dependency
footprint or prove automatic convergence of arbitrary native editor operations.

## Shared checkpoint boundary (parts 2a-2c)

Core stores require document scope and caller authorization. Object hashes are
content integrity addresses, not permissions or actor attestations. PostgreSQL
publication protects the document from erasure, derives an exact historical state,
stores/validates its reachable object graph and compares reconstruction before
inserting the immutable sequence/root/chain manifest in the same transaction.
Same-revision publication is idempotent. Part 2b normal current/history readers and
API write materialization select mixed checkpoints, verify shared graphs/chain
positions and stream only the suffix through the pinned revision. Explicit CLI
publication retains an independent legacy/event reference. Corrupt selected shared
data fails, even when legacy data exists. Reader support is independent of the
automatic writer flag; named/deployed snapshots and draft/merge bases stay legacy.

Explicit publishers take a document advisory lock before the row lock; periodic
jobs use the same namespace with try-lock semantics to skip competing builders.
This serializes overlapping historical publication before object batches, avoiding
cross-batch lock-order deadlocks. A savepoint rolls back partial shared objects on
capacity errors before a legacy fallback; other errors propagate. Background jobs
opt in with API process env DYNODOC_PERIODIC_CHECKPOINT_STORAGE=shared-v1, otherwise
legacy. Both formats count toward cadence.

The writer scans all state, buffering at most 64 objects / 1 MiB of encoded bytes,
plus the current object being encoded and driver/input state. PgStore validates
input and checks exact stored bytes in bounded SQL joins returning booleans; one
INSERT stores missing objects, and raced conflicts are checked again. Unchanged
batches issue no INSERT. The document KEY SHARE lock still blocks FOR UPDATE
appends through publication. Short staged publication remains separate work.

Breadth-first index traversal and values use batches of at most 16 addresses with
full hash/type/route/subtree validation and byte/object budgets. Traversal queues
count against the remaining object budget. The cache retains the latest scoped
batch, at most 16 MiB encoded bytes; traversal metadata, complete state/map entries,
current decoded values and driver allocations are outside that cache bound.

Objects are at most 1 MiB, radix leaves at most 32 entries, branches at most 16 and
paths at most 64 nibbles. Total byte/object budgets are checked. Complete state and
map entries remain in memory; no whole native-file streaming guarantee follows.
Audited erasure removes manifests then document-scoped objects. No GC is enabled.

Migration bytes are also a compatibility contract: SQLx hashes the complete file.
`.gitattributes` pins SQL checkouts to committed LF bytes on Windows and Unix.
Application/engine migration checksums are tested against the same isolated DB;
never edit applied migration content or recorded checksums to resolve a mismatch.
