# Architecture

Canonical content is an append-only `event` chain per document. Current node rows
and snapshots are derived materializations. `log::append_in_tx` locks the document
row before allocating sequence numbers and hashes canonical, length-framed semantic
content and actor identity. Genesis uses a zero predecessor hash.

`Materializer` folds operations into stable-ID state, including tombstones.
`SnapshotEngine` stores replay checkpoints and an ordered node Merkle commitment.
Snapshots currently contain full JSONB states, not shared content-addressed trees.
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
Project policy inheritance and multi-file branches/releases are future work.
