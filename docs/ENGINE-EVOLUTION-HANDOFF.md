# Engine evolution handoff

Updated 10 October 2026. **Part 1 complete and published.** Scope: checkpoint-aware streamed historical reads, streaming
verification, mathematical/product contract correction and replay regression coverage.
Read PRODUCT-SPEC, ENGINE-EVOLUTION-PLAN and PROJECT-STATUS before continuing.
Starting engine commit: `67060cf`; starting application commit: `f054ad1`.

## Implemented in this increment

- Core `read_state_at`: nearest checkpoint at/before the exact revision, streamed
  event suffix, revision/gap checks and selected-checkpoint/replay-count evidence.
- Review/provenance checkpoints, historical batches and historical draft bases share
  the reader within their existing authorization/transaction boundary.
- Chain verification streams events; cadence checks read indexed sequence metadata.
- Historical replay equivalence/boundary/document-isolation tests and two
  cross-node validation-dependency regressions. No changed event or migration bytes.
- Product/storage/replication roadmap and current status. Native client changes,
  bounded browser matching and corrected historical math live in the application.

## Verification and publication

Synchronized from application `667ecb6ecef5b64debcca6817e73b6be807bde37`.
All seven changed source/test files match the application exactly. No migration,
event format or HTTP schema changes. MIT package metadata and the standalone
rich-text fixture location remain intact.

- `task lint`: formatting and Clippy with warnings denied passed.
- `task test`: all 204 tests passed against isolated PostgreSQL, including the
  unchanged 100 ms SSE assertion and new historical/constraint regressions.
- `task docs`: passed with the pre-existing Rustdoc link warnings.
- `task openapi`: passed; generated OpenAPI unchanged.
- Application: 204 Rust tests, affected 13 tests rerun after final streaming changes,
  274 frontend unit tests, Clippy, ESLint and complete Svelte/type check passed.

The disposable test container and volumes have been removed. No VPS deployment,
real native-host acceptance or marketplace publication is claimed. Implementation is pushed to main at `647249e7ed692534f7ab21a1ad522912c7d58385`;
application source is `667ecb6ecef5b64debcca6817e73b6be807bde37`.
[Independent CI](https://github.com/ArefinAlter/dynodoc-engine/actions/runs/38038142218)
passed for implementation `647249e`: formatting, Clippy, build, all tests, docs
and OpenAPI consistency. Subsequent documentation commits do not change those source files.

## Next concrete task

Part 2: specify typed/versioned canonical objects and commit manifests, then implement
tenant-scoped shared checkpoints behind a compatibility boundary. Compare every new
checkpoint with legacy replay, prove unchanged subtrees reuse objects, test interrupted
publication and reachability/erasure. Keep draft bases/event hashes readable. See the
plan's design gate before adding a migration or raising upload limits.

Full JSON snapshots, native structure/format/background gaps and centralized canonical
history remain. Independent heads/signatures, full replica convergence, background
capture and hundreds-of-MB/load acceptance are open; do not report them as shipped.
