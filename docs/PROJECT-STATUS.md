# Engine project status

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
warnings). Publication/CI is being finalized. The synthetic
8,000-block/21-checkpoint trace used 7.83 MB of unique object bytes versus 135.24 MB
of full-state copies. Native files, database overhead and load are unmeasured.

Next: normal-path shared checkpoint adoption and draft/version references; bounded
large text/assets and durable backend measurements; then local commits/branches
and missing-object exchange. Complete offline convergence, signed/witnessed heads,
full native-host capture and large-file/service capacity remain unfinished. No
production deployment; the application VPS remains at its recorded schema 24.

Part 1 previously added streamed historical replay and verification, checkpoint
cadence metadata reads and dependency-counterexample tests (204 tests). The full
prior source and CI record remains in the handoff.
