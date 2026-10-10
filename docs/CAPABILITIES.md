# Current engine capabilities

## Projects profiles and upload cap - 10 October 2026

Source `8eef6dd` adds own/shared-Project-member profiles with revision-checked
updates, private email omission and erasure cleanup. Original test uploads have a
3,000,000-byte cap, including bounded base64 decoding and upload request bodies.
Migration 0026 is required. All 233 Rust tests and source CI pass. This is an API
increment; the Projects-first frontend lives in application source `6f1ac21`.
See [the release contract](PROJECTS-WORKSPACE-RELEASE.md).

The hosted application remains `536a448` on schema 25 until the next controlled
rollout. Installed-host acceptance and the algorithm/storage limits below remain
open. This increment does not change event encoding or algorithmic complexity.

## History ranges and connector pairing - 10 October 2026

Range revert/cherry-pick computes and validates a selected net content delta,
merges against current state and requires overlap choices before creating a private
draft. Both range anchors and explicit choices are server-recorded; review rules,
stale-head checks and retry identity remain enforced. Browser-approved connector
keys can be registered by hash, completed using the editor secret, and revoked.
Native file exporters and installation/ribbon/sidebar clients remain application
features; this engine exposes pinned checkpoints, content operations and scoped auth.
Portable commit/branch commands, bounded storage and native fidelity remain open.
See HISTORY-RECOVERY.md and CONNECTOR-PAIRING-AND-INSTALLATION.md.

## Historical recovery - 10 October 2026

Current document members can export retained historical checkpoints. Recovery
preview derives whole-block operations from a server-read earlier revision;
contributors can create private drafts against a checked current head, with source
sequence/hash and retry-safe UUIDs. Normal submission, approval and merge rules
apply. Canonical history is preserved and newer overlaps require resolution.
See [the contract](HISTORY-RECOVERY.md) and [verification handoff](ENGINE-EVOLUTION-HANDOFF.md).
This adds no migration, portable commit model or native-file export capability.
The history reader/diff/draft base still materialize full state.

## Evolution part 2d - 10 October 2026

Core/API writers now use a document lock compatible with checkpoint erasure guards,
retaining writer/permission serialization and exact pinned-history reconstruction.
Ten real core writers in the controlled trace committed in 38-212 ms during shared
publication, versus 1.93-2.04 s with the previous entry lock. API tests separately
check edits under a checkpoint guard and permission revocation after a real wait.
This is not end-to-end API or native-host latency acceptance. Stronger management
and erasure operations still wait. The default shared writer remains off; full-state
work, large chunks, compressed packing and shared draft references remain open.
See [concurrency evidence](CHECKPOINT-CONCURRENCY.md) and [handoff](ENGINE-EVOLUTION-HANDOFF.md).

## Evolution part 2c - 10 October 2026

Shared checkpoint writes now buffer bounded batches (64 objects / 1 MiB); index
and value reads fetch up to 16 objects together. Exact-byte reuse validation,
concurrent INSERT-conflict validation, full reconstruction, document scope and
rollback remain mandatory. Fixed-ID comparison fixtures preserve the same roots
and canonical bytes across individual and batched SQL paths. Explicit/periodic
publishers share an advisory lock to serialize overlapping historical graphs.

Publication still scans full state and holds a document lock that blocks appends.
The default writer stays legacy. This does not yet add large-value chunks, compact
packing, short staged publication, shared draft references or offline commits.
Current measurements and verification are in [the checkpoint contract](SHARED-CHECKPOINTS.md)
and [handoff](ENGINE-EVOLUTION-HANDOFF.md). Earlier entries record historical slices.

## Evolution part 2b - 10 October 2026

Normal history/current reads and authorized API writes now use the nearest shared
or legacy checkpoint and a streamed tail. Shared wins ties and corrupt selected
graphs fail explicitly. The periodic shared writer is gated off by default; codec
capacity failures roll back partial objects and retain a legacy checkpoint at the
same revision. Duplicate jobs skip work and both checkpoint formats count toward
cadence. PostgreSQL value reads use bounded batches with full validation.

Named versions, deployed pins, audit snapshot IDs and draft/merge bases remain full
JSON. Shared publication scans all state, writes objects individually and blocks
FOR UPDATE appends during its transaction. Rollout, large-value chunks, versioned
draft references and local commit exchange are still open. See
[the storage contract/measurements](SHARED-CHECKPOINTS.md) and
[handoff](ENGINE-EVOLUTION-HANDOFF.md). Earlier entries below describe their slices.

## Evolution part 2a - 10 October 2026

Opt-in shared checkpoints now reuse unchanged document objects. The versioned
canonical codec covers full materialized state, stable-key radix indexes bound
reference fanout, and document-scoped memory/Pg stores preserve isolation. Schema
25 publication is transactional, verifies reconstruction and supports retry;
immutable guards and audited erasure cover the new tables. The operator CLI exposes
`shared-snapshot DOCUMENT_UUID --through-seq N`. No public object API is added.

Default snapshots and draft/version bases still use full JSON. Objects over 1 MiB
are rejected, state is fully resident and writes still scan it. The synthetic storage
benchmark is in [SHARED-CHECKPOINTS](SHARED-CHECKPOINTS.md); it is not a native-file,
database-load or production capacity result. Full local commit/branch exchange,
large text/assets, default-path migration and independent provenance remain open.
Verification, counterpart commits and CI are in [the handoff](ENGINE-EVOLUTION-HANDOFF.md).

## Evolution part 1 - 10 October 2026

The authoritative direction is local/remote document repositories, not questionnaire
authoring. See [PRODUCT-SPEC](PRODUCT-SPEC.md), [PROJECT-STATUS](PROJECT-STATUS.md)
and [ENGINE-EVOLUTION-HANDOFF](ENGINE-EVOLUTION-HANDOFF.md).

Historical materialization now selects the nearest preceding checkpoint and streams
the suffix. Old-base batches/drafts share the review/provenance reader. Full chain
verification streams rows, and checking snapshot cadence does not hydrate snapshot
JSON. Core replay metadata makes selected checkpoint/replay counts testable. New
regressions cover history boundaries, scope and cross-node constraint dependencies.
Current snapshots/draft bases are still full state. Shared storage, a local commit
DAG, complete offline convergence and independent audit anchors remain planned.
Local part-1 checks passed: task lint, 204 tests, task docs (existing link warnings)
and unchanged generated OpenAPI. Source: application `667ecb6`.
The dated capability records below describe prior increments; current verification
and counterpart source commits belong in the evolution handoff.

Updated 6 October 2026 from Dynodoc application 348bef9da0be3a72e1f3eeca57225d60aef71420. This records
executable service behaviour, not a production rollout or complete product.

| Area | Implemented | Boundary |
| --- | --- | --- |
| History | Serialized append-only semantic events, stable node ULIDs, hash chains, replay, snapshots/Merkle roots and restoration as new events. | Central PostgreSQL; no independent external chain-head commitment. Audited whole-document erasure intentionally removes history. |
| Rich content | Checked compact wording/formatting patches, three-way merge and explicit overlaps. | No complete Office file runtime or automatic convergence. |
| Drafts/review | Private append-only drafts, selected sharing, historical/named versions, requests, approvals/comments, strict unrelated-content choices and permission-checked merge/decline/withdraw. | Other people's unsubmitted drafts remain private, including from project managers. |
| Projects | Invite-only roots, folders, creation/listing, aggregate files/requests/own drafts, members, revision-checked settings and submission Watch. | Web navigation/import/download UI lives in Dynodoc; Compare/Activity and multi-file releases remain open. |
| Roles/rules | Owner/Manager/Editor/Reviewer/Contributor/Viewer, direct/inherited access, file overrides, inherited project review defaults and protection/approval/merge restrictions. | Core still uses Author/Reviewer/Auditor; membership/rules are operational metadata. |
| Provenance | Version-1 portable bundles, exact base-sequence/hash check, permission-checked historical checkpoints, atomic content-only proposal, immutable normalized envelope/digest and durable same-actor retry receipt. Retrieval preserves private-draft permissions. | Uploader/reception are server facts; host/local-time/origin descriptions are client claims, not human/AI authorship proof or external timestamping. |
| Editor credentials | Hashed seven-day revocable file/host-scoped read/propose keys for Word/Docs, Excel/Sheets and PowerPoint/Slides; file-kind validation on creation; current membership, account/session generation and expiry rechecked. | No merge/access-management permissions, no OAuth pairing or complete offline replica. Native clients remain development code in the application. |
| Copies | Deterministic fingerprints, MinHash/LSH detection, containment/relatedness, owner actions and permission-filtered results. | Filename/content matching suggests relationships, not authenticated authorship. |
| Notifications | Per-person inbox/count/read, copies/reviews/access notices and project submission watchers. | No engine email delivery, all-event Watch or daily summary. |
| Governance/API | Sheet protection, questionnaire validation, authenticated HTTP/SSE/audit, PASETO sessions, administrative controls and audited document/account erasure. Generated OpenAPI. | Hosted cookie/provider gateways and file parsing/editing are application responsibilities. |

## Compatibility and packaging

New migrations 0022 and 0023 add Projects/settings/watchers and connector/bundle
tables. Migration 0024 expands the six-host constraint; earlier migration bytes remain unchanged. Existing migrations through 0021, event variants and serialization are
unchanged. MIT metadata, Rust 1.96 pin, independent CI and local rich-text replay
fixture remain. No frontend, credentials, private files or production data are
copied. Core/shared remain usable without the product HTTP adapters.

Stored bundle history cannot be changed/deleted through ordinary operations.
Same-transaction audited document/account erasure removes it with its draft.
Ordinary retry lookup still checks current permissions; different content/actor
cannot reuse an existing receipt. Merging appends canonical events as the
responsible merger, while the original uploader/observations remain separate.

## Previous backlog (6 October; superseded by the evolution plan)

1. Accept all three application editor pairs in real hosts: Word/Docs, Excel/Sheets and PowerPoint/Slides.
   Extend stable-ID structural sync, formatting adapters and conflict recovery.
2. Durable background/local capture, automatic copy/device discovery, secure
   pairing, signed installation and both marketplace reviews/publication.
3. Project Compare/Activity/search and consistent multi-file releases.
4. Remove duplicated Rust sources through a pinned dependency/subtree, extend
   durable retry semantics, retain independent chain commitments and profile
   snapshot/storage costs. No Git transport, CRDT typing or full offline sync.

Invitation emails remain in the application web gateway. AI-origin/MCP/assessment
proposals are separate future work. Further web-editor Office parity is not the
owner's product priority.

## Earlier verification records

Projects/provenance integration tests cover isolation/private drafts, inheritance,
settings revisions, Watch, concurrent retries, bad-base/invalid-operation rollback,
scoped keys, revocation, expiry, forced sign-out/access removal and both document
and private-account erasure. Existing replay/merge/privacy regressions remain.
Run task lint, task test, task docs and task openapi against an isolated database.
Local verification for the earlier e73e4ba synchronization passed task lint, all 198 tests via
task test (including the unchanged 100 ms SSE assertion), task docs and generated
OpenAPI. Documentation retains existing Rustdoc link warnings. Earlier application
runs hit the intermittent native SSE timeout; Linux CI retains the assertion.
Source/test coverage does not establish production or live editor acceptance.

Historical checkpoint follow-up: both GET endpoints accept optional through_seq.
Current access/session/expiry checks apply to historical content; invalid/future
revisions return 400. Application clients verify a recovered queue's exact base
before binding. This increment passed task lint, all four Projects/provenance
integration tests and OpenAPI generation locally. Independent CI runs all 199
tests. No migrations/event variants changed. Native recovery UI remains application
code and does not establish background capture or real editor-host acceptance.

Six-editor follow-up: the same anchored bundle service accepts all six editor host
claims, with scoped host/file keys and file-kind checks. New integration coverage
verifies Excel/Sheets and PowerPoint/Slides key isolation, string field operations,
retry receipts, unchanged canonical heads and revocation. Client cell/formula/shape
adapters live in the application. This does not establish structural/formatting
sync, native-host acceptance, background capture or publication.

Six-editor verification: task lint, all 200 tests via task test, task docs and
OpenAPI generation passed locally. The generated API is unchanged. Independent
CI for d6666a2 passed format, Clippy, build, all 200 tests, docs and OpenAPI consistency:
[run 37430229717](https://github.com/ArefinAlter/dynodoc-engine/actions/runs/37430229717).
Pre-existing Rustdoc link warnings remain. Native installation and VPS rollout
are application evidence and are not implied by engine source publication.

## Date-only application clients - 6 October 2026

Application 8c7461d137f0cefbbe265d58a12d4078acb07212 adds date-only Excel/Sheets
observations to the existing version-1 string-field contract. Excel uses checked
native calendar functions; Sheets uses the spreadsheet timezone and checked local
midnight. Both preflight native date-only masks/values and preserve retry/recovery identity. The application
now requires ExcelApi 1.13 for local merged-cell checks. Timestamps, date-format/type
changes, formula-engine compatibility and real-host acceptance remain open.

These adapters and generated Google artifacts live in the application, not this
MIT engine repository. Service source remains the d6666a2 synchronization from
application 348bef9; migration bytes, event variants and OpenAPI are unchanged.
The engine already stores/retrieves these string observations and merges them
through the existing permission-checked proposal path. The engine does not perform
native calendar or Office/Google runtime conversion. See the
[application release](https://github.com/ArefinAlter/dynodoc/blob/main/docs/SPREADSHEET-DATE-SYNC-RELEASE.md)
and [native acceptance matrix](https://github.com/ArefinAlter/dynodoc/blob/main/docs/NATIVE-CONNECTOR-ACCEPTANCE.md).
