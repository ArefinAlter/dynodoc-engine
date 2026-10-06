# Current engine capabilities

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

## Remaining work, in order

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

## Verification

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
