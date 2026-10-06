# Changelog

## Unreleased

### Historical checkpoints and recovery support - 2026-10-06

Synchronized from application a286aee276dff03f01c529485566115cc7024658. Both checkpoint
GET endpoints accept optional through_seq and return exact canonical historical
state/hash under current membership/scoped-key checks. Reject invalid/future
revisions; omitted selector retains current-head behavior. Native connectors use
this to verify sidecar recovery before identity binding. They remain application
code. No migration/event-format changes. Local lint, four integration tests and
generated MIT OpenAPI pass; independent CI runs all 199 tests.


### Projects and portable provenance - 2026-10-06

Synchronized from application 2a289ce2fe5fc0071fc45596fdf39b66aca10af7: invite-only Projects, aggregate
files/requests/private own drafts, inherited review defaults and submission Watch.
Added anchored immutable change bundles, atomic proposals/durable retry receipts,
scoped revocable seven-day editor keys and current-access/session/expiry checks.
New migrations 0022/0023 only; historical migrations and event formats unchanged.
Three integration tests exercise privacy, policy, retries, scoping and audited
document/private-account erasure. Regenerated API and current capability docs.
Word/Google Docs clients remain application development prototypes; no production
deployment, real-host acceptance or marketplace publication is implied.

Local verification passed formatting/Clippy, all 198 tests (including SSE),
documentation (existing Rustdoc warnings) and regenerated MIT OpenAPI.

### Application synchronization - 2026-10-06

Synchronized the Rust service from application `52c2447`: change-request lifecycle,
strict unrelated-content merging, roles/review policies/approvals, content
fingerprints and copy detection, permission-aware in-app notifications and
administrative deletion updates. Added migrations `0020`/`0021` and their existing
regression tests. Historical migrations and event serialization are unchanged.
Standalone MIT packaging, Rust 1.96 and the local golden replay fixture are retained.
Regenerated OpenAPI; documented current capabilities and remaining work.

At that earlier synchronization Projects was unimplemented; invitation emails live in the
hosted web gateway. No production deployment, binary or crates.io release is
implied. Local Windows verification: formatting/Clippy passed; 194 tests passed
with the existing 100 ms SSE test filtered after it timed out both in the full
run and alone. Its code and threshold are unchanged. Documentation built (with
Rustdoc link warnings) and OpenAPI was regenerated. Linux CI runs all 195 tests.

### Earlier standalone fixes

Worksheet protection now runs through the governance gate, including structural
operations and suggestion acceptance. Authors can explicitly unprotect; discussion
and proposals remain available. This prevents accidental edits and is not password
security. Snapshot diffs apply explicit unprotection before content and protection
after content, including new worksheets. Older snapshots can clear the flag.
Idle event streams now acknowledge immediately instead of waiting for the first
heartbeat; comments do not change replay cursors. No event format or migration changes.

## 0.1.0 — 2026-09-22

Initial standalone source release from Dynodoc: four Rust crates, immutable
migrations, generated API, tests and fixtures. MIT license authorized by the owner.
Community policies, local PostgreSQL setup and independent CI added. Existing
content-event and database migration formats are unchanged. No binary or crates.io
release is implied by this entry.

## Six-editor provenance (6 October 2026)

- Sync service/tests from application 348bef9da0be3a72e1f3eeca57225d60aef71420.
- Add immutable migration 0024 for Word/Docs, Excel/Sheets and PowerPoint/Slides keys.
- Validate file kind on connection creation; retain scoped retries and revocation.
- Native adapter source and acceptance remain application responsibilities.

