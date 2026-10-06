# Changelog

## Unreleased

### Application synchronization - 2026-10-06

Synchronized the Rust service from application `52c2447`: change-request lifecycle,
strict unrelated-content merging, roles/review policies/approvals, content
fingerprints and copy detection, permission-aware in-app notifications and
administrative deletion updates. Added migrations `0020`/`0021` and their existing
regression tests. Historical migrations and event serialization are unchanged.
Standalone MIT packaging, Rust 1.96 and the local golden replay fixture are retained.
Regenerated OpenAPI; documented current capabilities and remaining work.

The Projects workspace is not implemented; invitation emails still live in the
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
