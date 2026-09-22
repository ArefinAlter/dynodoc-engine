# Changelog

## Unreleased

Worksheet protection now runs through the governance gate, including structural
operations and suggestion acceptance. Authors can explicitly unprotect; discussion
and proposals remain available. This prevents accidental edits and is not password
security. Snapshot diffs apply explicit unprotection before content and protection
after content, including new worksheets. Older snapshots can clear the flag.
No event format or migration changes.

## 0.1.0 — 2026-09-22

Initial standalone source release from Dynodoc: four Rust crates, immutable
migrations, generated API, tests and fixtures. MIT license authorized by the owner.
Community policies, local PostgreSQL setup and independent CI added. Existing
content-event and database migration formats are unchanged. No binary or crates.io
release is implied by this entry.
