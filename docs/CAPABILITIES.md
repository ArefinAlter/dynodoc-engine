# Current engine capabilities

Updated 6 October 2026. Source synchronized from application `52c2447`, following
standalone engine `a22bf71`. This records the Rust implementation, not a new
production deployment or a claim that the full Dynodoc product is complete.

## Core and service boundary

| Area | Implemented behavior | Boundary |
| --- | --- | --- |
| Canonical history | Serialized per-document appends, semantic events, stable node ULIDs, hash-chain verification, replay, materialized state, snapshots/Merkle roots, restoration through new operations. | Centralized PostgreSQL; no independent chain-head anchoring or offline replicas. Whole-document audited erasure deliberately removes history. |
| Rich content | Compact checked wording/formatting patches, full-field fallback, supported disjoint three-way merges, explicit overlap resolution. | Run boundaries/offsets are not permanent identities; no full Office compatibility. |
| Private drafts | Personal append-only draft operations, pull/rebase, selected sharing, named versions and historical state. | Unsubmitted drafts remain private to their author. No project-wide branch tree. |
| Change requests | Submit/list/detail, approve/request changes/comment, merge/decline/withdraw, per-block notes and historical starting points. | File parsing/alignment happens in the hosted client; API receives structured operations and source metadata. |
| Unrelated content | Strict merge requires explicit choices for changed existing blocks rather than silently replacing team content. | Same-name files do not prove shared history. |
| Roles and rules | Owner, Manager, Editor, Reviewer, Contributor, Viewer; direct/inherited access; protect team version, require 0–5 approvals, restrict merging. Content changes invalidate earlier approvals. | Per-document policies; project defaults and project spaces are not implemented. Core governance still uses Author/Reviewer/Auditor capabilities. |
| Copy detection | Deterministic content/block fingerprints, MinHash/LSH candidates, similarity/containment classification; owner actions and permission-filtered results. | Similarity is heuristic, not verified authorship or plagiarism proof. Historical baseline copies are listed without notification floods. |
| Notifications | Per-recipient list/unread count/mark-read; review, copy and access notices, with permission-aware display. | In-app data only. No engine email sender, watcher subscriptions or daily digest. |
| Protection and validation | Whole-sheet governance checks including suggestion acceptance/restoration/merge ordering; questionnaire expression/integrity validation. | No password protection, protected cell ranges or full vendor expression runtime. |
| HTTP/SSE and audit | Authenticated REST, PASETO sessions/service exchange, replayable SSE with immediate idle acknowledgement, admin/audited erasure operations, generated OpenAPI and audit CLI. | Browser cookie gateway, OAuth/provider exchange and hosting are separate deployment/application responsibilities. |

The adapter preserves the original product schema. Core/shared can be used
without adopting questionnaire, workspace or administration endpoints.

## Role names and compatibility

| Display role | Storage/source | Meaning |
| --- | --- | --- |
| Owner | `document.created_by` | Document ownership and management. |
| Manager | Inherited workspace owner/manager | Access/rules/lifecycle management. |
| Editor | `author` (document), `editor` (space) | Team editing/merging subject to policy. |
| Reviewer | `approver` | Approval/request-changes capability. |
| Contributor | `reviewer` | Comments, personal drafts and submitted proposals. |
| Viewer | `auditor` (document), `viewer` (space) | Read-only access. |

The request value `reviewer` names the new product Reviewer role; the persisted
historical `reviewer` value remains Contributor. Clients should obtain the
effective role/capabilities from `/documents/:id/people` rather than interpreting
database strings as UI labels.

## Synchronization and migrations

This update adds the application Rust changes from the September change-request
and copies/roles releases, including their integration tests and similarity
benchmark. Existing standalone package metadata, MIT license, Rust 1.96 pin,
local golden fixture and independent build remain in place.

Only new migrations are added:

- `0020_change_requests.sql`: submitted draft source/lifecycle/review metadata.
- `0021_copies_roles_reviews_notifications.sql`: role mapping, document policies,
  append-only reviews, notifications and rebuildable copy indexes/baseline.

Migrations through `0019` are untouched and have the same committed Git blobs
as the application. Existing event variants and serialization remain unchanged.
Review metadata/fingerprints/notifications are operational or derived records,
not a claim that every permission change is hash-chained content.

The application remains AGPL; this authorized standalone extraction remains MIT.
No website, credentials, user files, provider settings or production data are copied.

## What remains

The hosted GitHub-style Projects workspace is **approved, unimplemented**. Its
first phase will group files, submitted requests, the caller's drafts, members,
review defaults and in-app Watch; Compare/Activity and project releases follow.
This update supplies existing per-document primitives, not those project APIs.

Invitation email shipped in the application web gateway at `b70f048`. It calls
the engine to grant access before sending through Resend; email delivery and its
limits are not engine capabilities. Other notices remain in-app.

Engine follow-ups: durable idempotency throughout workspace operations, clearer
adapter separation, independent retained chain commitments, measured snapshot
efficiency, richer attribution and portable history exchange. The hosted product
still duplicates the Rust sources; a pinned dependency/subtree migration is open.
No Git transport, CRDT typing, full offline sync, agent-origin tracking, MCP agent
server, AI assessment or complete Office runtime is implemented here.

## Verification

Use `task lint`, `task test`, `task docs` and `task openapi`. Database tests create
isolated SQLx databases on a local PostgreSQL service. Added evidence lives in
`review_test.rs`, `copies_test.rs`, `workspace_merge` strict-merge tests and
`similarity` tests. Golden rich-text replay stays local to this repository.
CI checks compilation, formatting, Clippy, database tests, docs and OpenAPI drift.
Actual results are recorded in [the synchronization entry](../CHANGELOG.md);
test coverage is not real-provider or production-latency acceptance.
