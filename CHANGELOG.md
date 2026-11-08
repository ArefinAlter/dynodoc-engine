# Changelog

## Unreleased

### Application engine at 4f0e7a3 (decisions 024 to 043) - 2026-11-08

Synchronized `engine-shared`, `engine-core`, `engine-agent`, `engine-mcp`, `engine-api`,
`engine-cli`, migrations 0056 to 0142 and `openapi.yaml` from application `4f0e7a3`, and
added `engine-wasm` (`dynodoc-engine-wasm`). The incremental history archive export (#122,
#123) and the engine's own richtext fixture are kept. New in source, none of it deployed:

- Agent sessions, agent blame and project memory with MCP memory tools (026); MCP writes
  held for a person's confirmation, sealed agent authorship and organisation agent-client
  policy (029, 038); OAuth 2.1 for remote MCP clients and MCP over HTTP sessions.
- Ledger mode beside repository mode, storage manifests, relay, block states and partial
  rebase (025, 028, 040).
- Directory primitives for enterprise identity: sign-in by `(issuer, subject)`, scoped
  `/internal/directory/*` routes, source-tagged membership reconciliation and organisation
  sign-in settings (031); identity protocols themselves are not part of the engine.
- History horizons, shared object collection and a transparency log with a separate
  witness binary, `dynodoc-witness` (032).
- Automatic node resolution and cross-document merge (033); merge policies, history holds
  and structural merge (042).
- Resumable uploads, import jobs and shared object budgets for large files (034); object
  storage on the filesystem or S3 with a deletion queue (037, 043).
- Encrypted projects (HPKE key grants, Shamir escrow), at-rest data keys with Vault, AWS,
  Google Cloud and Azure key providers, device key rotation and legacy plaintext erasure
  (035, 041); PKCS#11 hardware device keys in `engine-cli` (039).
- Sessions, roles and service accounts, a mail outbox, event fan-out over `NOTIFY`,
  re-authentication for sensitive actions and metrics (037, 043).
- A pure build of `engine-core` and `engine-shared` without PostgreSQL, tokio or ring, and
  its WebAssembly exports with frozen parity vectors (036).

### Opt-in shared checkpoints - 2026-10-10

Added versioned full-state content objects, stable-key radix maps, document-scoped
memory/PostgreSQL stores, verified atomic checkpoint publication/load and an
operator CLI. Migration 0025 is additive; legacy snapshots/events and the HTTP
schema are unchanged. Admin erasure previews/receipts count the new data and audited
document erasure removes it. New codec/property/DB regressions and a synthetic
storage-growth benchmark cover the first part-2 slice. Default-path adoption,
large text/assets and portable commits remain open. See the evolution handoff for
source synchronization, exact checks and CI. Pinned SQL checkouts to LF to prevent
Windows line-ending conversion from changing SQLx migration checksums.


### Repository foundations and bounded replay - 2026-10-10

Synchronized from application `667ecb6`. Local lint, 204 tests, documentation and
unchanged generated OpenAPI checks passed. Centralized historical reconstruction in a core nearest-checkpoint reader with a
streamed suffix, revision/gap rejection and replay accounting. Historical batches
and draft bases reuse it. Chain verification streams rows, and snapshot cadence
reads sequence metadata only. Added checkpoint-boundary/replay-equivalence/scope
and cross-node validation dependency regressions. No migrations, event format or
HTTP schema changes. Shared content storage/offline commit exchange remain planned;
new product/status/handoff documents establish their acceptance gates.


### Date-only application contract documentation - 2026-10-06

Documented application 8c7461d date-only Excel/Sheets observations, native calendar
round-trip/timezone checks, merged-cell preflight and retained retry/recovery IDs.
Client code remains in the application. No Rust, migration, event or OpenAPI
changes; engine source remains synchronized at d6666a2. Native-host acceptance,
structural/formatting sync and marketplace distribution remain open.

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

