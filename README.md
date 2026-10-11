# Dynodoc Engine

## Source: typed storage and portable local project history (12 October 2026)

Current source adds typed v2 checkpoints and opt-in shared draft bases (schema 31),
plus a durable SQLite local repository with signed multi-file commits, parent
history, branch CAS, missing-object transfer, project comparison and CLI commands.
Read [storage/reference bounds](docs/TYPED-CHECKPOINTS.md),
[local history and trust limits](docs/PORTABLE-PROJECT-HISTORY.md) and
[the complete acceptance ledger](docs/ROADMAP-ACCEPTANCE.md).

This has not been deployed to the schema-29 VPS. Remote project authorization,
connector/UI adoption, complete offline/native convergence and independent witness
commitments remain open. Installed Office/Google testing is the owner's local
worksheet. Exact checks and source revisions are in the
[handoff](docs/ENGINE-EVOLUTION-HANDOFF.md).

## Source: streaming byte-content storage (12 October 2026)

Engine `746d373` (application `3462520`) adds document-scoped 64 KiB content chunks,
bounded reference trees and streaming I/O with explicit object/byte budgets. Fixed
independent hash vectors, reuse/scope, rollback and erasure regressions accompany
the binary format. Existing v1 state/event hashes and schema 29 are preserved.
Read [the contract and measured limits](docs/CHUNKED-CONTENT.md) and
[verification/next work](docs/ENGINE-EVOLUTION-HANDOFF.md).

This is an internal byte-storage primitive. Typed checkpoint manifests, bounded
semantic decoding, shared draft/version references and portable project branches
remain open; ordinary snapshots do not yet use these content roots. Production
remains the release below, with shared periodic writes off. The application also
provides a [local native-host test worksheet](https://github.com/ArefinAlter/dynodoc/blob/main/extensions/ACCEPTANCE.md);
real Office/Google host acceptance remains to be run by the owner.

## Verified: bounded API workloads and hosted release (11 October 2026)

Engine `80cd148` passes all 275 Rust tests and independent CI. Process-local
response admission, identity/project expensive-read budgets and database deadlines
are implemented. The hosted application `858801c` is live at schema 29 after an
isolated backup/upgrade/compatible-rollback rehearsal. Its API uses a restricted
database login; events and hashes are unchanged. See [release evidence](docs/operations/2026-10-11-security-runtime-release.md)
and [bounds/remaining work](docs/ENGINE-EVOLUTION-HANDOFF.md).

Next are bounded shared chunks and historical references, portable project-wide
commits, durable offline convergence and independent audit commitments. Current
workload limits do not bound full-state memory or establish large-service capacity.

## Project policy and metadata authority - 11 October 2026

The API combines file rules with project minimums and reserves project review
bypasses/settings/moves for project management. Metadata uses bounded supported
settings patches and atomic before/after digest audit. Existing schema 29,
events and hashes are unchanged. See [the contract](docs/PROJECT-POLICY-AND-METADATA.md)
and [verification/handoff](docs/ENGINE-EVOLUTION-HANDOFF.md).
Engine lint, all 269 Rust tests, rustdoc, OpenAPI and implementation CI passed.
This records the previous source increment; the later hosted release is linked above.

[![CI](https://github.com/ArefinAlter/dynodoc-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/ArefinAlter/dynodoc-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Semantic version control for structured documents, written in Rust with PostgreSQL.
Stable node identities, immutable content operations, hash-chain verification,
replay, snapshots, personal drafts and three-way merging form the core. Rich-text
patches retain wording and formatting; independent edits can merge and genuine
overlaps require review.

This is the standalone engine extracted from [Dynodoc](https://github.com/ArefinAlter/dynodoc).
It does not include the browser editors, public website, production configuration,
credentials, user files or production database. It is an early 0.1 source release,
not a claim of Git protocol compatibility, offline convergence or complete Office
file support. No crates.io package has been published.

## Previous increment: restricted database runtime (11 October 2026)

Schema 0029 separates operator migrations from API credentials. Startup checks the
schema and a dedicated restricted login; it never applies migrations. Immutable
history has SELECT/INSERT grants only, while approved erasure runs through guarded
trigger entrypoints. Read [setup, trust and rollout requirements](docs/DATABASE-PRIVILEGES.md)
and [verification/status](docs/ENGINE-EVOLUTION-HANDOFF.md). No VPS deployment is implied.

## Previous increment: verified legacy snapshots (11 October 2026)

Schema 0028 protects legacy snapshot rows and adds immutable verification receipts.
Checked reads reject unverified/corrupt snapshots; API and CLI audits compare every
legacy snapshot against the event history, including non-node state. New snapshots
are reconstructed canonically. Existing databases require explicit verified backfill
before reopening traffic. See [the snapshot contract](docs/VERIFIED-SNAPSHOTS.md)
and [validation/remaining work](docs/ENGINE-EVOLUTION-HANDOFF.md).

Runtime database privilege separation and hosted deployment acceptance pass.
Receipts remain internal attestations,
not signatures or external witnesses. Portable project histories, shared chunks,
offline convergence and installed-editor acceptance remain open.

## Previous increment: authentication and bounded history (10 October 2026)

Source hardening adds fail-closed service credentials, migration 0027 for revocable
login lineages, bounded REST/SSE history reads, expression admission limits and
iterative relevance-cycle detection. Existing event hashes remain unchanged.
Legacy-cookie logout invalidates the account generation; new logout revokes only
that login. An old API build must not be used as rollback without compatible
revocation enforcement or deliberate credential invalidation.

See [the security findings and open gates](docs/SECURITY-HARDENING.md) and
[handoff](docs/ENGINE-EVOLUTION-HANDOFF.md). Snapshot/runtime-role and project-policy
rollout acceptance passed in the later release above. Independent audit commitments
and the remaining repository/offline/storage work are incomplete.

## Previous increment: bounded checkpoint encoding (10 October 2026)

Shared checkpoint v1 now encodes borrowed values into a capped output buffer and
checks canonical bytes through streaming comparison. Existing hashes, roots and
history remain compatible; no migration or public API change. Five new tests cover
byte compatibility, generated nested values and allocation boundaries. The
[allocation probe and limits](docs/BOUNDED-CHECKPOINT-ENCODING.md) document the
oversized-rejection improvement without claiming bounded total document memory.

Large-value/asset chunks, packing/incremental publication and shared draft/version
references remain next, before portable project commits and offline exchange.
Shared writes remain opt-in. This source increment is not deployed; current source
checks, native-host gaps and publication requirements are in
[the handoff](docs/ENGINE-EVOLUTION-HANDOFF.md).

## Previous increment: member profiles and test-file boundaries (10 October 2026)

Migration 0026 adds minimal account profiles with revision-checked saves. Profile
reads require the same account or current shared Project membership and exclude
email. Manually edited names survive subsequent provider sign-in. Original file
uploads now accept at most 3,000,000 bytes, with a bounded base64 request and no
stored upload on rejection. Existing events and history readers are unchanged.

The hosted application's Projects-first interface, previews and separate editor
navigation live in the application repository. Current drafts are per-file; this
increment does not add project-wide branches or portable multi-file commits.
Standalone verification: task lint, all 233 Rust tests, task docs (existing link
warnings) and regenerated OpenAPI. Source/deployment status and remaining storage,
offline, native-host and audit work are in [the handoff](docs/ENGINE-EVOLUTION-HANDOFF.md).

## Previous increment: history ranges and editor pairing (10 October 2026)

The API supports net revision-range revert/cherry-pick with explicit overlap
choices, checked current heads and private recovery drafts. Normal review/merge
policies preserve append-only canonical history. Browser approval can register a
hash of the editor-held secret and complete through a scoped connection endpoint;
all six hosts retain file/kind/role/session/revocation constraints. No migration.
See [history operations](docs/HISTORY-RECOVERY.md) and [pairing](docs/CONNECTOR-PAIRING-AND-INSTALLATION.md).
Native historical DOCX/XLSX/PPTX export controls, ribbon/menu UI and test-installation
packages live in the application repository. They are not included in this Rust
repository or a claim of full fidelity/native acceptance/marketplace publication.
Verification and publication are tracked in [the handoff](docs/ENGINE-EVOLUTION-HANDOFF.md).

## Previous increment: historical recovery (10 October 2026)

The account-authenticated API previews selected content from any retained revision
and creates a private recovery draft with a checked current base and source hash.
Current membership, ordinary review/merge rules and idempotent retries apply.
See [the recovery contract](docs/HISTORY-RECOVERY.md). The web controls live in the
application repository. Commit revert/cherry-pick and native historical exports
remain future work; bounded chunks and shared version/draft references stay next.

## Previous increment: checkpoint concurrency (10 October 2026)

Part 2d lets ordinary content transactions proceed during a checkpoint while
preserving serialized writes, permission checks, pinned history and erasure guards.
[The concurrency contract](docs/CHECKPOINT-CONCURRENCY.md) records the lock audit,
regressions and controlled ten-writer measurement. Shared checkpoint writes remain
opt-in; full-state work, bounded large text/assets, compression, shared version/draft
references and durable local commits/exchange remain open. Existing graph batching
and v1 hashes are unchanged.
Source/check evidence is in
[the handoff](docs/ENGINE-EVOLUTION-HANDOFF.md); see [current status](docs/PROJECT-STATUS.md),
[product contract](docs/PRODUCT-SPEC.md) and [ordered plan](docs/ENGINE-EVOLUTION-PLAN.md).

## Previous synchronization (6 October 2026)

The Rust service now includes invite-only Projects, cross-file requests/private
own drafts, inherited review rules and submission watchers. Portable change
bundles are anchored to exact document revisions, stored immutably and receive
durable retry receipts. Seven-day revocable Word/Docs, Excel/Sheets and PowerPoint/Slides keys read/propose
on one file only; they cannot merge or act as account-wide sessions.

Synchronized from application 348bef9da0be3a72e1f3eeca57225d60aef71420. All six editor development
clients and the Projects UI live in that application; real-host acceptance,
structural/background sync and marketplace publication remain open. This engine
does not send invitation email. See [capabilities](docs/CAPABILITIES.md) and
[provenance service contract](docs/PROVENANCE-SYNC.md).

The application client follow-up 8c7461d adds checked date-only Excel/Sheets
observations to that same contract. Native conversion/merged-cell checks stay in
the application; service source and schema remain unchanged. See
[current capabilities](docs/CAPABILITIES.md#date-only-application-clients---6-october-2026)
for the implementation boundary and remaining acceptance work.

## Components

| Crate | Responsibility |
| --- | --- |
| `engine-shared` | IDs, events, row types and rich-text patch schema |
| `engine-core` | Append, verify, materialize, snapshots, merge and validation |
| `engine-api` | HTTP/SSE, auth and the existing document/workspace service adapter |
| `engine-cli` | Verify, replay, snapshot and generated OpenAPI |

The API adapter still contains product roles, questionnaire validation, access
hierarchies and administrative operations inherited from Dynodoc. Embedders can
use core/shared without adopting its entire HTTP product surface. These domain
boundaries are documented honestly; this extraction does not rename product code
as a fully generic distributed version-control service.

## Local development

Install Docker, Rust (the pinned `rust-toolchain.toml`) and
[Task](https://taskfile.dev/). PostgreSQL 16 is required for integration tests.

```sh
cp .env.example .env
cp migration.env.example .env.migrate
# Fill PASETO_LOCAL_KEY with `openssl rand -hex 32` and WEB_SERVICE_KEY with
# a separate random value. Task loads .env; the binaries do not read it themselves.
task up
# Create the restricted login and set its password as described in DATABASE-PRIVILEGES.
task migrate
task db:grant-runtime
task db:check
task run
```

The development database listens only at `127.0.0.1:5548`. `task run` checks the
schema/runtime role and listens on loopback port 8080; it never migrates. The operator
URL belongs only in `.env.migrate`, loaded by the migrate/grant tasks. `GET /healthz`
is the health check. Export separate isolated test-owner credentials as `DATABASE_URL`
for `task test`; SQLx tests need CREATE DATABASE and CREATE ROLE. Never run tests
against hosted data or start an API with the test-owner URL. See
[the full setup contract](docs/DATABASE-PRIVILEGES.md); the application-specific
`task setup`/`task dev` commands there are replaced by the copy/`task run` steps above.

```sh
task lint
task docs
cargo run --locked -p engine-cli -- openapi
# With DATABASE_URL exported (or using your .env loader):
cargo run --locked -p engine-cli -- verify DOCUMENT_UUID
cargo run --locked -p engine-cli -- replay DOCUMENT_UUID
cargo run --locked -p engine-cli -- snapshot DOCUMENT_UUID
```

See [current capabilities](docs/CAPABILITIES.md), [architecture](docs/ARCHITECTURE.md),
[API and authentication](docs/API.md),
[contributing](CONTRIBUTING.md), [security](SECURITY.md),
[code of conduct](CODE_OF_CONDUCT.md) and [roadmap](ROADMAP.md).

## Guarantees and limits

- Document appends serialize under a database lock on the document row, including
  empty histories. Events remain append-only; restore appends compensating edits.
- Structural ULIDs survive edits. Rich-text run boundaries and character offsets
  are not permanent identities. Patch counts use Unicode scalar values.
- Hash-chain verification detects inconsistent recorded chains. It cannot detect
  a privileged operator replacing the entire chain and head without an externally
  retained commitment. External anchoring is not implemented.
- Independent supported edits merge; ambiguous or overlapping edits require an
  explicit resolution. No CRDT, offline replica or Git wire protocol is supplied.
- Administrative whole-document erasure is an explicit product operation and
  removes its history. Erased history cannot subsequently be verified.

## License and origin

MIT; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Relicensing of this extraction was
expressly authorized by the copyright owner. Third-party libraries remain under
their respective licenses. The source application's license is unchanged.
