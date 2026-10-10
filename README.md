# Dynodoc Engine

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

## Current increment: bounded checkpoint encoding (10 October 2026)

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
# Fill PASETO_LOCAL_KEY with `openssl rand -hex 32` and WEB_SERVICE_KEY with
# a separate random value. Task loads .env; the binaries do not read it themselves.
task up
task test
task run
```

The development database listens only at `127.0.0.1:5548`. `task run` applies the
bundled migrations and listens on loopback port 8080. `GET /healthz` is the health
check. Use a database role with CREATE DATABASE for SQLx integration tests; each
`#[sqlx::test]` creates an isolated database. Never run tests against hosted data.

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
