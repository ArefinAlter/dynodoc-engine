# Dynodoc Engine

[![CI](https://github.com/ArefinAlter/dynodoc-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/ArefinAlter/dynodoc-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Semantic version control for documents edited in existing tools. Rust libraries,
a PostgreSQL HTTP service adapter, SQLite local repositories and an operator CLI
provide stable node identity, append-only operations, review and synchronization
building blocks. This MIT engine is extracted from the
[Dynodoc application](https://github.com/ArefinAlter/dynodoc), which contains the
Projects frontend and Word/Docs, Excel/Sheets and PowerPoint/Slides connectors.

## Current state — 12 October 2026

Source supports PostgreSQL schema 34. The hosted application remains at schema 29
and release `858801c`; these new storage and audit capabilities are not deployed.
Read [verified source revisions and tests](docs/ENGINE-EVOLUTION-HANDOFF.md) and the
[complete acceptance ledger](docs/ROADMAP-ACCEPTANCE.md).

| Capability | Current boundary |
|---|---|
| [Shared state](docs/TYPED-CHECKPOINTS.md) | Typed chunked objects, immutable document-scoped storage, verified mixed readers and opt-in shared periodic/draft/named/deployed/public references. Durable per-document/account encoded-object budgets are enforced. Full-state scans, resident reconstruction and physical packing remain. |
| [Local project history](docs/PORTABLE-PROJECT-HISTORY.md) | Durable signed multi-file commits, parents, branch CAS, missing-object exchange, merge bases and conservative comparison. SQLite schema 2 adds persistent local object/commit/branch capacity with an explicit CLI. Hosted project transport/review and editor adoption remain open. |
| [Client audit](docs/REF-RECEIPTS.md) | Signed ref receipts, independent signature fixtures, separate durable pins, authority rotation and local revocation. Account-bound device enrollment/revocation is available; atomic server issuance and external witnesses remain open. |
| [Historical recovery](docs/HISTORY-RECOVERY.md) | Authorized per-file history, selected recovery and revision-range revert/cherry-pick under existing review rules. [Local project commit recovery](docs/PROJECT-COMMIT-RECOVERY.md) now adds signed revert/cherry-pick; hosted/native integration remains open. |
| [Correctness and resources](docs/VERSIONING-CONFORMANCE.md) | Fixed compatibility vectors, replay equivalence, explicit budgets and constraint-aware validation. Complete offline/native convergence and large-service capacity are not certified. |

The default shared writers remain disabled. Schema-compatible readers are
required even when the writer settings are disabled. Key imports for local
signing accept unencrypted DER Ed25519 PKCS#8 v1/v2, including OpenSSL v1 output.
The [native-host worksheet](https://github.com/ArefinAlter/dynodoc/blob/main/extensions/ACCEPTANCE.md)
is prepared for the owner to run; installed-host and marketplace acceptance remain open.

This early 0.1 source release includes neither browser editors nor production
configuration, credentials or user documents. It does not implement the Git wire
protocol, and no crates.io package has been published. Dated implementation and
release history lives in the [handoff](docs/ENGINE-EVOLUTION-HANDOFF.md).

## Components

| Crate | Responsibility |
| --- | --- |
| `engine-shared` | IDs, events, row types and rich-text patch schema |
| `engine-core` | Append/replay/validation, typed shared state, local project history, receipts and client pins |
| `engine-api` | HTTP/SSE, auth and the existing document/workspace service adapter |
| `engine-cli` | Verify/migrate/snapshot, local commits/branches, receipt journals and generated OpenAPI |

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
