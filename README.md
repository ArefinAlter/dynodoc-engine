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

See [architecture](docs/ARCHITECTURE.md), [API and authentication](docs/API.md),
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
