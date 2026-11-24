# Dynodoc Engine

[![CI](https://github.com/ArefinAlter/dynodoc-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/ArefinAlter/dynodoc-engine/actions/workflows/ci.yml)
[![Platforms](https://github.com/ArefinAlter/dynodoc-engine/actions/workflows/platforms.yml/badge.svg)](https://github.com/ArefinAlter/dynodoc-engine/actions/workflows/platforms.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Semantic version control for documents edited in existing tools. Rust libraries,
a PostgreSQL HTTP service adapter, SQLite local repositories and an operator CLI
provide stable node identity, append-only operations, review and synchronization
building blocks. This MIT engine is the open-source core of Dynodoc, a product of
Verne Ltd. (Dhaka, Bangladesh). The Dynodoc workspace, website and editor
connectors are developed in a separate private repository and are not published
as open source; this repository carries the engine, HTTP API and command-line tools.

## Current state — 12 October 2026

[Shared project history](docs/SHARED-PROJECT-HISTORY.md) now adds explicit
candidate publication, reachable downloads, protected main CAS/reviews and atomic
server-signed receipts. A public authority is operator-installed, and the matching
secret must be explicitly mounted into the API. These sources are not deployed.
[Selected-history CLI sync](docs/SELECTED-HISTORY-SYNC.md) now adds reviewed
push, verified fetch, fast-forward pull and separate pinned remote tracking.
Project-scoped sign-in, UI/native adoption, server rotation/witnesses and full
native convergence/large-service acceptance remain open.

Source supports PostgreSQL migrations through 0143 (0056 to 0142 synchronized from application
`4f0e7a3` on 8 November 2026; 0143, compact v3 named snapshots, from #132 on 22 November and
not yet in the application). It adds agent sessions and project memory, ledger mode,
directory primitives for enterprise identity, history horizons with a transparency log,
encrypted projects and at-rest encryption, large-file uploads and object storage, and a
WebAssembly build of the pure engine; the [changelog](CHANGELOG.md) lists them by
decision. None of this is deployed.
Read [verified source revisions and tests](docs/ENGINE-EVOLUTION-HANDOFF.md) and the
[complete acceptance ledger](docs/ROADMAP-ACCEPTANCE.md).

| Capability | Current boundary |
|---|---|
| [Shared state](docs/TYPED-CHECKPOINTS.md) | Typed chunked objects, immutable document-scoped storage, verified mixed readers and opt-in shared periodic/draft/named/deployed/public references. Durable per-document/account encoded-object budgets are enforced. Full-state scans, resident reconstruction and physical packing remain. |
| [Local project history](docs/PORTABLE-PROJECT-HISTORY.md) | Durable signed multi-file commits, parents, branch CAS, missing-object exchange, merge bases and conservative comparison. SQLite schema 2 adds persistent local object/commit/branch capacity with an explicit CLI. Authenticated private staging, explicit shared publication, protected main CAS/review and atomic ref receipts are implemented. Selected-history CLI push/fetch, fast-forward pull and separate pinned remote tracking are available; project-scoped sign-in and editor adoption remain open. |
| [Client audit](docs/REF-RECEIPTS.md) | Signed ref receipts, independent signature fixtures, separate durable pins, authority rotation and local revocation. Account-bound device enrollment/revocation is available; atomic server issuance is implemented; authority distribution/server rotation and external witnesses remain open. |
| [Historical recovery](docs/HISTORY-RECOVERY.md) | Authorized per-file history, selected recovery and revision-range revert/cherry-pick under existing review rules. [Local project commit recovery](docs/PROJECT-COMMIT-RECOVERY.md) now adds signed revert/cherry-pick; hosted/native integration remains open. |
| [Correctness and resources](docs/VERSIONING-CONFORMANCE.md) | Fixed compatibility vectors, replay equivalence, explicit budgets and constraint-aware validation. Complete offline/native convergence and large-service capacity are not certified. |

The default shared writers remain disabled. Schema-compatible readers are
required even when the writer settings are disabled. Key imports for local
signing accept unencrypted DER Ed25519 PKCS#8 v1/v2, including OpenSSL v1 output.
Installed-host and marketplace acceptance of the editor connectors remain open.

This early 0.1 source release includes neither browser editors nor production
configuration, credentials or user documents. It does not implement the Git wire
protocol, and no crates.io package has been published. Dated implementation and
release history lives in the [handoff](docs/ENGINE-EVOLUTION-HANDOFF.md).

## Components

| Crate | Responsibility |
| --- | --- |
| `engine-shared` | IDs, events, row types and rich-text patch schema |
| `engine-core` | Append/replay/validation, typed shared state, local project history, receipts and client pins |
| `engine-agent` | Agent protocol: refs, hashes, compact text, outline/read/find/diff and the propose compiler |
| `engine-mcp` | MCP server for the agent protocol; read-only by default, writes wait for a person |
| `engine-api` | HTTP/SSE, auth and the existing document/workspace service adapter; `dynodoc-witness` transparency witness |
| `engine-cli` | Verify/migrate/snapshot, local commits/branches, receipt journals, MCP and generated OpenAPI |
| `engine-wasm` | Pure engine (hashing, fold, operations, merge) for WebAssembly hosts |

The API adapter still contains product roles, questionnaire validation, access
hierarchies and administrative operations inherited from Dynodoc. Embedders can
use core/shared without adopting its entire HTTP product surface. These domain
boundaries are documented honestly; this extraction does not rename product code
as a fully generic distributed version-control service.

## Local development and CLI usage

Install Rust (pinned via `rust-toolchain.toml`), [Task](https://taskfile.dev/), and
Docker (only needed for PostgreSQL-backed API runs and integration tests).

**Local API + PostgreSQL (`127.0.0.1:5548` → API on `127.0.0.1:8080`, or next free port if `8080` is busy):**

Start the Docker engine/daemon before running `task dev:init` or any PostgreSQL-backed
task (open Docker Desktop on macOS/Windows, or run `sudo systemctl start docker` on
Linux; if Docker fails to start after a Linux kernel upgrade, reboot first).

```sh
task dev:init      # Generates .env/.env.migrate, starts Postgres, bootstraps dynodoc_runtime, migrates, grants, checks
task run           # Starts engine-api (GET /healthz); never runs migrations
task test:local    # Runs full workspace tests against the local Compose owner
task db:upgrade    # After git pull: migrate + grant-runtime + check
```

**Local-only CLI & pure tests (no Docker/PostgreSQL):**

```sh
task install-cli   # Installs engine-cli into Cargo's bin directory (or use `task cli -- <args>`)
task test:unit     # Runs pure-Rust and CLI unit tests
engine-cli repo --help
```

`engine-cli` commands (`repo`, `sync`, `historical-diff`, `mcp`) read `DYNODOC_REPO`,
`DYNODOC_PROJECT`, `DYNODOC_REMOTE`, `DYNODOC_JOURNAL`, `DYNODOC_BRANCH`, and `DYNODOC_KEY`
when flags are omitted. `engine-api` enforces strict credential separation: `.env` holds
only the restricted `dynodoc_runtime` login, `.env.migrate` holds `MIGRATION_DATABASE_URL`,
and `task test:local` uses an isolated test-owner URL. Never run tests against hosted data
or pass `MIGRATION_DATABASE_URL` to `engine-api`.

```sh
task lint
task docs
task openapi
# With DATABASE_URL exported (or via `task cli -- ...`):
engine-cli verify DOCUMENT_UUID
engine-cli replay DOCUMENT_UUID
engine-cli snapshot DOCUMENT_UUID
```

See [local development and CLI usage](docs/LOCAL-DEVELOPMENT.md),
[database privileges](docs/DATABASE-PRIVILEGES.md),
[current capabilities](docs/CAPABILITIES.md), [architecture](docs/ARCHITECTURE.md),
[API and authentication](docs/API.md),
[contributing](CONTRIBUTING.md), [security](SECURITY.md),
[code of conduct](CODE_OF_CONDUCT.md) and [roadmap](ROADMAP.md).

## Platforms and prebuilt binaries

The engine, API and command line are built and tested on Linux, macOS and Windows,
on x86-64 and on Arm (aarch64), by GitHub-hosted runners on every change
([platform workflow](.github/workflows/platforms.yml)). Windows on Arm is tier 2.
Tagged `cli-v*` releases attach `engine-cli` and `engine-api` archives for all six
OS and processor pairs with a `SHA256SUMS` file; they are not code-signed, so
macOS Gatekeeper and Windows SmartScreen will warn. The support matrix, what CI
proves, what is excluded, platform differences and how to verify a download are in
[PLATFORM-SUPPORT.md](docs/PLATFORM-SUPPORT.md).

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
