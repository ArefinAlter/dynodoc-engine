# Local development and CLI usage

Dynodoc Engine supports two local workflows:

1. **Full local service (API + PostgreSQL):** runs `engine-api` and PostgreSQL integration tests while enforcing the two-role database privilege boundary.
2. **Local-only CLI & pure tests (no Docker/PostgreSQL):** works with local SQLite project repositories, offline verification, MCP, OpenAPI generation, and pure-Rust tests.

---

## Prerequisites

- **Rust `1.96.0`** (pinned in [`rust-toolchain.toml`](../rust-toolchain.toml), with `rustfmt` and `clippy`)
- **[Task](https://taskfile.dev/)** (`task`) — loads `.env` / `.env.migrate` for local tasks; the Rust binaries themselves do not read dotenv files
- **Docker** (only needed for PostgreSQL-backed API runs and `task test:local` / `task test`) — start the Docker engine/daemon before running `task dev:init` or `task up` (Docker Desktop on macOS/Windows, or `sudo systemctl start docker` on Linux; reboot first if Docker fails to start after a Linux kernel upgrade)

---

## Track 1: Local API + PostgreSQL

### First-time setup

```sh
task dev:init
task run
```

`task dev:init` works natively on Linux, macOS, and Windows (PowerShell) and runs the full setup idempotently:
1. `task setup` ([`scripts/dev-setup.sh`](../scripts/dev-setup.sh) on Linux/macOS, [`scripts/dev-setup.ps1`](../scripts/dev-setup.ps1) on Windows) — creates `.env` (with generated `PASETO_LOCAL_KEY`, `WEB_SERVICE_KEY`, and a local `dynodoc_runtime` password) and `.env.migrate`, never overwriting existing files.
2. `task up` — starts PostgreSQL 16 on `127.0.0.1:5548`.
3. `task db:bootstrap-runtime` ([`scripts/dev-bootstrap-runtime.sh`](../scripts/dev-bootstrap-runtime.sh) on Linux/macOS, [`scripts/dev-bootstrap-runtime.ps1`](../scripts/dev-bootstrap-runtime.ps1) on Windows) — creates/updates the restricted `dynodoc_runtime` login inside the local Compose container using stdin (no password in argv).
4. `task migrate` — applies PostgreSQL migrations using `.env.migrate`.
5. `task db:grant-runtime` — grants the explicit runtime allowlist to `dynodoc_runtime`.
6. `task db:check` — verifies schema checksums and runtime role privileges.

`task run` starts `engine-api` on `127.0.0.1:8080` (`GET /healthz`).

### Day-to-day commands

```sh
task db:upgrade   # After git pull: migrate + grant-runtime + check
task doctor       # Check toolchain, env files, and runtime DB privileges
task test:local   # Run full workspace tests against local Compose owner (port 5548)
task down         # Stop local Postgres container (keeps volume data)
task lint         # cargo fmt --check + clippy -D warnings
task docs         # cargo doc with -D warnings
task openapi      # Regenerate openapi.yaml
```

### Manual setup (without bootstrap scripts)

If you prefer not to use the `dev-setup` or `dev-bootstrap-runtime` scripts:

1. Copy `.env.example` to `.env` and `migration.env.example` to `.env.migrate`.
2. Fill `PASETO_LOCAL_KEY` (`openssl rand -hex 32`), a distinct `WEB_SERVICE_KEY` (at least 32 characters), and a password in `DATABASE_URL` inside `.env`.
3. Run `task up`.
4. Connect to `127.0.0.1:5548/dynodoc_engine` as `dynodoc` (password `local-development-only`) via `psql` and create the restricted role interactively:
   ```sql
   CREATE ROLE dynodoc_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   \password dynodoc_runtime
   ```
5. Run `task migrate`, `task db:grant-runtime`, `task db:check`, then `task run`.

---

## Track 2: Local-only CLI & pure tests (no Docker / Postgres)

Install `engine-cli` into Cargo's bin directory, or run via `task cli -- <args>`:

```sh
task install-cli
task test:unit
```

### Environment defaults (`DYNODOC_*`)

To avoid repeating paths, project UUIDs, remotes, and keys across commands, export the variables once in your shell:

```sh
export DYNODOC_REPO=./local-project.sqlite
export DYNODOC_PROJECT=11111111-1111-4111-8111-111111111111
export DYNODOC_REMOTE=./remote.json
export DYNODOC_JOURNAL=./pins.sqlite
export DYNODOC_BRANCH=main
export DYNODOC_KEY=./device-key.der
```

| Variable | Used by |
| --- | --- |
| `DYNODOC_REPO` | `engine-cli repo --repo ...`, `engine-cli historical-diff --repository ...` |
| `DYNODOC_PROJECT` | `engine-cli repo --project ...`, `engine-cli historical-diff --project ...`, `engine-cli mcp --project ...` |
| `DYNODOC_REMOTE` | `engine-cli sync --remote ...`, `engine-cli mcp --remote ...` |
| `DYNODOC_JOURNAL` | `engine-cli sync --journal ...` |
| `DYNODOC_BRANCH` | `engine-cli sync --branch ...` |
| `DYNODOC_KEY` | `engine-cli sync --device-key ...`, `engine-cli mcp --device-key ...` |

Explicit CLI flags always override environment variables.

### Shorthand `repo` vs positional `repository`

Both forms invoke the same local SQLite repository engine:

```sh
# Flag / env-backed shorthand (uses DYNODOC_REPO and DYNODOC_PROJECT when exported):
engine-cli repo init
engine-cli repo storage

# Explicit positional form (still fully supported):
engine-cli repository ./local-project.sqlite 11111111-1111-4111-8111-111111111111 init
```

---

## Credential and environment boundaries

| Surface | Credential / role | Used by | Why separate |
| --- | --- | --- | --- |
| `.env` | `dynodoc_runtime` (restricted login) | `task run`, `task db:check` | `engine-api` refuses owner/superuser roles and fails closed if `MIGRATION_DATABASE_URL` is set |
| `.env.migrate` | `dynodoc` (owner) via `MIGRATION_DATABASE_URL` | `task migrate`, `task db:grant-runtime`, `task db:upgrade` | Only operator processes may apply DDL or grant privileges |
| `task test:local` | `dynodoc` (owner) on `127.0.0.1:5548` | `cargo test --workspace` | SQLx tests create/drop disposable test databases (`CREATE DATABASE`, `CREATE ROLE`) |

See [the database runtime boundary](DATABASE-PRIVILEGES.md) for the full PostgreSQL privilege model.

---

## Troubleshooting

- **`DATABASE_URL is not set` or `MIGRATION_DATABASE_URL is required` when running `cargo run` directly:** Rust binaries do not load `.env` or `.env.migrate` automatically. Use `task db:check` / `task migrate` / `task run`, or export the variable in your shell.
- **`task test` fails with permission denied for `CREATE DATABASE`:** `.env` holds the restricted `dynodoc_runtime` login, which cannot create test databases. Run `task test:local` for local Compose tests, or export an isolated test-owner `DATABASE_URL`.
- **`check-runtime` fails after `git pull`:** A new migration was added. Run `task db:upgrade` to apply migrations and re-grant the runtime allowlist.
- **Port `5548` connection refused:** Run `task up` (or `task doctor`) to verify the local PostgreSQL container is running and healthy.
