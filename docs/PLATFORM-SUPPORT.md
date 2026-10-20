# Platform and processor support

Status: written 21 October 2026 from the CI runs linked below. It states what a run
proved and nothing else. A row is true for the commit its run names; re-read the run
before relying on it.

The policy behind this page is decision 016 of the Dynodoc product repository
(20 October 2026): the engine, command line and servers run with full feature parity
on the processors people use (Intel/AMD and Arm, including Apple silicon).

## Support matrix

| Platform | Tier | Runner label | Built and tested on every change | Prebuilt `engine-cli` and `engine-api` |
| --- | --- | --- | --- | --- |
| Linux x86-64 | 1 | `ubuntu-latest` | [`ci.yml`](../.github/workflows/ci.yml) | `x86_64-unknown-linux-gnu` |
| Linux aarch64 | 1 | `ubuntu-24.04-arm` | [`platforms.yml`](../.github/workflows/platforms.yml) | `aarch64-unknown-linux-gnu` |
| macOS aarch64 (Apple silicon) | 1 | `macos-latest` | `platforms.yml` | `aarch64-apple-darwin` |
| macOS x86-64 | 1 | `macos-15-intel` | `platforms.yml` | `x86_64-apple-darwin` |
| Windows x86-64 | 1 | `windows-latest` | `platforms.yml` | `x86_64-pc-windows-msvc` |
| Windows aarch64 | 2 | `windows-11-arm` | `platforms.yml`, non-blocking (`continue-on-error`) | `aarch64-pc-windows-msvc` |

Tier 1: a failing build or test on that platform fails the workflow. Tier 2: built
and tested, a failure is reported but does not block, nothing stronger is promised.
Not supported: 32-bit targets, RISC-V, big-endian, musl (the Linux binaries link
glibc), and Linux distributions older than the glibc floor listed below.

## What CI verifies

Evidence run: [engine-platforms 39488859505](https://github.com/ArefinAlter/dynodoc-engine/actions/runs/39488859505)
(commit `e2c1055`). Every job builds with `cargo build --workspace --locked`, runs
`cargo test --workspace --locked --no-fail-fast` against PostgreSQL, regenerates
`openapi.yaml` and compares it, and exercises the real operating-system key store.
Tests run one at a time (`RUST_TEST_THREADS=1`, as in `ci.yml`) with
`CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_INCREMENTAL=0`.

@RESULTS@

Earlier runs of the same workflow that informed the fixes below:
[39470062867](https://github.com/ArefinAlter/dynodoc-engine/actions/runs/39470062867),
[39472623633](https://github.com/ArefinAlter/dynodoc-engine/actions/runs/39472623633),
[39477250840](https://github.com/ArefinAlter/dynodoc-engine/actions/runs/39477250840),
[39482886733](https://github.com/ArefinAlter/dynodoc-engine/actions/runs/39482886733).

## Excluded or different in CI, and why

@EXCLUSIONS@

## Platform differences and how each is tested

| Behaviour | Linux | macOS | Windows | Test |
| --- | --- | --- | --- | --- |
| Device key held by the OS (`device keygen --keystore`) | Secret Service through `secret-tool` (needs `libsecret-tools` and a running Secret Service such as gnome-keyring; otherwise refused with a pointer to the passphrase mode) | login keychain through `/usr/bin/security`, secret sent on stdin | DPAPI (`CryptProtectData`, current user, no UI); the protected blob lives in the key file | `keystore.rs` unit tests (no secret in command arguments, absent tool is a clear error, DPAPI binds account and entropy); `tests/native_keystore.rs` drives the real binary against the real store |
| Owner-only key and token files | mode `0600` set at creation; loaders refuse group or other access | same | a one-entry access list set with `icacls` and verified, creation fails closed | `private_file.rs` unit tests (including the two Windows cases below), `tests/key_files.rs`, `device.rs` and `sync` tests |
| Secret files for the API (`NAME_FILE`) and at-rest KEK files | group or other access refused unless `DYNODOC_ALLOW_OPEN_SECRET_FILES=true` | same | **not checked** (no mode bits); protect the folder with an access list | `secrets.rs` and `at_rest/provider.rs` tests (Unix only) |
| Paths | case sensitive; any byte except `/` | case insensitive on APFS by default; names are normalisation-insensitive | case insensitive; drive letters; either slash accepted; child tools print in the console code page | `tests/platform_behaviour.rs`: spaces, Bengali letters, `..` segments, forward slashes, relative paths; an existing key is never overwritten, even through another letter case |
| Line endings | LF | LF | `core.autocrlf=true` checks files out as CRLF; `migrations/*.sql` and `integrations/**` are pinned to LF by `.gitattributes` (SQLx hashes the migration bytes; a test requires LF plugin files) | the Windows jobs check out with CRLF on purpose; the generated `openapi.yaml` must contain no CR and match the checked-out one ignoring CR; `platform_behaviour.rs` opens a key with a CRLF passphrase file (one line ending is removed, a second is part of the passphrase) and checks that key files are written byte for byte |
| Hidden passphrase prompt | `stty -echo` on the terminal | same | console mode API | **not exercised in CI** (needs a terminal); passphrase files are the tested path |
| PostgreSQL used by the tests | `postgres:16` service container | Homebrew `postgresql@16`, `en_US.UTF-8` | see the results table | every job logs `select version()`, encoding and collation |

### The real key store test

`crates/engine-cli/tests/native_keystore.rs` is marked `#[ignore]` because it writes to
the signed-in user's key store; the platform workflow prepares a throwaway store and
runs it with `--ignored`. It creates a key with `device keygen --encrypt --keystore`,
opens it again through the store (`device public-key`), then unprotects it and proves
the stored secret is gone: a copy of the encrypted file must no longer open. On
Windows the DPAPI blob lives in the file, so the copy keeps opening for the same
account. Each child process is killed after 60 seconds so a surprise prompt fails the
test instead of hanging the job.

- macOS: a temporary keychain is created and unlocked, becomes the only entry of the
  search list and the default keychain, and is deleted afterwards. A following step
  checks that nothing was written to the login keychain. It worked headless on both
  macOS images without any prompt.
- Linux: `dbus-run-session` with a fresh, unlocked gnome-keyring; nothing outside the
  job is touched. Run on aarch64 and on x86-64.
- Windows: DPAPI needs no preparation.

To run it against your own key store (it creates and deletes one `dynodoc-key-v1`
entry): `cargo test -p engine-cli --test native_keystore -- --ignored`.

### Bugs this work found and fixed

All three were found by running on a real runner, none by reading code.

1. **Windows, non-ASCII key path.** `icacls` prints in the console code page, so a
   Bengali or accented folder name came back as `?` and `device keygen`, `protect`
   and the sync token files failed closed with "unrecognised icacls output" for any
   such path or user name. The verification now compares the user name by its ASCII
   letters when the path or name is not ASCII (`private_file.rs`). Test:
   `platform_behaviour.rs::key_paths_with_spaces_bengali_letters_...` runs the real
   binary on a Bengali path; unit test with synthetic `icacls` output.
2. **Windows, elevated token.** A process running as Administrator creates files that
   already carry explicit SYSTEM and Administrators entries; dropping inheritance left
   them and the one-entry check refused every key and token file (12 tests failed on
   the runner). `icacls` now also removes those two by well-known SID in the same call
   (`private_file.rs`). Test: a Windows-only test reproduces the state.
3. **Windows checkout, plugin files.** A default Windows clone turned the Claude Code
   plugin files (`integrations/`) into CRLF and `mcp_plugin.rs` rejected them.
   `.gitattributes` now pins `integrations/**` to LF.

## Verify a downloaded release

Each `cli-v*` release has one archive per target and a `SHA256SUMS` file. An archive
holds `engine-cli`, `engine-api`, `LICENSE` and a short `README.md`.

```sh
sha256sum --check --ignore-missing SHA256SUMS      # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing        # macOS
```

```powershell
Get-FileHash .\dynodoc-engine-cli-<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

Then `engine-cli --version`. `engine-api` has no `--version`; started with no
configuration it exits with the list of missing settings, which is the smoke test the
release workflow uses.

**The binaries are not signed or notarised.** The project has no code-signing
certificate yet. A checksum shows that a file is the one the workflow built; it does
not show who wrote the source.

- macOS Gatekeeper blocks a downloaded unsigned binary. After the checksum matches, run
  `xattr -d com.apple.quarantine engine-cli engine-api`, or open it once with a right
  click and Open. A file fetched with `curl` carries no quarantine flag.
- Windows SmartScreen shows an unknown-publisher warning. After the checksum matches,
  choose More info, then Run anyway.
- Linux shows no warning; `chmod +x` the files.

@BINARIES@

## Releases

[`release-cli.yml`](../.github/workflows/release-cli.yml) runs on a pushed tag `cli-v*`
and on manual dispatch. It builds natively on a runner of each target, runs every
binary it built, unpacks the archive into a clean directory and runs that too, and
writes `SHA256SUMS`. A manual run stops at workflow artifacts (kept 30 days). Only a
tag push creates a GitHub Release; that last step has not been exercised, see below.

@RELEASE@

## Known limits

@LIMITS@

## Running the checks yourself

```sh
cargo build --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked          # needs DATABASE_URL for PostgreSQL 16 (README)
cargo test -p engine-cli --test platform_behaviour
cargo test -p engine-cli --test native_keystore -- --ignored   # writes to your key store
```
