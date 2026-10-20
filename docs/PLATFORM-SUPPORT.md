# Platform and processor support

Status: written 21 October 2026 from the runs listed below. It states what a run
proved and nothing else. Re-read the run links before relying on a row: a row is true
for the commit it names.

The policy behind this page is decision 016 of the Dynodoc product repository
(20 October 2026): the engine, command line and servers run with full feature parity
on the processors people use (Intel/AMD and Arm, including Apple silicon).

## Support matrix

| Platform | Tier | Runner label (image) | Built and tested on every change | Prebuilt `engine-cli` / `engine-api` |
| --- | --- | --- | --- | --- |
| Linux x86-64 | 1 | `ubuntu-latest` | [`ci.yml`](../.github/workflows/ci.yml) | yes (`x86_64-unknown-linux-gnu`) |
| Linux aarch64 | 1 | `ubuntu-24.04-arm` | [`platforms.yml`](../.github/workflows/platforms.yml) | yes (`aarch64-unknown-linux-gnu`) |
| macOS aarch64 (Apple silicon) | 1 | `macos-latest` | `platforms.yml` | yes (`aarch64-apple-darwin`) |
| macOS x86-64 | 1 | `macos-15-intel` | `platforms.yml` | yes (`x86_64-apple-darwin`) |
| Windows x86-64 | 1 | `windows-latest` | `platforms.yml` | yes (`x86_64-pc-windows-msvc`) |
| Windows aarch64 | 2 | `windows-11-arm` | `platforms.yml`, non-blocking (`continue-on-error`) | yes (`aarch64-pc-windows-msvc`) |

Tier 1 means a failing build or test on that platform fails the workflow. Tier 2
means the platform is built and tested, a failure is reported but does not block, and
nothing stronger is promised. Not supported: 32-bit targets, RISC-V, big-endian,
musl (the Linux binaries link glibc), and any Linux distribution older than the glibc
floor below.

## What CI verifies

@RESULTS@

## Excluded or different in CI, and why

@EXCLUSIONS@

## Platform differences and how each is tested

| Behaviour | Linux | macOS | Windows | Test |
| --- | --- | --- | --- | --- |
| Device key held by the OS (`device keygen --keystore`) | Secret Service through `secret-tool` (needs `libsecret-tools` and a running Secret Service such as gnome-keyring; otherwise refused with a pointer to the passphrase mode) | login keychain through `/usr/bin/security`, secret sent on stdin | DPAPI (`CryptProtectData`, current user, no UI); the protected blob lives in the key file | `keystore.rs` unit tests (commands carry no secret in arguments, absent tool is a clear error, DPAPI binds account and entropy); `tests/native_keystore.rs` drives the real binary against the real store, see below |
| Owner-only key and token files | mode `0600` set at creation; loaders refuse group/other access | same | one-entry access list set with `icacls` and verified; creation fails closed | `private_file.rs` unit tests, `tests/key_files.rs`, `device.rs` and `sync` tests |
| Secret files for the API (`NAME_FILE`) and at-rest KEK files | group/other access refused unless `DYNODOC_ALLOW_OPEN_SECRET_FILES=true` | same | **not checked** (no mode bits); protect the folder with an access list | `secrets.rs` and `at_rest/provider.rs` tests (Unix only) |
| Paths | case sensitive; no restriction on characters | case insensitive APFS by default; normalisation-insensitive names | case insensitive; drive letters; either slash accepted; code-page output from child tools | `tests/platform_behaviour.rs`: spaces, Bengali letters, `..` segments, forward slashes, relative paths, and an existing key is never overwritten even through another letter case |
| Line endings | LF | LF | `core.autocrlf=true` checks files out as CRLF; `migrations/*.sql` are pinned to LF by `.gitattributes` (SQLx hashes the bytes) | the Windows jobs check out with CRLF on purpose; generated `openapi.yaml` is compared to the checked-out one ignoring CR and must itself contain no CR; `platform_behaviour.rs` opens a key with a CRLF passphrase file and checks that the key file is written byte for byte |
| Hidden passphrase prompt | `stty -echo` on the terminal | same | console mode API | **not exercised in CI** (needs a terminal); passphrase files are the tested path |
| PostgreSQL for the tests | `postgres:16` service container | Homebrew `postgresql@16`, `en_US.UTF-8` | see the matrix of runs | each job logs `select version()`, encoding and collation |

### The real key store test

`crates/engine-cli/tests/native_keystore.rs` is marked `#[ignore]` because it writes to
the signed-in user's key store. The platform workflow prepares a throwaway store and
runs it with `--ignored`. It creates a key with `device keygen --encrypt --keystore`,
reads the public key back through the store, then unprotects the key and proves the
store entry is gone (a copy of the encrypted file must no longer open; on Windows the
DPAPI blob stays in the file, so the copy keeps opening for the same account). Every
child process has a 60 second limit so a surprise prompt fails instead of hanging.

- macOS: a temporary keychain is created and unlocked, becomes the only entry of the
  search list and the default keychain, and is deleted afterwards; the login keychain
  is restored and checked for leftovers.
- Linux: a private D-Bus session (`dbus-run-session`) with a fresh, unlocked
  gnome-keyring; nothing outside the job is touched.
- Windows: DPAPI needs no preparation.

To run it by hand against your own key store, accept that it creates and deletes one
`dynodoc-key-v1` entry: `cargo test -p engine-cli --test native_keystore -- --ignored`.

## Verify a downloaded release

Each `cli-v*` release has one archive per target and a `SHA256SUMS` file. Archives
hold `engine-cli`, `engine-api`, `LICENSE` and a short `README.md`.

```sh
sha256sum --check --ignore-missing SHA256SUMS      # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing        # macOS
```

```powershell
Get-FileHash .\dynodoc-engine-cli-<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

Then `engine-cli --version`. `engine-api` has no `--version`; started with no
configuration it exits with a list of the missing settings, which is the smoke test the
release workflow uses.

**The binaries are not signed or notarised.** The project has no code-signing
certificate yet. A checksum shows that a file is the one the workflow built; it does
not show who wrote the source.

- macOS Gatekeeper blocks a downloaded unsigned binary. After the checksum matches, run
  `xattr -d com.apple.quarantine engine-cli engine-api` or open it once with a right
  click, then Open. A file fetched with `curl` carries no quarantine flag.
- Windows SmartScreen shows an unknown-publisher warning. After the checksum matches,
  choose More info, then Run anyway.
- Linux shows no warning; `chmod +x` the files.

What a release binary needs from the system:

@BINARIES@

## Releases

`.github/workflows/release-cli.yml` runs on a pushed tag `cli-v*` and on manual
dispatch. It builds natively on a runner of each target, runs every binary it built,
repacks and runs the archive from a clean directory, and writes `SHA256SUMS`. A manual
run stops at workflow artifacts. Only a tag push creates a GitHub Release.

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
