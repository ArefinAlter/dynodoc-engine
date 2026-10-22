# Dynodoc engine command-line tools

This archive holds two programs built from the public engine source
(https://github.com/ArefinAlter/dynodoc-engine, MIT licence, see `LICENSE`):

- `engine-cli`: the operator and local-repository command line (`engine-cli --help`).
- `engine-api`: the HTTP/SSE service. It refuses to start without its configuration
  and needs PostgreSQL 16 (see the repository README and `docs/DATABASE-PRIVILEGES.md`).

Check the download first. The release page has a `SHA256SUMS` file:

    sha256sum --check --ignore-missing SHA256SUMS      (Linux)
    shasum -a 256 -c SHA256SUMS --ignore-missing        (macOS)
    Get-FileHash <archive> -Algorithm SHA256            (Windows; compare by eye)

Then run `engine-cli --version`.

## These binaries are not signed

The project has no code-signing certificate yet, so the operating system will warn:

- **macOS**: Gatekeeper blocks a downloaded, unsigned, un-notarised binary. After you
  have verified the checksum, remove the quarantine flag
  (`xattr -d com.apple.quarantine engine-cli engine-api`) or open it once with a right
  click, Open. Programs fetched with `curl` carry no quarantine flag.
- **Windows**: SmartScreen will say the publisher is unknown. Choose More info, Run
  anyway, only after verifying the checksum.
- **Linux**: no warning; make sure the file is executable (`chmod +x`).

A checksum proves the file is the one the workflow built. It does not prove who wrote
the source; that is what signing will add later.

## Platforms

Linux (x86-64, aarch64; glibc, the minimum is listed on the release page), macOS 11 or
newer (Intel and Apple silicon), Windows 10 or newer (x86-64 and aarch64). Windows
binaries carry their C runtime and need no Visual C++ redistributable. The full
support matrix, what CI verifies and the known limits are in `docs/PLATFORM-SUPPORT.md`
in the source repository.
