# Standalone engine synchronization

Latest storage synchronization (12 October 2026): engine `746d373` mirrors
application `3462520` for the streaming byte-content codec, fixed vectors, tests
and benchmark. See [the contract](CHUNKED-CONTENT.md) and
[verification/handoff](ENGINE-EVOLUTION-HANDOFF.md). This adds an internal storage
primitive; it does not change deployed snapshots, schema or published branches.

Latest test synchronization: engine PR #7 (`e31f093`, merged `d6be03a`)
is mirrored byte-for-byte in application `648aa27`. The v1 event fixture
and regression test do not change runtime behavior or schema. See
[verification and handoff](ENGINE-EVOLUTION-HANDOFF.md). The runtime
synchronization and release below remain the deployed baseline.

The engine is MIT-licensed source extracted from the AGPL Dynodoc application
with the copyright owner?s authorization. It contains core/shared, HTTP API and
operator CLI crates and compatible migrations. It has no dependency on the
application checkout, production configuration or credentials.

Deployed baseline implementation is `80cd148`, aligned with application release `858801c`
at schema 29. Both pass 275 Rust tests and CI. See [hosted release evidence](operations/2026-10-11-security-runtime-release.md)
and [current capabilities and remaining work](ENGINE-EVOLUTION-HANDOFF.md).

Intentional repository differences are MIT package/OpenAPI metadata, independent
rich-text fixture paths and Rust 1.96?s equivalent integer parity method. Keep
these differences when synchronizing; do not overwrite the standalone manifests
or toolchain conventions with application copies. Migration bytes and event
semantics remain compatible.

The [application extraction record](https://github.com/ArefinAlter/dynodoc/blob/main/docs/ENGINE-EXTRACTION.md)
contains the historical source/publication details. No crates.io publication,
Git protocol compatibility, complete offline repository or complete Office
round-trip guarantee is implied by this source release.
