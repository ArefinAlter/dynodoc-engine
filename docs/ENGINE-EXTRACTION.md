# Standalone engine synchronization

The engine is MIT-licensed source extracted from the AGPL Dynodoc application
with the copyright owner?s authorization. It contains core/shared, HTTP API and
operator CLI crates and compatible migrations. It has no dependency on the
application checkout, production configuration or credentials.

Current implementation is `80cd148`, aligned with application release `858801c`
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
