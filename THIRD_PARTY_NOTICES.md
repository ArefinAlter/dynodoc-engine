# Third-party dependencies

This repository does not vendor dependency source, fonts, Office assets or browser
libraries. Rust dependency versions and checksums are recorded in Cargo.lock.
Their licenses are separate from the project's MIT license and must be retained
when distributing builds or dependency source. Inspect the exact dependency graph
with `cargo metadata --locked --format-version 1` and the downloaded crates'
LICENSE/NOTICE files. This file is not a replacement license for dependencies.

The extracted rich-text compatibility fixture is original project test data. The
source origin and owner-authorized relicensing are recorded in NOTICE.
