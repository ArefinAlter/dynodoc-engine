# Working on Dynodoc Engine

Read README.md, CONTRIBUTING.md and docs/ARCHITECTURE.md before changing the engine.
Preserve stable IDs, historical event readers and append-only canonical content.
Never edit applied migrations; add a new numbered migration.
Use isolated local databases for all tests. Do not read or publish credentials,
user documents or production data. Run task lint and task test for Rust changes.
Regenerate openapi.yaml when API schemas change. Keep patches focused and record
compatibility limits honestly. This repository is MIT licensed; dependency licenses
remain separate. The hosted product and frontend live in ArefinAlter/dynodoc.
