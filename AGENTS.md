# Working on Dynodoc Engine

Read README.md, CONTRIBUTING.md and docs/ARCHITECTURE.md before changing the engine.
Preserve stable IDs, historical event readers and append-only canonical content.
Never edit applied migrations; add a new numbered migration.
Use isolated local databases for all tests. Do not read or publish credentials,
user documents or production data. Run task lint and task test for Rust changes.
Regenerate openapi.yaml when API schemas change. Keep patches focused and record
compatibility limits honestly. This repository is MIT licensed; dependency licenses
remain separate. The hosted product and frontend live in ArefinAlter/dynodoc.

Current owner direction (10 October 2026): local/remote document provenance and
review around existing editors. Read docs/PRODUCT-SPEC.md, docs/ENGINE-EVOLUTION-PLAN.md,
docs/PROJECT-STATUS.md and docs/ENGINE-EVOLUTION-HANDOFF.md. Shared storage, offline
history/convergence and stronger independent audit are authorized staged work;
questionnaire/civic plans are not the current roadmap. Preserve compatibility and
update status/handoff with source commits and actual checks at every increment.
