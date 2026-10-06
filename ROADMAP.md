# Roadmap

Updated 6 October 2026. See [current capabilities](docs/CAPABILITIES.md) for the
implementation and boundaries synchronized from Dynodoc application `52c2447`.

Implemented: serialized append-only event chains, replay/snapshots, stable IDs,
compact formatting-aware patches, three-way and strict unrelated-content merge,
private drafts and named versions; change requests, role/rule checks, approvals,
copy fingerprints/detection, in-app notification APIs and integration tests.

| Priority | Work | Completion evidence |
| --- | --- | --- |
| 1 | Keep the hosted and standalone engine compatible; replace duplicate sources with a pinned dependency/subtree in a separate application build change. | Independent builds, identical historical migration blobs, golden replay and API consistency. |
| 2 | Durable idempotency/retry behavior throughout workspace operations; strengthen metadata/access audit. | Retry/restart/concurrent-request regressions without duplicate mutations or lost access checks. |
| 3 | Independently retained/signed chain-head commitments. | Detect privileged full-history replacement using an external commitment, not just self-consistent database hashes. |
| 4 | Profile snapshot/storage/materialization and improve attribution. | Reproducible workloads, bounded memory/storage, deterministic replay and old-reader compatibility. |
| 5 | Smaller generic service boundary, portable history exchange and external compatibility policy. | Keep questionnaire/hosted admin adapters explicit; test supported historical imports and version negotiation. |

The next hosted product milestone is the approved GitHub-style Projects workspace;
its project kind, aggregate APIs, policy inheritance and Watch are not yet built.
Core per-document primitives already support the current file workflow. Browser
editors, file conversion, invitation delivery and Projects navigation belong to the
application; shared API/schema additions should be synchronized explicitly.

Offline replication, CRDT typing, Git transport, AI agent provenance and Office
editors are not implemented by this engine. Dates and delivery commitments are
not assigned.
