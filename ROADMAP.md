# Roadmap

Implemented: serialized append-only event chains, replay/snapshots, stable IDs,
compact formatting-aware patches, three-way merge, draft/version service APIs,
permission checks and integration tests.

Next: independent signed chain-head commitments; durable idempotency across all
workspace operations; measured snapshot/storage improvements; finer attribution;
separation of questionnaire/hosted administration adapters from a smaller service;
portable history exchange and a compatibility/versioning policy for external users.

Offline replication, CRDT typing, Git transport and Office editors are not currently
implemented by this engine. Dates and delivery commitments are not assigned.
