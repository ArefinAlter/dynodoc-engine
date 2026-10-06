# Roadmap

Updated 6 October 2026. Projects and anchored retry-safe provenance bundles now
have service implementations. See [capabilities](docs/CAPABILITIES.md) and the
[portable contract](docs/PROVENANCE-SYNC.md). Application source: 2a289ce2fe5fc0071fc45596fdf39b66aca10af7.

1. Accept Word and Google Docs together in real hosts; extend structural block
   operations, formatting and cross-host conflict/retry recovery.
2. Background/local capture and portable sidecars across copies/renames/devices;
   secure pairing, signed installations and marketplace acceptance.
3. Project activity/compare/search, then consistent multi-file releases.
4. Replace duplicated application Rust sources with a pinned dependency/subtree;
   expand durable idempotency and metadata audit throughout workspace operations.
5. Independently retained chain-head commitments, measured snapshot/storage costs
   and a smaller generic service boundary with historical compatibility tests.

Editor clients, file parsing and invitation email remain application components.
Core history is serialized, centralized PostgreSQL with explicit overlap review;
no Git transport, CRDT typing, complete offline convergence or Office editor is
implemented by this standalone engine. Source publication is not deployment.
