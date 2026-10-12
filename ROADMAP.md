# Roadmap

Updated 6 October 2026. Projects and anchored retry-safe provenance bundles now
have service implementations. See [capabilities](docs/CAPABILITIES.md) and the
[portable contract](docs/PROVENANCE-SYNC.md). Application source: 348bef9da0be3a72e1f3eeca57225d60aef71420.

1. Accept Word/Docs, Excel/Sheets and PowerPoint/Slides in real hosts; extend structural block
   operations, formatting and cross-host conflict/retry recovery.
2. Background/local capture and automatic discovery across copies/renames/devices;
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

All six development clients now share field-level capture, frozen retries and
explicit sidecar recovery in the application. Spreadsheet cells, date-only values/formulas and
slide shape text are initial supported projections, not full format coverage.

The date-only client follow-up is application 8c7461d. Its native calendar/timezone
checks are application code; timestamps, formula/date formatting compatibility
and installed-host acceptance remain open. Service source/migrations are unchanged.
