# Write-state cache: validation before reuse

Opt-in verified prefix caching for document writes via `DYNODOC_WRITE_STATE_CACHE=on`
(default off). Replaces repeated replay of long event tails on active documents.

## Contract and invalidation

- **Bounds**: Max 64 document states, 32 MiB total serialized state, 16 MiB per entry, 5-minute TTL.
- **Locking & Auth**: Role checks and document/project row locks run before every cache access; authorization is never cached.
- **Coherence**: Under document lock, reuse requires matching document ID, sequence, chain hash, checkpoint, and receipt. To detect direct SQL modifications to tail rows, a SHA-256 token binds tail sequence numbers and PostgreSQL tuple versions (`xmin`, `ctid`). Any discrepancy invalidates the entry and falls back to the checked reader.
- **Bypass**: Shared checkpoints and shared-storage snapshots bypass the cache.
- **Fail-safe**: Rollbacks, restarts, or poisonings evict entries immediately.

## Performance baseline vs cached (debug build, local PostgreSQL 16)

Median of 9 runs on 500-event tail (`benchmarks/write-state-cache-comparison-2026-10-21.json`):

| Blocks | Checked read | Cached read | Warm unchanged |
| --- | ---: | ---: | ---: |
| 1,000 | 110.96 ms | 23.47 ms | 3.94 ms |
| 8,000 | 803.52 ms | 215.93 ms | 29.83 ms |
