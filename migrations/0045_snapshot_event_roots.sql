-- Existing immutable snapshots remain NULL; do not backfill canonical rows.
alter table snapshot add column event_merkle_root bytea
    check (event_merkle_root is null or octet_length(event_merkle_root) = 32);
-- Versions 1/2 keep their exact historical envelope. Versions 3/4 also bind the
-- event-prefix root for inline/shared-state snapshots respectively.
alter table snapshot_verification drop constraint snapshot_verification_version_check;
alter table snapshot_verification add constraint snapshot_verification_version_check
    check (version in (1, 2, 3, 4));
