-- Migration 0050: Set LZ4 compression on high-volume JSONB columns
-- (event.payload, snapshot.state, and node.current_fields).
--
-- Preserves existing rows, append-only triggers, and historical event digests.
-- Only newly toasted values will be compressed using LZ4.
-- Requires PostgreSQL 14+ compiled with LZ4 support.

DO $$
BEGIN
    BEGIN
        CREATE TEMP TABLE _test_lz4_support (val text COMPRESSION lz4) ON COMMIT DROP;
    EXCEPTION WHEN feature_not_supported OR undefined_object THEN
        RAISE EXCEPTION 'PostgreSQL was built without LZ4 support (requires PostgreSQL 14+ compiled with --with-lz4)';
    END;
END $$;

ALTER TABLE public.event ALTER COLUMN payload SET COMPRESSION lz4;
ALTER TABLE public.snapshot ALTER COLUMN state SET COMPRESSION lz4;
ALTER TABLE public.node ALTER COLUMN current_fields SET COMPRESSION lz4;
