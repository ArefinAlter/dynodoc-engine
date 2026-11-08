-- Objects an erasure left to delete (docs/decisions/043-platform-third-part.md section 5).
--
-- Erasing a document deletes its rows in one transaction; the bytes in an object store
-- (DYNODOC_OBJECT_STORE=filesystem or s3, migration 0113) can only be deleted after the commit.
-- The same transaction now queues each key here, the API deletes it right after the commit and
-- removes the row, and a periodic sweep retries whatever is left (a failed delete, a crash between
-- commit and delete), so no erased document's bytes outlive their erasure by more than a sweep.
-- A key names only an erased document's id and an upload id or digest: never content.
create table object_deletion (
    storage_key text primary key check (char_length(storage_key) between 1 and 200),
    queued_at timestamptz not null default now(),
    attempts integer not null default 0 check (attempts >= 0),
    next_attempt_at timestamptz not null default now()
);
create index object_deletion_due_idx on object_deletion(next_attempt_at);
