-- Original files and editor images in an object store (roadmap Q16 default: S3-compatible with a
-- local filesystem driver; docs/decisions/037, crates/engine-api/src/object_store.rs).
--
-- With DYNODOC_OBJECT_STORE=filesystem or s3, a new row keeps a storage key, the size and the
-- SHA-256 of its bytes instead of the bytes. A row holds its bytes in exactly one place, and its
-- key is bound to the row: an original's key names its document and upload id, an image's its
-- document and digest, so no row can point at another document's object. Existing rows keep
-- their bytes and are read as before; nothing is moved. The default store is the database, so
-- an installation that changes no setting writes exactly what it wrote before.
--
-- Erasing a document still deletes its rows in the same transaction (migration 0017 and the
-- cascade of 0055); the API then deletes the objects the rows named.
alter table document_upload
    add column storage_key text,
    add column size bigint check (size is null or size between 0 and 20971520),
    add column sha256 bytea check (sha256 is null or octet_length(sha256) = 32),
    alter column content drop not null,
    add constraint document_upload_one_place check ((content is null) <> (storage_key is null)),
    add constraint document_upload_object_key check (storage_key is null or (
        storage_key = 'originals/' || document_id::text || '/' || replace(id::text, '-', '')
        and size is not null and sha256 is not null));

-- The size check of 0055 (size = octet_length(bytes)) was declared on the column; its generated
-- name is not part of the schema contract, so it is found by its definition.
do $$
declare
    name text;
begin
    for name in select conname from pg_constraint
                 where conrelid = 'public.connector_media'::regclass and contype = 'c'
                   and pg_get_constraintdef(oid) like '%octet_length(bytes)%' loop
        execute format('alter table public.connector_media drop constraint %I', name);
    end loop;
end $$;
alter table connector_media
    alter column bytes drop not null,
    add column storage_key text,
    add constraint connector_media_size_check
        check (size between 1 and 15728640 and (bytes is null or size = octet_length(bytes))),
    add constraint connector_media_one_place check ((bytes is null) <> (storage_key is null)),
    add constraint connector_media_object_key check (storage_key is null
        or storage_key = 'media/' || document_id::text || '/' || encode(sha256, 'hex'));
