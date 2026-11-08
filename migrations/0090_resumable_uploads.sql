-- Resumable, hash-verified uploads (decision 034). A client declares the size and
-- SHA-256 of the whole payload, sends chunks at the server's offset (each with its own
-- SHA-256), and completes; the server re-hashes the chunks before using them. Open
-- sessions reserve quota at creation, so concurrent uploads cannot overrun it. Chunks
-- are staging only: they are deleted when the upload completes, is cancelled or expires.
create table upload_session (
    id          uuid        primary key default gen_random_uuid(),
    document_id uuid        not null references document (id) on delete cascade,
    created_by  uuid        not null references identity (id),
    kind        text        not null check (kind in ('media', 'bundle', 'import')),
    media_type  text        check (media_type is null or length(media_type) between 1 and 100),
    size        bigint      not null check (size between 1 and 524288000),
    sha256      bytea       not null check (octet_length(sha256) = 32),
    received    bigint      not null default 0 check (received between 0 and size),
    state       text        not null default 'open' check (state in ('open', 'complete', 'cancelled')),
    result      jsonb,
    created_at  timestamptz not null default now(),
    expires_at  timestamptz not null default now() + interval '24 hours',
    check ((state = 'complete') = (result is not null))
);
create index upload_session_open_by_identity on upload_session (created_by) where state = 'open';
create index upload_session_open_by_document on upload_session (document_id) where state = 'open';
create index upload_session_expiry on upload_session (expires_at) where state = 'open';

create table upload_chunk (
    session_id uuid   not null references upload_session (id) on delete cascade,
    at         bigint not null check (at >= 0),
    sha256     bytea  not null check (octet_length(sha256) = 32),
    bytes      bytea  not null check (octet_length(bytes) between 1 and 8388608),
    primary key (session_id, at)
);
-- Chunk bytes never change after insert.
create function upload_chunk_immutable() returns trigger as $$
begin
    raise exception 'upload_chunk rows are immutable';
end;
$$ language plpgsql;
create trigger upload_chunk_no_update before update on upload_chunk
    for each row execute function upload_chunk_immutable();
