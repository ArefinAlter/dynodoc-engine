-- Content-addressed media for host-native blocks (decision 024). A block's Word or
-- Google Docs form names its images by SHA-256; each image is stored once per
-- document, so editing the text of a paragraph never re-sends its picture. Rows are
-- created and never edited; they go with their document. Pruning images no block
-- references any more is not implemented yet (the per-document quota bounds them).
create table connector_media (
    document_id  uuid        not null references document (id) on delete cascade,
    sha256       bytea       not null check (octet_length(sha256) = 32),
    content_type text        not null check (content_type in (
                     'image/png', 'image/jpeg', 'image/gif', 'image/bmp', 'image/tiff',
                     'image/x-emf', 'image/x-wmf', 'image/svg+xml')),
    bytes        bytea       not null,
    size         integer     not null check (size between 1 and 15728640 and size = octet_length(bytes)),
    created_by   uuid        not null references identity (id),
    created_at   timestamptz not null default now(),
    primary key (document_id, sha256)
);
-- The bytes never change after insert; refuse edits for every login.
create function connector_media_immutable() returns trigger as $$
begin
    raise exception 'connector_media rows are immutable';
end;
$$ language plpgsql;
create trigger connector_media_no_update before update on connector_media
    for each row execute function connector_media_immutable();
