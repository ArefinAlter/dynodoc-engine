-- Erasing legacy plaintext after a project moved to encryption (decision 035, OQ-PR-4, owner
-- decision of 6 November 2026): the file's owner asks, a different administrator confirms, and
-- the erasure runs through the audited whole-document erasure (0017) with its receipt, in the
-- same transaction as the confirmation. The request outlives the document as the record of who
-- asked and who confirmed, so it names the document and project by id only.
create table legacy_erasure_request (
    id           uuid        primary key default gen_random_uuid(),
    document_id  uuid        not null,
    project_id   uuid        not null,
    requested_by uuid        not null references identity (id),
    requested_at timestamptz not null default now(),
    confirmed_by uuid        references identity (id),
    confirmed_at timestamptz,
    check ((confirmed_by is null) = (confirmed_at is null)),
    check (confirmed_by is null or confirmed_by <> requested_by)
);
create unique index legacy_erasure_request_open on legacy_erasure_request (document_id)
    where confirmed_at is null;
revoke all on legacy_erasure_request from public;
