-- Streaming server ingest of a large native import (decision 034). A completed import
-- upload becomes a job; the worker streams the package from the staged chunks and commits
-- the graph in batches. Each batch commits with the job's cursor in the same transaction,
-- so a crash resumes at the next batch and no batch is applied twice. The original file is
-- then kept as a document-scoped content tree (state_root of checkpoint_object), charged to
-- the shared storage budgets, and the staged chunks are deleted.
create table import_job (
    id             uuid        primary key default gen_random_uuid(),
    upload_id      uuid        not null unique references upload_session (id) on delete cascade,
    document_id    uuid        not null references document (id) on delete cascade,
    created_by     uuid        not null references identity (id),
    filename       text        not null check (length(filename) between 1 and 255),
    state          text        not null default 'queued'
                               check (state in ('queued', 'running', 'done', 'failed')),
    root_node_id   text,
    cursor         bigint      not null default 0 check (cursor >= 0),
    first_seq      bigint,
    through_seq    bigint,
    original_root  text        check (original_root is null or original_root ~ '^[0-9a-f]{64}$'),
    error          text        check (error is null or length(error) <= 500),
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now()
);
create index import_job_pending on import_job (created_at) where state in ('queued', 'running');
create index import_job_by_identity on import_job (created_by) where state in ('queued', 'running');
