-- Documents whose event history no longer replays. The API refuses writes to them
-- until an operator releases them; their events are never changed. Only the
-- operator login writes this table (engine-cli quarantine / release).
create table document_quarantine (
    document_id uuid primary key references document (id) on delete cascade,
    seq bigint not null check (seq > 0),
    reason text not null check (length(reason) between 1 and 1000),
    created_at timestamptz not null default now()
);
