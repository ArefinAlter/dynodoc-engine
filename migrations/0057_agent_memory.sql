-- Shared agent memory per project (decision 026, part 2).
--
-- A memory is a short statement agents of a project should know (a decision, a fact, a
-- style rule, a past failure, a preference), with provenance and up to eight citations of
-- document blocks. Agents propose memories; a person accepts, edits, archives or deletes
-- them. Citation hashes are computed by the server from the cited block when the memory is
-- written, and every read reports whether each cited block still has that content. Every
-- change is an append-only, hash-chained revision; the memory row holds the current one.

create table agent_memory (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references project_settings(space_id) on delete cascade,
    kind text not null check (kind in ('decision', 'fact', 'style', 'failure', 'preference')),
    state text not null default 'proposed' check (state in ('proposed', 'active', 'archived', 'deleted')),
    revision integer not null default 1 check (revision between 1 and 100000),
    body text not null check (char_length(body) between 1 and 2000),
    citations jsonb not null default '[]'::jsonb
        check (jsonb_typeof(citations) = 'array' and jsonb_array_length(citations) <= 8),
    -- Who wrote it first: an agent identity (with the person it acted for) or a person.
    created_by uuid not null references identity(id),
    principal_id uuid references identity(id),
    session_id uuid references agent_session(id),
    updated_by uuid not null references identity(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    head bytea not null check (octet_length(head) = 32)
);
create index agent_memory_project on agent_memory(project_id, state, updated_at);

create table agent_memory_revision (
    memory_id uuid not null references agent_memory(id) on delete cascade,
    revision integer not null check (revision between 1 and 100000),
    at timestamptz not null default now(),
    actor_id uuid not null references identity(id),
    action text not null check (action in ('propose', 'accept', 'edit', 'archive', 'restore', 'delete')),
    state text not null,
    kind text not null,
    body text not null,
    citations jsonb not null,
    prev bytea not null check (octet_length(prev) = 32),
    hash bytea not null check (octet_length(hash) = 32),
    primary key (memory_id, revision)
);
create trigger agent_memory_revision_no_update before update on agent_memory_revision
    for each row execute function event_immutable();

-- The current row moves only with a new revision, one step at a time.
create function agent_memory_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if new.id <> old.id or new.project_id <> old.project_id or new.created_by <> old.created_by
       or new.principal_id is distinct from old.principal_id
       or new.session_id is distinct from old.session_id or new.created_at <> old.created_at
       or new.revision <> old.revision + 1 then
        raise exception 'an agent memory changes only by its next revision';
    end if;
    if not exists(select 1 from public.agent_memory_revision r
                  where r.memory_id = new.id and r.revision = new.revision and r.hash = new.head) then
        raise exception 'an agent memory revision must be recorded before the memory moves';
    end if;
    return new;
end $$;
create trigger agent_memory_guard before update on agent_memory
    for each row execute function agent_memory_guard();
