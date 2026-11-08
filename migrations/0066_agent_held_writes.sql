-- Held writes of remote AI agents (decision 029 section 5).
--
-- A write tool (propose, submit, withdraw, remember) called with a remote grant (an OAuth
-- client of /mcp) is not carried out: the request is held here, visible only to the person
-- the agent acts for, until that person confirms it on a human-only surface (the web
-- workspace or the desktop app) within seven days. Confirming replays the stored request as
-- the agent, through the same checks as a direct call; declining discards its text. Nothing
-- held reaches a draft, a change request, the reviewers' inbox or the project memory.
create table agent_held_write (
    id uuid primary key,
    project_id uuid not null references project_settings(space_id) on delete cascade,
    principal_id uuid not null references identity(id),
    key_id uuid not null references device_signing_key(id),
    -- The device session and account generation of the call, checked again at replay.
    session_id uuid not null,
    session_generation bigint not null,
    tool text not null check (tool in ('propose', 'submit', 'withdraw', 'remember')),
    -- The file of a propose (full id) or the proposal of a submit or withdraw.
    target text not null default '' check (char_length(target) <= 64),
    document_id uuid,
    body jsonb not null,
    digest bytea not null check (octet_length(digest) = 32),
    client text not null default '' check (char_length(client) <= 200),
    summary text not null check (char_length(summary) <= 8000),
    preview text check (preview is null or char_length(preview) <= 64000),
    state text not null default 'held' check (state in ('held', 'confirmed', 'declined', 'expired', 'failed')),
    result jsonb,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    decided_at timestamptz,
    decided_by uuid references identity(id)
);
create index agent_held_write_waiting on agent_held_write(principal_id, state, expires_at);

-- A held write is decided once: held becomes confirmed, or declined or expired (both remove
-- the text), and a confirmed one may only record its result or that the replay failed.
create function agent_held_write_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if new.id <> old.id or new.project_id <> old.project_id or new.principal_id <> old.principal_id
       or new.key_id <> old.key_id or new.session_id <> old.session_id
       or new.session_generation <> old.session_generation or new.tool <> old.tool
       or new.target <> old.target or new.document_id is distinct from old.document_id
       or new.digest <> old.digest or new.created_at <> old.created_at
       or new.expires_at <> old.expires_at then
        raise exception 'a held agent write keeps what was asked';
    end if;
    if not ((old.state = 'held' and new.state = 'confirmed' and new.body = old.body)
         or (old.state = 'held' and new.state in ('declined', 'expired') and new.body = '{}'::jsonb
             and new.summary = '' and new.preview is null)
         or (old.state = 'confirmed' and new.state in ('confirmed', 'failed') and new.body = old.body
             and new.decided_at = old.decided_at and new.decided_by = old.decided_by)) then
        raise exception 'a held agent write is decided once';
    end if;
    return new;
end $$;
create trigger agent_held_write_guard before update on agent_held_write
    for each row execute function agent_held_write_guard();
