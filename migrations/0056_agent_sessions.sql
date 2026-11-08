-- Agent sessions, turns and their link to proposals (decision 026, part 1).
--
-- An agent session is what one agent did for one person in one project: which product,
-- model and launcher, and an append-only list of turns (the person's prompt as typed, the
-- agent's visible reasoning). Proposal receipts name the session and turn that produced
-- them and the blocks they touched, so a merged block can be traced to the prompt that
-- asked for it. The project decides how much is kept (capture) and who may read prompts.

-- 1. Capture policy per project. No row means the default: full capture, prompts visible
--    to their author only (the owner's choice of 5 November 2026: on by default).
create table project_agent_capture (
    project_id uuid primary key references project_settings(space_id) on delete cascade,
    capture text not null default 'full' check (capture in ('off', 'actions', 'full')),
    prompt_visibility text not null default 'author'
        check (prompt_visibility in ('author', 'reviewers', 'members')),
    revision bigint not null default 1 check (revision >= 1),
    updated_by uuid not null references identity(id),
    updated_at timestamptz not null default now()
);

-- 2. Sessions. `head` is the hash of the last turn (or of the session header when there
--    is none), so the chain of turns can be verified from the session alone.
create table agent_session (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references project_settings(space_id) on delete cascade,
    agent_identity_id uuid not null references agent_identity(identity_id),
    principal_id uuid not null references identity(id),
    key_id uuid references device_signing_key(id),
    source text not null check (source in ('mcp', 'acp', 'gateway', 'import')),
    product text not null check (char_length(product) between 1 and 80),
    product_version text check (product_version is null or char_length(product_version) between 1 and 40),
    model text check (model is null or char_length(model) between 1 and 120),
    capture text not null check (capture in ('actions', 'full')),
    started_at timestamptz not null default now(),
    turns integer not null default 0 check (turns between 0 and 10000),
    head bytea not null check (octet_length(head) = 32)
);
create index agent_session_project on agent_session(project_id, started_at);
create index agent_session_agent on agent_session(agent_identity_id);
-- Only the turn counter and head move, and only forward together.
create function agent_session_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if tg_op = 'UPDATE' then
        if new.id <> old.id or new.project_id <> old.project_id
           or new.agent_identity_id <> old.agent_identity_id or new.principal_id <> old.principal_id
           or new.key_id is distinct from old.key_id or new.source <> old.source
           or new.product <> old.product or new.product_version is distinct from old.product_version
           or new.model is distinct from old.model or new.capture <> old.capture
           or new.started_at <> old.started_at or new.turns <> old.turns + 1 then
            raise exception 'an agent session only gains turns';
        end if;
    end if;
    return new;
end $$;
create trigger agent_session_guard before update on agent_session
    for each row execute function agent_session_guard();

-- 3. Turns. Text is stored only under full capture, after secret redaction. The only
--    change ever allowed is removing the text (a person's erasure): actions stay.
create table agent_turn (
    session_id uuid not null references agent_session(id) on delete cascade,
    seq integer not null check (seq between 1 and 10000),
    at timestamptz not null,
    prompt text check (prompt is null or char_length(prompt) <= 20000),
    prompt_source text check (prompt_source in ('launcher', 'agent')),
    reasoning text check (reasoning is null or char_length(reasoning) <= 40000),
    redactions integer not null default 0 check (redactions >= 0),
    prev bytea not null check (octet_length(prev) = 32),
    hash bytea not null check (octet_length(hash) = 32),
    erased boolean not null default false,
    primary key (session_id, seq)
);
create function agent_turn_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if tg_op = 'UPDATE' then
        if new.session_id <> old.session_id or new.seq <> old.seq or new.at <> old.at
           or new.prompt_source is distinct from old.prompt_source
           or new.redactions <> old.redactions or new.prev <> old.prev or new.hash <> old.hash
           or new.prompt is not null or new.reasoning is not null or not new.erased then
            raise exception 'agent turns are append-only; only erasure removes their text';
        end if;
    end if;
    return new;
end $$;
create trigger agent_turn_guard before update on agent_turn
    for each row execute function agent_turn_guard();

-- A person's erasure removes the prompts and reasoning of their agents' sessions.
create function agent_turn_erase() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if new.erased_at is not null and old.erased_at is null then
        update public.agent_turn t set prompt = null, reasoning = null, erased = true
          from public.agent_session s
         where s.id = t.session_id and s.principal_id = new.id and not t.erased;
    end if;
    return new;
end $$;
create trigger agent_turn_erase after update of erased_at on identity
    for each row execute function agent_turn_erase();

-- 4. The link from a proposal call to its session and turn, and the blocks it touched.
alter table agent_proposal_receipt
    add column session_id uuid references agent_session(id),
    add column turn integer check (turn is null or turn between 1 and 10000),
    add column nodes text[] not null default '{}'::text[] check (cardinality(nodes) <= 10000),
    add constraint agent_proposal_receipt_turn_needs_session check (turn is null or session_id is not null);
create index agent_proposal_receipt_session on agent_proposal_receipt(session_id) where session_id is not null;
