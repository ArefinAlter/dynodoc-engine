-- Ledger mode refinements (decision 040).
--
-- 1. Block states for agents. A block bound by a ledger document's first commit and never
--    changed since is only a hash on the server, so an agent cannot read or change it. When an
--    agent's proposal needs one, the server asks members' panes for its state through the relay
--    (kind 'state'); the API keeps an answer only when its fields hash to the asked block hash
--    (ledger::fields_hash), here, content-addressed. Plaintext ledger documents only: an
--    encrypted project's keyed hashes cannot be checked by the server, which never holds their
--    plaintext. Rows go only with their document.
alter table ledger_relay drop constraint ledger_relay_kind_check;
alter table ledger_relay add constraint ledger_relay_kind_check
    check (kind in ('block', 'media', 'state'));

create table ledger_block_state (
    document_id uuid        not null references document (id) on delete cascade,
    block_hash  bytea       not null check (octet_length(block_hash) = 32),
    fields      jsonb       not null check (jsonb_typeof(fields) = 'object'),
    created_at  timestamptz not null default now(),
    primary key (document_id, block_hash)
);
create trigger ledger_block_state_no_update before update on ledger_block_state
    for each row execute function event_immutable();

-- 2. A partly merged ledger change request keeps only what is still unmerged. Its edits replay
--    from its base; once part of it is merged, those edits are copies of events. Inserting one
--    rebase row here, in the merge transaction, deletes the request's edits and moves its base
--    to the revision the merge left (its merge base, a log reference); the API then appends the
--    remaining difference as new edits, so the request's state is unchanged. The triggers check
--    that the request is a partly merged one of a ledger document; the count is the server's.
create table ledger_request_rebase (
    id             uuid        primary key default gen_random_uuid(),
    draft_id       uuid        not null,
    document_id    uuid        not null references document (id) on delete cascade,
    edits          integer     not null default 0 check (edits >= 0),
    transaction_id bigint      not null default txid_current(),
    rebased_at     timestamptz not null default now()
);
create index ledger_request_rebase_draft on ledger_request_rebase (draft_id, transaction_id);
create trigger ledger_request_rebase_no_update before update on ledger_request_rebase
    for each row execute function event_immutable();

create function ledger_request_rebase_check() returns trigger
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
begin
    if not exists (
        select 1 from public.workspace_draft d
        join public.document_storage s on s.document_id = d.document_id
        where d.id = new.draft_id and d.document_id = new.document_id
          and d.merged_at is null and s.mode = 'ledger'
          and d.merge_base_state ? '$dynodoc_log'
    ) then
        raise exception 'only a partly merged change request of a ledger-mode document is rebased';
    end if;
    new.edits := (select count(*) from public.draft_edit where draft_id = new.draft_id);
    new.transaction_id := txid_current();
    new.rebased_at := now();
    return new;
end $$;
create trigger ledger_request_rebase_check before insert on ledger_request_rebase
    for each row execute function ledger_request_rebase_check();

create function ledger_request_rebase() returns trigger
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
begin
    delete from public.draft_edit where draft_id = new.draft_id;
    update public.workspace_draft set base_state = merge_base_state where id = new.draft_id;
    return null;
end $$;
create trigger ledger_request_rebase after insert on ledger_request_rebase
    for each row execute function ledger_request_rebase();

-- A draft's base stays immutable (0031) except in its own rebase: only to its merge base, only
-- from the trigger above, only in the transaction of the rebase row.
create function workspace_draft_base_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if pg_trigger_depth() > 1
       and new.base_state = old.merge_base_state
       and exists (select 1 from public.ledger_request_rebase r
                   where r.draft_id = old.id and r.transaction_id = txid_current())
    then
        return new;
    end if;
    raise exception 'a draft''s base is immutable';
end $$;
drop trigger workspace_draft_base_immutable on workspace_draft;
create trigger workspace_draft_base_immutable before update of base_state on workspace_draft
    for each row when (old.base_state is distinct from new.base_state)
    execute function workspace_draft_base_guard();

-- The draft_edit guard of 0061 with one added clause (marked): the edits of a request rebased
-- in this transaction. ACL and trigger bindings are unchanged.
create or replace function document_erasure_child_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
declare target uuid;
begin
    if tg_table_name = 'draft_edit' then
        select document_id into target from public.workspace_draft where id=old.draft_id;
        if pg_trigger_depth() > 1 and exists (
            select 1 from public.erasure_receipt r join public.workspace_draft d on d.created_by=r.resource_id
            where d.id=old.draft_id and r.kind='users' and r.transaction_id=txid_current()
        ) then
            return old;
        end if;
        -- 0044: the drafts of the agent identities of an erased person.
        if pg_trigger_depth() > 1 and exists (
            select 1 from public.erasure_receipt r
            join public.agent_identity a on a.principal_id=r.resource_id
            join public.workspace_draft d on d.created_by=a.identity_id
            where d.id=old.draft_id and r.kind='users' and r.transaction_id=txid_current()
        ) then
            return old;
        end if;
        -- 0061: a merged ledger change request compacted in this transaction.
        if pg_trigger_depth() > 1 and exists (
            select 1 from public.ledger_compaction c
            where c.draft_id=old.draft_id and c.transaction_id=txid_current()
        ) then
            return old;
        end if;
        -- 0125: a partly merged ledger change request rebased in this transaction.
        if pg_trigger_depth() > 1 and exists (
            select 1 from public.ledger_request_rebase r
            where r.draft_id=old.draft_id and r.transaction_id=txid_current()
        ) then
            return old;
        end if;
    else
        target := old.document_id;
    end if;
    if tg_op = 'DELETE' and pg_trigger_depth() > 1 and exists (
        select 1 from public.erasure_receipt r join public.document d on d.id=r.resource_id
        where r.resource_id=target and r.kind='documents'
          and r.transaction_id=txid_current() and d.deleted_at is not null
    ) then
        return old;
    end if;
    raise exception 'history is immutable outside an audited whole-document erasure';
end;
$$;

revoke all on ledger_block_state, ledger_request_rebase from public;
revoke execute on function ledger_request_rebase_check(), ledger_request_rebase(),
    workspace_draft_base_guard() from public;
