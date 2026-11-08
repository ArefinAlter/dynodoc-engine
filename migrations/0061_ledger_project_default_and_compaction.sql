-- Ledger mode, second part (decision 028).
--
-- 1. A project's default storage mode. A document that enters the project before its first
--    commit, and has no setting of its own, takes it (the API writes its document_storage row).
--    Repository mode stays the default; images by hash only exist in ledger mode.
alter table project_settings
    add column default_storage_mode text not null default 'repository'
        check (default_storage_mode in ('repository', 'ledger')),
    add column default_media_policy text not null default 'stored'
        check (default_media_policy in ('stored', 'hash_only')),
    add constraint project_settings_hash_only_in_ledger
        check (default_media_policy = 'stored' or default_storage_mode = 'ledger');

-- 2. Compaction of a merged ledger change request. The events keep what the ledger needs
--    (the signed edit messages, their order, the block hashes); the request's own edits and the
--    body of its uploaded bundle are copies of them. Inserting one receipt row here, in the merge
--    transaction, deletes those copies: the bundle keeps its digest, receipt and attribution, so
--    a retried upload is still answered with its receipt. The triggers check that the request is
--    merged and its document is in ledger mode; the counts are the server's, not the caller's.
--    Rows go only with their document.
create table ledger_compaction (
    draft_id       uuid        primary key,
    document_id    uuid        not null references document (id) on delete cascade,
    edits          integer     not null default 0 check (edits >= 0),
    bundle_bytes   bigint      not null default 0 check (bundle_bytes >= 0),
    transaction_id bigint      not null default txid_current(),
    compacted_at   timestamptz not null default now()
);
create trigger ledger_compaction_no_update before update on ledger_compaction
    for each row execute function event_immutable();

create function ledger_compaction_check() returns trigger
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
begin
    if not exists (
        select 1 from public.workspace_draft d
        join public.document_storage s on s.document_id = d.document_id
        where d.id = new.draft_id and d.document_id = new.document_id
          and d.merged_at is not null and s.mode = 'ledger'
    ) then
        raise exception 'only a merged change request of a ledger-mode document is compacted';
    end if;
    new.edits := (select count(*) from public.draft_edit where draft_id = new.draft_id);
    new.bundle_bytes := coalesce((select sum(octet_length(body::text)) from public.provenance_bundle
                                  where draft_id = new.draft_id), 0);
    new.transaction_id := txid_current();
    new.compacted_at := now();
    return new;
end $$;
create trigger ledger_compaction_check before insert on ledger_compaction
    for each row execute function ledger_compaction_check();

create function ledger_compact() returns trigger
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
begin
    delete from public.draft_edit where draft_id = new.draft_id;
    update public.provenance_bundle set body = '{"compacted": true}'::jsonb where draft_id = new.draft_id;
    return null;
end $$;
create trigger ledger_compact after insert on ledger_compaction
    for each row execute function ledger_compact();

-- The draft_edit guard of 0017 and 0044 with one added clause (marked): the edits of a request
-- compacted in this transaction. ACL and trigger bindings are unchanged.
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

-- An uploaded bundle stays immutable except for compaction: only its body, only to the marker,
-- only in the transaction of its request's compaction.
create function provenance_bundle_update_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if pg_trigger_depth() > 1
       and new.body = '{"compacted": true}'::jsonb
       and (new.document_id, new.bundle_id, new.draft_id, new.actor_id, new.digest, new.receipt, new.received_at)
           is not distinct from
           (old.document_id, old.bundle_id, old.draft_id, old.actor_id, old.digest, old.receipt, old.received_at)
       and exists (select 1 from public.ledger_compaction c
                   where c.draft_id = old.draft_id and c.transaction_id = txid_current())
    then
        return new;
    end if;
    raise exception 'provenance is immutable outside audited whole-resource erasure';
end $$;
drop trigger provenance_bundle_no_update on provenance_bundle;
create trigger provenance_bundle_no_update before update on provenance_bundle
    for each row execute function provenance_bundle_update_guard();

revoke all on ledger_compaction from public;
revoke execute on function ledger_compaction_check(), ledger_compact(),
    provenance_bundle_update_guard() from public;
