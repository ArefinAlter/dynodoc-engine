-- Shared object collector (docs/DESIGN-COMMIT-PRUNING.md section 6.4, phase P5b,
-- decision 032). Physical reclaim of checkpoint objects that only released history
-- reached. The runtime login can only read this table: a collection is an operator
-- act (`engine-cli shared-object-gc` with the owner credential), never an API route.
-- The operator command marks every root (checkpoints, draft bases, named snapshots,
-- retained publication rows, staged objects and staged commits), sweeps only objects
-- of released states that no root reaches, and inserts one row per document; the
-- insert trigger deletes exactly the listed objects and the object guard admits only
-- those, inside that transaction. Foreign keys from every direct reference still
-- refuse a wrong delete, and quota is released by the existing delete accounting.
create table shared_object_collection (
    id bigint generated always as identity primary key,
    document_id uuid not null references document(id),
    addresses text[] not null check(cardinality(addresses) between 1 and 4096 and array_position(addresses,null) is null),
    plan_hash text not null check(plan_hash ~ '^[0-9a-f]{64}$'),
    transaction_id bigint not null default txid_current(),
    actor text not null default session_user,
    created_at timestamptz not null default now()
);
create trigger shared_object_collection_no_update before update on shared_object_collection
    for each row execute function event_immutable();
create trigger shared_object_collection_no_delete before delete on shared_object_collection
    for each row execute function event_immutable();
create trigger shared_object_collection_no_truncate before truncate on shared_object_collection
    for each statement execute function event_immutable();

create function checkpoint_object_delete_guard() returns trigger
language plpgsql set search_path=pg_catalog,public,pg_temp as $$
begin
    if pg_trigger_depth()>1 and exists (
        select 1 from public.erasure_receipt r join public.document d on d.id=r.resource_id
        where r.resource_id=old.document_id and r.kind='documents'
          and r.transaction_id=txid_current() and d.deleted_at is not null
    ) then return old; end if;
    if pg_trigger_depth()>1 and exists (
        select 1 from public.shared_object_collection c
        where c.document_id=old.document_id and c.transaction_id=txid_current()
          and old.address=any(c.addresses)
    ) then return old; end if;
    raise exception 'history is immutable outside an audited whole-document erasure';
end $$;
drop trigger checkpoint_object_no_delete on checkpoint_object;
create trigger checkpoint_object_no_delete before delete on checkpoint_object
    for each row execute function checkpoint_object_delete_guard();

create function collect_shared_objects() returns trigger
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare removed bigint;
begin
    delete from public.checkpoint_object
        where document_id=new.document_id and address=any(new.addresses);
    get diagnostics removed = row_count;
    if removed<>cardinality(new.addresses) then
        raise exception 'shared object collection differs from its plan' using errcode='23514';
    end if;
    return null;
end $$;
create trigger collect_shared_objects after insert on shared_object_collection
    for each row execute function collect_shared_objects();

revoke all on shared_object_collection from public;
revoke execute on function collect_shared_objects(),checkpoint_object_delete_guard() from public;
