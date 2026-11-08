-- Shared history horizons (docs/DESIGN-COMMIT-PRUNING.md sections 5.4 and 6.3,
-- decision 032). The API creates a horizon only with the receipt authority's key
-- mounted, countersigning in the same transaction that inserts the rows; without an
-- installed authority (today's production) no horizon can exist. Every row is
-- immutable and charged to the project's history budget. Released bodies and
-- reachability rows are deleted only by a hard-release batch after the quarantine,
-- through the security-definer trigger below, and the history delete guard admits
-- exactly those rows. Review rows, receipts and ref events are never released.
create table project_history_horizon (
    project_id uuid not null references project_settings(space_id),
    sequence bigint not null check(sequence>=1),
    address text not null check(address ~ '^[0-9a-f]{64}$'),
    envelope bytea not null check(octet_length(envelope) between 1 and 69632),
    policy bytea not null check(octet_length(policy) between 1 and 65536),
    tier text not null check(tier in ('content','history')),
    actor uuid not null references identity(id),
    quarantine_until timestamptz not null,
    created_at timestamptz not null default now(),
    charged_bytes bigint generated always as (octet_length(envelope)::bigint+octet_length(policy)::bigint+128) stored,
    primary key(project_id,sequence),
    unique(project_id,address),
    check(quarantine_until>=created_at)
);
create table project_history_skeleton (
    project_id uuid not null,
    address text not null check(address ~ '^[0-9a-f]{64}$'),
    parents text[] not null check(cardinality(parents)<=2 and array_position(parents,null) is null),
    height bigint not null check(height between 0 and 100000),
    horizon_sequence bigint not null,
    charged_bytes bigint generated always as (64+64*cardinality(parents)::bigint) stored,
    primary key(project_id,address),
    foreign key(project_id,horizon_sequence) references project_history_horizon(project_id,sequence)
);
create index project_history_skeleton_horizon on project_history_skeleton(project_id,horizon_sequence,address);
create table project_history_released_state (
    project_id uuid not null,
    document_id uuid not null,
    state_root text not null check(state_root ~ '^[0-9a-f]{64}$'),
    horizon_sequence bigint not null,
    charged_bytes bigint not null default 128 check(charged_bytes=128),
    primary key(project_id,document_id,state_root),
    foreign key(project_id,horizon_sequence) references project_history_horizon(project_id,sequence)
);
-- One row per hard-release batch, in the transaction that deletes it.
create table project_history_horizon_batch (
    project_id uuid not null,
    sequence bigint not null,
    batch bigint not null check(batch>=1),
    transaction_id bigint not null default txid_current(),
    created_at timestamptz not null default now(),
    primary key(project_id,sequence,batch),
    foreign key(project_id,sequence) references project_history_horizon(project_id,sequence)
);

do $$ declare t text; begin
    foreach t in array array['project_history_horizon','project_history_skeleton','project_history_released_state'] loop
        execute format('create trigger history_account after insert or delete on %I for each row execute function account_project_history()',t);
    end loop;
    foreach t in array array['project_history_horizon','project_history_skeleton','project_history_released_state','project_history_horizon_batch'] loop
        execute format('create trigger history_no_update before update on %I for each row execute function event_immutable()',t);
        execute format('create trigger history_no_delete before delete on %I for each row execute function event_immutable()',t);
        execute format('create trigger history_no_truncate before truncate on %I for each statement execute function event_immutable()',t);
    end loop;
end $$;

-- The erasure clause is unchanged; the horizon clause admits a delete only inside a
-- release batch's own transaction, and only of a body the batch's horizon released
-- or a reachability row of a state it released.
create or replace function project_history_delete_guard() returns trigger
language plpgsql set search_path=pg_catalog,public,pg_temp as $$
declare documents uuid[];
begin
    if tg_table_name='project_published_commit' then documents:=old.scope;
    elsif tg_table_name='project_published_object' then documents:=array[old.document_id];
    else
        select scope into documents from public.project_published_commit
            where project_id=old.project_id and address=old.candidate;
    end if;
    if pg_trigger_depth()>1 and exists (
        select 1 from public.erasure_receipt r join public.document d on d.id=r.resource_id
        where r.kind='documents' and r.transaction_id=txid_current()
            and r.resource_id=any(documents) and d.deleted_at is not null
    ) then return old; end if;
    if pg_trigger_depth()>1 and tg_table_name='project_published_commit' and exists (
        select 1 from public.project_history_horizon_batch b
        join public.project_history_skeleton s on s.project_id=b.project_id and s.horizon_sequence=b.sequence
        where b.project_id=old.project_id and b.transaction_id=txid_current() and s.address=old.address
    ) then return old; end if;
    if pg_trigger_depth()>1 and tg_table_name='project_published_object' and exists (
        select 1 from public.project_history_horizon_batch b
        join public.project_history_released_state s on s.project_id=b.project_id and s.horizon_sequence=b.sequence
        where b.project_id=old.project_id and b.transaction_id=txid_current()
            and s.document_id=old.document_id and s.state_root=old.state_root
    ) then return old; end if;
    raise exception 'published history is immutable outside audited document erasure';
end $$;

-- After the quarantine: the reachability rows of every released state, and at most
-- 256 released bodies, per batch. A body whose candidate has review rows cannot go
-- (the foreign key refuses), so the planner pins reviewed candidates.
create function release_project_history_batch() returns trigger
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare until timestamptz;
begin
    select quarantine_until into until from public.project_history_horizon
        where project_id=new.project_id and sequence=new.sequence;
    if until>now() then
        raise exception 'history horizon is in quarantine' using errcode='23514',constraint='project_history_quarantine';
    end if;
    delete from public.project_published_object o using public.project_history_released_state s
        where s.project_id=new.project_id and s.horizon_sequence=new.sequence
            and o.project_id=s.project_id and o.document_id=s.document_id and o.state_root=s.state_root;
    delete from public.project_published_commit c using (
        select s.address from public.project_history_skeleton s
        where s.project_id=new.project_id and s.horizon_sequence=new.sequence
            and exists(select 1 from public.project_published_commit p where p.project_id=s.project_id and p.address=s.address)
        order by s.address limit 256
    ) d where c.project_id=new.project_id and c.address=d.address;
    return null;
end $$;
create trigger release_project_history_batch after insert on project_history_horizon_batch
    for each row execute function release_project_history_batch();

revoke all on project_history_horizon,project_history_skeleton,project_history_released_state,project_history_horizon_batch from public;
revoke execute on function release_project_history_batch() from public;
