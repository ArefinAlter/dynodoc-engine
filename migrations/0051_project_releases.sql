-- Named multi-file releases pointing to accepted protected main commits.
-- Releases are immutable records keyed by (project_id, name).
-- An unreviewed candidate cannot become a release by bypassing protected main.

create table project_release (
    project_id uuid not null references project_settings(space_id),
    name text not null check(octet_length(name) between 1 and 100 and name ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
    commit_address text not null check(commit_address ~ '^[0-9a-f]{64}$'),
    actor uuid not null references identity(id),
    created_at timestamptz not null default now(),
    charged_bytes bigint generated always as (160 + octet_length(name)::bigint) stored,
    primary key(project_id, name),
    foreign key(project_id, commit_address) references project_published_commit(project_id, address)
);
create index project_release_commit on project_release(project_id, commit_address);

create trigger release_account after insert or delete on project_release
    for each row execute function account_project_history();
create trigger release_no_update before update on project_release
    for each row execute function event_immutable();
create trigger release_no_truncate before truncate on project_release
    for each statement execute function event_immutable();

-- Audited document erasure handling: replace project_history_delete_guard and erase_published_project_history
create or replace function project_history_delete_guard() returns trigger
language plpgsql set search_path=pg_catalog,public,pg_temp as $$
declare documents uuid[];
begin
    if tg_table_name='project_published_commit' then documents:=old.scope;
    elsif tg_table_name='project_published_object' then documents:=array[old.document_id];
    elsif tg_table_name='project_release' then
        select scope into documents from public.project_published_commit
            where project_id=old.project_id and address=old.commit_address;
    else
        select scope into documents from public.project_published_commit
            where project_id=old.project_id and address=old.candidate;
    end if;
    if pg_trigger_depth()>1 and exists (
        select 1 from public.erasure_receipt r join public.document d on d.id=r.resource_id
        where r.kind='documents' and r.transaction_id=txid_current()
            and r.resource_id=any(documents) and d.deleted_at is not null
    ) then return old; end if;
    raise exception 'published history is immutable outside audited document erasure';
end $$;

create trigger release_no_delete before delete on project_release
    for each row execute function project_history_delete_guard();

create or replace function erase_published_project_history() returns trigger
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
begin
    delete from public.project_release r using public.project_published_commit c
        where r.project_id=c.project_id and r.commit_address=c.address and c.scope @> array[old.id];
    delete from public.project_history_review r using public.project_published_commit c
        where r.project_id=c.project_id and r.candidate=c.address and c.scope @> array[old.id];
    delete from public.project_published_object where document_id=old.id;
    delete from public.project_published_commit where scope @> array[old.id];
    return old;
end $$;

revoke all on project_release from public;
