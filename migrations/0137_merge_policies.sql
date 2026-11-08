-- Project merge policies and organisation floors (docs/DESIGN-NODE-CONFLICT-RESOLUTION.md 6.2
-- and 8, decision 042). A project stores one `dynodoc.merge-policy.v1` in canonical form with
-- its hash; an organisation stores floors (`gate_at_least` per strategy) that the policies of
-- projects its members own can only tighten. Both are edited in place with a revision that
-- grows by one per save (If-Match), and every revision is kept, immutable, with its actor.
-- Saving is an account-session act of a person: a project owner or manager, an organisation
-- owner or admin. Publication refuses a v4 merge whose embedded policy is below the effective
-- floor and re-runs its recorded resolutions (decision 042).
create table project_merge_policy (
    project_id uuid primary key references project_settings(space_id),
    policy bytea not null check(octet_length(policy) between 2 and 16384),
    policy_hash text not null check(policy_hash ~ '^[0-9a-f]{64}$'),
    revision bigint not null check(revision>=1),
    updated_by uuid not null references identity(id),
    updated_at timestamptz not null default now()
);
create table project_merge_policy_revision (
    project_id uuid not null references project_settings(space_id),
    revision bigint not null check(revision>=1),
    policy bytea not null check(octet_length(policy) between 2 and 16384),
    policy_hash text not null check(policy_hash ~ '^[0-9a-f]{64}$'),
    actor uuid not null references identity(id),
    created_at timestamptz not null default now(),
    primary key(project_id,revision)
);
create table organisation_merge_floor (
    organisation_id uuid primary key references organisation(id),
    floors bytea not null check(octet_length(floors) between 2 and 16384),
    revision bigint not null check(revision>=1),
    updated_by uuid not null references identity(id),
    updated_at timestamptz not null default now()
);
create table organisation_merge_floor_revision (
    organisation_id uuid not null references organisation(id),
    revision bigint not null check(revision>=1),
    floors bytea not null check(octet_length(floors) between 2 and 16384),
    actor uuid not null references identity(id),
    created_at timestamptz not null default now(),
    primary key(organisation_id,revision)
);

-- The current row moves only forward by one revision, and only with its history row.
create function merge_policy_revision_guard() returns trigger
language plpgsql set search_path=pg_catalog,public,pg_temp as $$
begin
    if tg_op='UPDATE' and new.revision<>old.revision+1 then
        raise exception 'a merge policy revision grows by one' using errcode='23514',constraint='merge_policy_revision';
    end if;
    if tg_op='INSERT' and new.revision<>1 then
        raise exception 'a merge policy starts at revision 1' using errcode='23514',constraint='merge_policy_revision';
    end if;
    if not exists(select 1 from public.identity where id=new.updated_by and kind='person') then
        raise exception 'only a person saves a merge policy or floor' using errcode='23514',constraint='merge_policy_revision';
    end if;
    return new;
end $$;
create trigger merge_policy_revision_guard before insert or update on project_merge_policy
    for each row execute function merge_policy_revision_guard();
create trigger merge_policy_revision_guard before insert or update on organisation_merge_floor
    for each row execute function merge_policy_revision_guard();
do $$ declare t text; begin
    foreach t in array array['project_merge_policy','organisation_merge_floor'] loop
        execute format('create trigger merge_policy_no_delete before delete on %I for each row execute function event_immutable()',t);
        execute format('create trigger merge_policy_no_truncate before truncate on %I for each statement execute function event_immutable()',t);
    end loop;
    foreach t in array array['project_merge_policy_revision','organisation_merge_floor_revision'] loop
        execute format('create trigger merge_policy_no_update before update on %I for each row execute function event_immutable()',t);
        execute format('create trigger merge_policy_no_delete before delete on %I for each row execute function event_immutable()',t);
        execute format('create trigger merge_policy_no_truncate before truncate on %I for each statement execute function event_immutable()',t);
    end loop;
end $$;
revoke all on project_merge_policy,project_merge_policy_revision,organisation_merge_floor,organisation_merge_floor_revision from public;
revoke execute on function merge_policy_revision_guard() from public;
