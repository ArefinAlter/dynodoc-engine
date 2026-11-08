-- History holds (docs/DESIGN-COMMIT-PRUNING.md sections 7.7 and 10.3, decision 042). A hold
-- keeps history that a horizon would otherwise release. A hold without a commit holds the
-- whole project (a legal hold, for example): no horizon can be created and no release batch
-- can run while it is in force. A hold on a commit pins that commit's body and states: the
-- planner keeps it, a horizon cannot release it, and a horizon created before the hold
-- cannot run its release batches until the hold ends.
--
-- Holds are human-only: set and released by a person's account session (an owner or a
-- manager; a legal hold only by an owner), never by a device, agent or service identity. The
-- API checks the session and the role; the trigger below checks that both actors are people.
-- A hold is never deleted: releasing it records who and when, once.
create table project_history_hold (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references project_settings(space_id),
    commit_address text check(commit_address ~ '^[0-9a-f]{64}$'),
    legal boolean not null default false,
    reason text not null check(octet_length(reason) between 1 and 200 and reason !~ '[[:cntrl:]]'),
    created_by uuid not null references identity(id),
    created_at timestamptz not null default now(),
    released_by uuid references identity(id),
    released_at timestamptz,
    check((released_by is null)=(released_at is null)),
    check(not legal or commit_address is null)
);
create index project_history_hold_active on project_history_hold(project_id,commit_address)
    where released_at is null;

create function project_history_hold_guard() returns trigger
language plpgsql set search_path=pg_catalog,public,pg_temp as $$
declare actor uuid;
begin
    if tg_op='INSERT' then
        if new.released_by is not null then
            raise exception 'a hold starts in force' using errcode='23514',constraint='project_history_hold';
        end if;
        actor:=new.created_by;
    else
        if old.released_at is not null or new.released_at is null
            or (new.id,new.project_id,new.commit_address,new.legal,new.reason,new.created_by,new.created_at)
               is distinct from (old.id,old.project_id,old.commit_address,old.legal,old.reason,old.created_by,old.created_at) then
            raise exception 'a hold is released once and otherwise immutable' using errcode='23514',constraint='project_history_hold';
        end if;
        actor:=new.released_by;
    end if;
    if not exists(select 1 from public.identity where id=actor and kind='person') then
        raise exception 'only a person sets or releases a history hold' using errcode='23514',constraint='project_history_hold';
    end if;
    return new;
end $$;
create trigger project_history_hold_guard before insert or update on project_history_hold
    for each row execute function project_history_hold_guard();
create trigger project_history_hold_no_delete before delete on project_history_hold
    for each row execute function event_immutable();
create trigger project_history_hold_no_truncate before truncate on project_history_hold
    for each statement execute function event_immutable();

-- No horizon while the whole project is held, and no skeleton row for a held commit.
create function project_history_hold_blocks() returns trigger
language plpgsql set search_path=pg_catalog,public,pg_temp as $$
begin
    if exists(select 1 from public.project_history_hold h where h.project_id=new.project_id
        and h.released_at is null
        and (h.commit_address is null or (tg_table_name='project_history_skeleton' and h.commit_address=new.address))) then
        raise exception 'history is on hold' using errcode='23514',constraint='project_history_hold';
    end if;
    return new;
end $$;
create trigger project_history_hold_blocks before insert on project_history_horizon
    for each row execute function project_history_hold_blocks();
create trigger project_history_hold_blocks before insert on project_history_skeleton
    for each row execute function project_history_hold_blocks();

-- The release batch of 0080, refused while a hold covers the project or one of the commits
-- this horizon releases.
create or replace function release_project_history_batch() returns trigger
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare until timestamptz;
begin
    select quarantine_until into until from public.project_history_horizon
        where project_id=new.project_id and sequence=new.sequence;
    if until>now() then
        raise exception 'history horizon is in quarantine' using errcode='23514',constraint='project_history_quarantine';
    end if;
    if exists(select 1 from public.project_history_hold h where h.project_id=new.project_id
        and h.released_at is null
        and (h.commit_address is null or exists(select 1 from public.project_history_skeleton s
            where s.project_id=h.project_id and s.horizon_sequence=new.sequence and s.address=h.commit_address))) then
        raise exception 'history is on hold' using errcode='23514',constraint='project_history_hold';
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

revoke all on project_history_hold from public;
revoke execute on function project_history_hold_guard(),project_history_hold_blocks() from public;
