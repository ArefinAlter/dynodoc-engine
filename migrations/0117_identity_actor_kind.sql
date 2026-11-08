-- Agent identity representation (decision 038; docs/AI-AGENT-CONNECTORS.md 4.1 and the roadmap's
-- recommended default "nullable email with an explicit actor kind"). An identity row is now
-- explicitly a person or an agent. Agents have no address at all, instead of the synthetic
-- agent+<id>@agents.invalid of schema 44, so no mail, sign-in or invitation path can ever match
-- one. The reserved domain stays refused for everyone, as defence in depth.

-- Schema 110 already added identity.kind (person or service, for service accounts); this
-- widens its check to agents.
alter table identity drop constraint identity_kind_check;
alter table identity add constraint identity_kind_check
    check (kind in ('person', 'service', 'agent'));
alter table identity alter column email drop not null;

-- Existing agent identities lose their synthetic address.
update identity i set kind = 'agent', email = null
  from agent_identity a where a.identity_id = i.id;

-- A person has an address; an agent has none.
alter table identity add constraint identity_kind_email check ((kind = 'agent') = (email is null));

-- The kind never changes once written.
create function identity_kind_fixed() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if new.kind is distinct from old.kind then
        raise exception 'identity.kind cannot change';
    end if;
    return new;
end $$;
create trigger identity_kind_fixed before update of kind on identity
    for each row execute function identity_kind_fixed();

-- The sidecar describes a disabled, unerased identity of kind agent.
create or replace function agent_identity_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if tg_op = 'DELETE' then
        raise exception 'agent identities are retained: revoke, never delete';
    elsif tg_op = 'INSERT' then
        if not exists(select 1 from public.identity i
                      where i.id = new.identity_id and i.disabled_at is not null
                        and i.erased_at is null and i.kind = 'agent' and i.email is null) then
            raise exception 'an agent identity needs a disabled identity row of kind agent';
        end if;
        if exists(select 1 from public.agent_identity a where a.identity_id = new.principal_id)
           or not exists(select 1 from public.identity p
                         where p.id = new.principal_id and p.disabled_at is null
                           and p.erased_at is null and p.kind = 'person') then
            raise exception 'an agent identity acts for an active person';
        end if;
        return new;
    end if;
    if new.identity_id is distinct from old.identity_id
       or new.principal_id is distinct from old.principal_id
       or new.client_kind is distinct from old.client_kind
       or new.client_ref is distinct from old.client_ref
       or new.created_at is distinct from old.created_at
       or old.revoked_at is not null
       or new.revoked_at is null then
        raise exception 'an agent identity can only be revoked, once';
    end if;
    return new;
end $$;

-- The reserved domain belongs to nobody now, and an identity of kind agent has its sidecar by
-- the end of the transaction that made it.
create or replace function agent_identity_domain_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if new.email is not null and lower(btrim(new.email, E' \t\r\n\f\v') collate "C")
                                 ~ '@([^@]*[.])?agents[.]invalid[.]*\Z' then
        raise exception 'the agents.invalid address domain is reserved for agent identities';
    end if;
    if new.kind = 'agent'
       and not exists(select 1 from public.agent_identity a where a.identity_id = new.id) then
        raise exception 'an identity of kind agent needs its agent_identity row';
    end if;
    return null;
end $$;
drop trigger identity_agent_domain on identity;
create constraint trigger identity_agent_domain after insert or update of email, kind on identity
    deferrable initially deferred for each row execute function agent_identity_domain_guard();

revoke execute on function identity_kind_fixed() from public;
