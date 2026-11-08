-- Identity, second part (docs/decisions/037-self-hosted-identity-ha-and-licensing.md,
-- docs/SELF-HOSTED-IDENTITY-AND-ACCESS.md sections 5.6, 7.5, 10.4, 11 and 12).
--
-- * login_session: one row per login (the refresh-token lineage, same session_id), written at
--   sign-in and on each refresh. It carries the provider and the identity provider's session
--   (OIDC `sid`, SAML SessionIndex) so a back-channel logout can end the right logins, and the
--   OIDC ID token for RP-initiated logout, sealed (DYNOENC) under the identity-secrets key.
-- * The read-only `auditor` role, for the instance and for an organisation.
-- * Service accounts: `identity.kind = 'service'` with a named owner; they never sign in through
--   a browser, and act through device keys with per-project grants that may expire.
-- * Per organisation: the approval email switch, the mapping freeze and the SCIM deactivation
--   circuit breaker (deactivations above the threshold are held for an owner or admin).
-- * The one-time ledger also remembers back-channel logout token ids (`jti`).
--
-- Additive: every existing row keeps its meaning (kind 'person', no session row for logins made
-- before this migration, approval email on, mapping not frozen, breaker at the documented
-- default of 10 percent and at least 20 accounts per hour).

create table login_session (
    session_id uuid primary key,
    identity_id uuid not null references identity(id),
    -- 'email', 'google', 'operator-link', 'handover', 'service-enrolment' or a provider id.
    provider text not null check (provider ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    issuer text check (issuer is null or char_length(issuer) between 1 and 512),
    subject text check (subject is null or char_length(subject) between 1 and 512),
    idp_session text check (idp_session is null or char_length(idp_session) between 1 and 512),
    id_token_hint bytea check (id_token_hint is null or octet_length(id_token_hint) <= 16384),
    auth_time timestamptz,
    started_at timestamptz not null default now(),
    last_refresh_at timestamptz,
    -- The absolute cap (SESSION_ABSOLUTE_TIMEOUT_SECONDS) at sign-in; no refresh row outlives it.
    absolute_expires_at timestamptz,
    revoked_at timestamptz,
    revoked_reason text check (revoked_reason is null or revoked_reason in
        ('logout', 'self', 'admin', 'idp_logout', 'deactivated'))
);
create index login_session_identity_idx on login_session(identity_id) where revoked_at is null;
create index login_session_idp_idx on login_session(issuer, idp_session) where idp_session is not null;
create index login_session_subject_idx on login_session(issuer, subject) where subject is not null;

alter table identity_instance_role drop constraint identity_instance_role_role_check;
alter table identity_instance_role add constraint identity_instance_role_role_check
    check (role in ('admin', 'auditor'));
-- 'manual': granted by an administrator in Dynodoc; mapping never removes or retags such a row.
alter table identity_instance_role drop constraint identity_instance_role_source_check;
alter table identity_instance_role add constraint identity_instance_role_source_check
    check (source ~ '^(manual|scim|idp:[a-z0-9][a-z0-9_-]{0,62})$');

alter table organisation_member drop constraint organisation_member_role_check;
alter table organisation_member add constraint organisation_member_role_check
    check (role in ('owner', 'admin', 'member', 'auditor'));

alter table identity
    add column kind text not null default 'person' check (kind in ('person', 'service')),
    add column service_owner uuid references identity(id),
    add constraint identity_service_owner_check check ((kind = 'service') = (service_owner is not null));

alter table organisation
    add column approval_email boolean not null default true,
    add column mapping_frozen boolean not null default false,
    add column scim_breaker_percent integer not null default 10
        check (scim_breaker_percent between 1 and 100),
    add column scim_breaker_minimum integer not null default 20
        check (scim_breaker_minimum between 1 and 100000);

-- A SCIM deactivation or delete above the breaker's threshold, waiting for an owner or admin.
create table scim_held_deactivation (
    organisation_id uuid not null references organisation(id),
    identity_id uuid not null references identity(id),
    operation text not null check (operation in ('deactivate', 'delete')),
    requested_at timestamptz not null default now(),
    primary key (organisation_id, identity_id)
);

-- Unattended credentials lapse: a grant may carry an expiry (written once, at creation).
alter table device_key_project_grant add column expires_at timestamptz;
create or replace function device_key_project_grant_guard() returns trigger language plpgsql as $$
begin
    if new.id is distinct from old.id
        or new.key_id is distinct from old.key_id
        or new.project_id is distinct from old.project_id
        or new.scopes is distinct from old.scopes
        or new.created_at is distinct from old.created_at
        or new.created_by is distinct from old.created_by
        or new.expires_at is distinct from old.expires_at
        or old.revoked_at is not null
        or new.revoked_at is null then
        raise exception 'device key grants can only be revoked, once';
    end if;
    return new;
end $$;
revoke execute on function device_key_project_grant_guard() from public;

alter table auth_flow_once drop constraint auth_flow_once_kind_check;
alter table auth_flow_once add constraint auth_flow_once_kind_check
    check (kind in ('oidc_state', 'saml_request', 'saml_assertion', 'oidc_logout_jti'));

revoke all on login_session, scim_held_deactivation from public;
