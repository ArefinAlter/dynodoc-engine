-- Enterprise identity (docs/SELF-HOSTED-IDENTITY-AND-ACCESS.md, docs/decisions/031): the minimal
-- organisation record with its AI-agent policy and kill switch, external identity links for OIDC
-- sign-in, the SCIM 2.0 directory (users, groups, per-organisation bearer tokens) and
-- source-tagged memberships for group-to-role mapping.
--
-- Protocol code (OIDC, the SCIM HTTP facade, mapping rules) lives in the web tier; these tables are
-- written only through the API's generic internal routes, which need the service key, and the
-- directory routes also need an organisation's SCIM token.
--
-- Additive: no existing row changes meaning. `space_member.source` defaults to 'manual', so every
-- existing membership stays manual and is never touched by mapping. Hosted behaviour is unchanged
-- unless an administrator creates an organisation. Not rollback-safe by leaving the tables unused:
-- the API refuses a newer schema, so rolling back means restoring the dump.

create table organisation (
    id uuid primary key default gen_random_uuid(),
    name text not null check (char_length(name) between 1 and 200),
    -- Lower-case email domains this organisation's directory may provision or link.
    domains text[] not null default '{}'
        check (cardinality(domains) <= 50 and array_to_string(domains, ',') !~ '[A-Z\s]'),
    -- AI agents acting for members: allowed at all, and the kill switch (only agent sessions
    -- issued strictly after this instant are honoured, as project_agent_policy does per project).
    agents_enabled boolean not null default true,
    agents_valid_after timestamptz,
    revision bigint not null default 1,
    created_by uuid not null references identity(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- Who belongs to an organisation and which channel manages them. `scim` means the organisation's
-- SCIM client owns the account's lifecycle; at most one organisation can do that per account.
create table organisation_member (
    organisation_id uuid not null references organisation(id),
    identity_id uuid not null references identity(id),
    source text not null check (source ~ '^(manual|scim|idp:[a-z0-9][a-z0-9_-]{0,62})$'),
    external_id text check (external_id is null or char_length(external_id) between 1 and 256),
    scim_deleted_at timestamptz,
    version bigint not null default 1,
    added_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (organisation_id, identity_id)
);
create index organisation_member_identity_idx on organisation_member(identity_id);
create unique index organisation_member_one_scim on organisation_member(identity_id)
    where source = 'scim';
create unique index organisation_member_external on organisation_member(organisation_id, external_id)
    where external_id is not null;

-- An identity provider's account, by (issuer, subject). Email decides nothing once a link exists.
create table identity_external (
    id uuid primary key default gen_random_uuid(),
    identity_id uuid not null references identity(id),
    provider text not null check (provider ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    issuer text not null check (char_length(issuer) between 1 and 512),
    subject text not null check (char_length(subject) between 1 and 512),
    email_at_link text,
    linked_at timestamptz not null default now(),
    last_login_at timestamptz,
    unique (issuer, subject)
);
create index identity_external_identity_idx on identity_external(identity_id);

-- SCIM bearer tokens: 256-bit random, only the SHA-256 stored, one organisation each.
create table scim_token (
    id uuid primary key default gen_random_uuid(),
    organisation_id uuid not null references organisation(id),
    token_hash bytea not null unique check (octet_length(token_hash) = 32),
    label text not null check (char_length(label) between 1 and 100),
    created_by uuid not null references identity(id),
    created_at timestamptz not null default now(),
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz
);
create index scim_token_organisation_idx on scim_token(organisation_id);

-- SCIM groups. They grant nothing by themselves: mapping rules turn them into memberships.
create table directory_group (
    id uuid primary key default gen_random_uuid(),
    organisation_id uuid not null references organisation(id),
    display_name text not null check (char_length(display_name) between 1 and 256),
    external_id text check (external_id is null or char_length(external_id) between 1 and 256),
    version bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (organisation_id, display_name)
);
create unique index directory_group_external on directory_group(organisation_id, external_id)
    where external_id is not null;
create table directory_group_member (
    group_id uuid not null references directory_group(id) on delete cascade,
    identity_id uuid not null references identity(id),
    primary key (group_id, identity_id)
);
create index directory_group_member_identity_idx on directory_group_member(identity_id);

-- Memberships made by mapping carry their source and rule; manual ones are never changed by it.
alter table space_member
    add column source text not null default 'manual'
        check (source ~ '^(manual|scim|idp:[a-z0-9][a-z0-9_-]{0,62})$'),
    add column mapping_rule text check (mapping_rule is null or char_length(mapping_rule) <= 200);

-- Instance roles granted by mapping (ADMIN_EMAILS keeps working beside them).
create table identity_instance_role (
    identity_id uuid not null references identity(id),
    role text not null check (role in ('admin')),
    source text not null check (source ~ '^(scim|idp:[a-z0-9][a-z0-9_-]{0,62})$'),
    mapping_rule text check (mapping_rule is null or char_length(mapping_rule) <= 200),
    granted_at timestamptz not null default now(),
    primary key (identity_id, role)
);

revoke all on organisation, organisation_member, identity_external, scim_token, directory_group,
    directory_group_member, identity_instance_role from public;
