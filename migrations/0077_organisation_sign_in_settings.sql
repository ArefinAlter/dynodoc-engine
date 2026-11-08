-- Organisation sign-in settings in the database (docs/decisions/031-enterprise-identity.md,
-- section 10): identity providers an organisation owner or admin configures on a settings screen,
-- verified email domains, the group mapping and who may join. File configuration
-- (OIDC_PROVIDERS_FILE, SAML_PROVIDERS_FILE, MAPPINGS_FILE) stays as the operator's override.
--
-- Organisation roles: `owner` and `admin` manage sign-in; `member` does not. Existing
-- organisations get their creator as owner. Domain routing adds members with source `domain`.
-- A provider's client secret is stored only as a DYNOENC envelope (engine_core::at_rest) whose
-- data key derives from the API's server key; it is never returned by any route that serves a
-- person. Additive; hosted behaviour is unchanged until someone creates an organisation.
alter table organisation
    add column restrict_join boolean not null default false,
    add column sign_in_mapping jsonb
        check (sign_in_mapping is null or octet_length(sign_in_mapping::text) <= 262144);

alter table organisation_member
    add column role text not null default 'member' check (role in ('owner', 'admin', 'member'));
alter table organisation_member drop constraint organisation_member_source_check;
alter table organisation_member add constraint organisation_member_source_check
    check (source ~ '^(manual|scim|domain|idp:[a-z0-9][a-z0-9_-]{0,62})$');
insert into organisation_member(organisation_id, identity_id, source, role)
    select id, created_by, 'manual', 'owner' from organisation
    on conflict (organisation_id, identity_id) do update set role = 'owner';

-- A domain an organisation claims; it routes sign-ins only once its DNS TXT record was found.
-- Only one organisation can hold a verified domain.
create table organisation_domain (
    organisation_id uuid not null references organisation(id),
    domain text not null check (domain ~ '^([a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}$' and char_length(domain) <= 253),
    token text not null check (token ~ '^[0-9a-f]{32}$'),
    verified_at timestamptz,
    created_by uuid not null references identity(id),
    created_at timestamptz not null default now(),
    primary key (organisation_id, domain)
);
create unique index organisation_domain_verified_idx on organisation_domain(domain)
    where verified_at is not null;

-- An identity provider configured from the settings screen. `slug` is the provider id in
-- /auth/oidc/{slug} and /auth/saml/{slug}, unique on the installation.
create table organisation_sign_in_provider (
    id uuid primary key default gen_random_uuid(),
    organisation_id uuid not null references organisation(id),
    slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    kind text not null check (kind in ('oidc', 'saml')),
    preset text check (preset in ('google', 'microsoft', 'okta', 'other')),
    display_name text not null check (char_length(display_name) between 1 and 80),
    settings jsonb not null check (jsonb_typeof(settings) = 'object' and octet_length(settings::text) <= 1100000),
    secret_sealed bytea check (secret_sealed is null or octet_length(secret_sealed) <= 8192),
    enabled boolean not null default false,
    revision bigint not null default 1,
    created_by uuid not null references identity(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index organisation_sign_in_provider_org_idx on organisation_sign_in_provider(organisation_id);

revoke all on organisation_domain, organisation_sign_in_provider from public;
