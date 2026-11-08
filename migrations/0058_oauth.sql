-- OAuth 2.1 for remote MCP clients (ChatGPT custom connectors and other hosted agents).
--
-- A person consents on Dynodoc's own page. The consent creates an agent key that has no
-- private key: its public key is random, so it can never sign a device-session challenge.
-- The key gets a project grant like any agent key. The token endpoint then issues the same
-- one-hour project device sessions (ledger row, budget, audit) that agent routes already
-- verify. Revoking the key in the profile ends the grant. Codes are single use; refresh
-- tokens rotate; only hashes are stored.

create table oauth_client (
    id text primary key check (id ~ '^[0-9a-f]{32}$'),
    name text not null check (char_length(name) between 1 and 100),
    redirect_uris text[] not null check (cardinality(redirect_uris) between 1 and 5),
    created_at timestamptz not null default now()
);
create index oauth_client_created on oauth_client(created_at);

create table oauth_grant (
    key_id uuid primary key references device_signing_key(id),
    client_id text not null references oauth_client(id),
    identity_id uuid not null references identity(id),
    project_id uuid not null references project_settings(space_id) on delete cascade,
    refresh_hash bytea unique check (refresh_hash is null or octet_length(refresh_hash) = 32),
    created_at timestamptz not null default now(),
    refreshed_at timestamptz
);
create unique index oauth_grant_once on oauth_grant(client_id, identity_id, project_id);

create table oauth_code (
    code_hash bytea primary key check (octet_length(code_hash) = 32),
    key_id uuid not null references oauth_grant(key_id) on delete cascade,
    redirect_uri text not null,
    code_challenge text not null check (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    expires_at timestamptz not null
);

revoke all on oauth_client, oauth_grant, oauth_code from public;
