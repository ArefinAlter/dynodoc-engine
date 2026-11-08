-- One-time ledger for sign-in flows (docs/decisions/031-enterprise-identity.md): an OpenID Connect
-- state, a SAML request id and a SAML assertion id are each accepted once, by every web process
-- of an installation (the web tier records them through the API's internal route, with the service
-- key). Only the SHA-256 of the value is stored. A row is created and pruned once expired, never
-- edited (INSERT_DELETE). Additive; hosted behaviour is unchanged until a provider is configured.
create table auth_flow_once (
    kind text not null check (kind in ('oidc_state', 'saml_request', 'saml_assertion')),
    key_hash bytea not null check (octet_length(key_hash) = 32),
    expires_at timestamptz not null,
    primary key (kind, key_hash)
);
create index auth_flow_once_expiry_idx on auth_flow_once(expires_at);
revoke all on auth_flow_once from public;
