-- Remote MCP sessions shared by every API replica (docs/decisions/037, crates/engine-api/src/
-- mcp_http.rs). A session made by `initialize` on one replica is honoured by the others: the row
-- binds it to the account, the device key and the project of the bearer that opened it, and is the
-- authority on whether it still exists and is within its idle limit. Only the SHA-256 of the
-- session id is stored. Retention prunes rows idle past the limit. Additive; hosted behaviour is
-- unchanged unless the agent gateway is on.

create table mcp_http_session (
    id_hash bytea primary key check (octet_length(id_hash) = 32),
    identity_id uuid not null references identity(id),
    key_id uuid not null,
    project_id uuid not null,
    writes boolean not null,
    created_at timestamptz not null default now(),
    seen_at timestamptz not null default now()
);
create index mcp_http_session_identity_idx on mcp_http_session(identity_id, seen_at);

revoke all on mcp_http_session from public;

-- The installation's first start (decision 037, owner decisions of 6 November): the self-hosted
-- web tier counts the 30-day trial from it. The runtime login only reads `device_authority`, so
-- moving the date needs the owner login and a deliberate UPDATE. Nothing is reported anywhere.
alter table device_authority add column started_at timestamptz not null default now();
