-- Signed agent session heads (decision 026 acceptance 4, decision 029).
--
-- Each time a session's chain head moves (opened, a turn recorded) and the operator has
-- installed the receipt signing key, the server signs the session id, project, turn count and
-- head with it and appends a seal here. A session record or turn changed afterwards no longer
-- matches the latest seal, so `GET /projects/{id}/agent-sessions/{session}/verify` reports it.
-- Append-only: the runtime login may only select and insert.
create table agent_session_seal (
    session_id uuid not null references agent_session(id) on delete cascade,
    turns integer not null check (turns between 0 and 10000),
    head bytea not null check (octet_length(head) = 32),
    public_key text not null check (public_key ~ '^[0-9a-f]{64}$'),
    signature bytea not null check (octet_length(signature) = 64),
    sealed_at timestamptz not null default now(),
    primary key (session_id, turns)
);
