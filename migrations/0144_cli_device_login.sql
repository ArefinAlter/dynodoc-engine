-- Browser-assisted CLI device login (RFC 8628-style with Ed25519 proof-of-possession).
-- Only the SHA-256 of the opaque device_code is stored.
-- Pending requests expire after 5 minutes and are atomically consumed once.

create table cli_login_request (
    id uuid primary key,
    device_code_hash bytea not null unique check (octet_length(device_code_hash) = 32),
    user_code text not null,
    public_key text not null check (public_key ~ '^[0-9a-f]{64}$'),
    label text not null check (char_length(label) between 1 and 80),
    challenge_nonce text not null check (challenge_nonce ~ '^[0-9a-f]{64}$'),
    status text not null check (status in ('pending', 'approved', 'denied', 'consumed')),
    identity_id uuid references identity(id),
    session_generation integer,
    grant_all_projects boolean not null default false,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    approved_at timestamptz,
    consumed_at timestamptz
);

create index cli_login_request_user_code_pending
    on cli_login_request(user_code)
    where status = 'pending';

create index cli_login_request_expires
    on cli_login_request(expires_at)
    where status in ('pending', 'approved');
