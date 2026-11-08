-- Ledger mode (decisions 025 and 028). A document either keeps its content on the server
-- (repository mode, the default: no row here) or keeps only the edit messages (ledger
-- mode): the first commit records block hashes without content, later commits carry the
-- full new state of each changed block, and the members' own files are the copies.
--
-- The owner or a manager chooses the mode before the first commit; the API refuses a change
-- once the document has content or a change request. The media policy says whether images
-- are stored ('stored') or known by hash only ('hash_only', the bytes travel between
-- members through the relay below).
create table document_storage (
    document_id  uuid        primary key references document (id) on delete cascade,
    mode         text        not null check (mode in ('repository', 'ledger')),
    media_policy text        not null default 'stored' check (media_policy in ('stored', 'hash_only')),
    set_by       uuid        not null references identity (id),
    set_at       timestamptz not null default now()
);

-- Short-lived member-to-member relay for a block state or an image a pane lacks. A request
-- names the content by hash; an online member uploads it; the requester downloads it once
-- and the row is deleted in that transaction. Unanswered or undelivered rows expire after an
-- hour and are purged on the next relay call. The server never reads `payload`: it is the
-- plain bytes today (`encoding` 'plain'; the requester checks the hash) and can become a
-- ciphertext for `recipient_key` (an X25519 public key, base64url) without a schema change.
create table ledger_relay (
    id            uuid        primary key default gen_random_uuid(),
    document_id   uuid        not null references document (id) on delete cascade,
    requested_by  uuid        not null references identity (id),
    kind          text        not null check (kind in ('block', 'media')),
    subject       bytea       not null check (octet_length(subject) = 32),
    recipient_key text        check (recipient_key is null or recipient_key ~ '^[A-Za-z0-9_-]{43}$'),
    payload       bytea       check (payload is null or octet_length(payload) between 1 and 15728640),
    encoding      text        check (encoding is null or encoding in ('plain', 'x25519-aes256gcm-v1')),
    served_by     uuid        references identity (id),
    created_at    timestamptz not null default now(),
    expires_at    timestamptz not null default now() + interval '1 hour',
    served_at     timestamptz,
    check ((payload is null) = (served_at is null) and (payload is null) = (encoding is null)),
    unique (document_id, requested_by, kind, subject)
);
create index ledger_relay_open on ledger_relay (document_id, expires_at) where served_at is null;

revoke all on document_storage, ledger_relay from public;
