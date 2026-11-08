-- Outbound mail outbox (docs/decisions/037-self-hosted-identity-ha-and-licensing.md,
-- docs/SELF-HOSTED-EDITION.md 6.5 "Outbound mail queue"). When a send fails in a way that may pass,
-- the web tier queues the message here and a worker in every web process drains it: claim with a
-- lease, send through the configured transport, report the result. Only invitations, approval and
-- notice messages are ever queued: a sign-in link is a credential and is never stored.
--
-- Once a message is sent or has failed for good its subject and bodies are cleared, so the table
-- keeps no message content after delivery; retention prunes the remaining row. Additive; nothing
-- is queued unless DYNODOC_MAIL_OUTBOX=on in the web tier.

create table mail_outbox (
    id uuid primary key default gen_random_uuid(),
    kind text not null check (kind in ('invitation', 'approval', 'notice')),
    recipient text not null check (char_length(recipient) between 3 and 254),
    reply_to text check (reply_to is null or char_length(reply_to) between 3 and 254),
    subject text not null check (char_length(subject) <= 300),
    text_body text not null,
    html_body text not null,
    attempts integer not null default 0 check (attempts >= 0),
    next_attempt_at timestamptz not null default now(),
    lease_until timestamptz,
    sent_at timestamptz,
    failed_at timestamptz,
    last_error_class text check (last_error_class is null or last_error_class ~ '^[a-z_]{1,40}$'),
    created_at timestamptz not null default now(),
    check (octet_length(text_body) + octet_length(html_body) <= 262144),
    check (sent_at is null or failed_at is null)
);
create index mail_outbox_due_idx on mail_outbox(next_attempt_at)
    where sent_at is null and failed_at is null;

revoke all on mail_outbox from public;
