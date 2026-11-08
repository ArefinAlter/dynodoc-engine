-- Encrypted projects (decision 035; docs/E2EE-PROTOCOL-AND-MIGRATION.md section 5).
-- Pre-release and not independently reviewed. The service stores ciphertext, signed records
-- and grants it cannot open; it never holds an epoch root, a document key or a private key.
--
-- Nothing existing is rewritten: plaintext projects keep encryption_mode 'none' and every
-- current table, hash and signature domain is unchanged.

-- 1. Mode and counters per project. rotation_pending: a member or device was removed at the
--    service but no client with keys has opened the next epoch yet (clients document 10.3).
alter table project_settings
    add column encryption_mode text not null default 'none'
        check (encryption_mode in ('none', 'migrating', 'sealed')),
    add column current_epoch integer not null default 0
        check (current_epoch between 0 and 1000000),
    add column sealed_name boolean not null default false,
    add column escrow_required boolean not null default false,
    add column agent_delegation text not null default 'none'
        check (agent_delegation in ('none', 'local_only', 'export_allowed')),
    add column rotation_pending boolean not null default false;

-- Per-document mode: a project can be part-migrated only while 'migrating'.
alter table document
    add column encryption text not null default 'none'
        check (encryption in ('none', 'sealed'));

-- 2. Device encryption keys (X25519), each bound by a signature to an enrolled signing key.
create table device_encryption_key (
    id             uuid        primary key default gen_random_uuid(),
    signing_key_id uuid        not null references device_signing_key (id),
    identity_id    uuid        not null references identity (id),
    public_key     text        not null unique check (public_key ~ '^[0-9a-f]{64}$'),
    -- The canonical binding message and its Ed25519 signature (crypto design 5.2).
    binding        jsonb       not null check (octet_length(binding::text) <= 2048),
    signature      text        not null check (signature ~ '^[0-9a-f]{128}$'),
    registered_at  timestamptz not null default now()
);
create index device_encryption_key_identity on device_encryption_key (identity_id, registered_at, id);
create unique index device_encryption_key_one_per_signing_key on device_encryption_key (signing_key_id);

-- 3. Signed, hash-chained membership log (append-only). body is the signed entry as JSON.
create table project_e2ee_log (
    project_id    uuid        not null references project_settings (space_id),
    index         bigint      not null check (index >= 0),
    entry_hash    text        not null check (entry_hash ~ '^[0-9a-f]{64}$'),
    previous_hash text        check (previous_hash ~ '^[0-9a-f]{64}$'),
    entry_type    text        not null check (entry_type in (
        'genesis', 'member_add', 'member_remove', 'role_change', 'device_add',
        'device_revoke', 'recovery_set', 'escrow_set', 'escrow_clear',
        'escrow_backfill', 'escrow_recover', 'epoch_open', 'policy_change',
        'agent_grant', 'agent_revoke', 'migration_begin', 'migration_complete',
        'reseal_live_state', 'owner_transfer')),
    body          bytea       not null check (octet_length(body) between 1 and 16384),
    signer_key    text        not null check (signer_key ~ '^[0-9a-f]{64}$'),
    created_at    timestamptz not null default now(),
    primary key (project_id, index),
    unique (project_id, entry_hash),
    check ((index = 0) = (previous_hash is null))
);

-- 4. Epoch records (append-only, one per epoch number, each announced by a log entry).
create table project_key_epoch (
    project_id     uuid        not null references project_settings (space_id),
    epoch          integer     not null check (epoch >= 1),
    record_hash    text        not null check (record_hash ~ '^[0-9a-f]{64}$'),
    record         bytea       not null check (octet_length(record) between 1 and 8192),
    signature      text        not null check (signature ~ '^[0-9a-f]{128}$'),
    created_by_key text        not null check (created_by_key ~ '^[0-9a-f]{64}$'),
    log_index      bigint      not null,
    created_at     timestamptz not null default now(),
    primary key (project_id, epoch),
    unique (project_id, record_hash),
    foreign key (project_id, log_index) references project_e2ee_log (project_id, index)
);

-- 5. Key grants. Written once; the only permitted change is superseded_at (null to a time,
--    once), the discipline of device_key_project_grant.revoked_at. A grant scoped to a
--    document goes with the document's audited erasure.
create table project_key_grant (
    id               bigint      generated always as identity primary key,
    project_id       uuid        not null,
    epoch            integer     not null,
    scope_document   uuid        references document (id) on delete cascade,
    recipient_kind   text        not null check (recipient_kind in
                       ('device', 'recovery', 'escrow', 'agent', 'addin', 'invitee')),
    recipient_key    text        not null check (recipient_key ~ '^[0-9a-f]{64}$'),
    recipient_device uuid        references device_encryption_key (id),
    grant_body       bytea       not null check (octet_length(grant_body) between 1 and 4096),
    created_by_key   text        not null check (created_by_key ~ '^[0-9a-f]{64}$'),
    created_at       timestamptz not null default now(),
    superseded_at    timestamptz,
    check ((recipient_kind = 'device') = (recipient_device is not null)),
    foreign key (project_id, epoch) references project_key_epoch (project_id, epoch)
);
create unique index project_key_grant_active
    on project_key_grant (project_id, epoch,
        coalesce(scope_document, '00000000-0000-0000-0000-000000000000'::uuid), recipient_key)
    where superseded_at is null;
create index project_key_grant_recipient on project_key_grant (recipient_key, project_id, epoch);

create function project_key_grant_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if (to_jsonb(new) - 'superseded_at') <> (to_jsonb(old) - 'superseded_at')
       or old.superseded_at is not null or new.superseded_at is null then
        raise exception 'key grants can only be superseded, once' using errcode = '23514';
    end if;
    return new;
end $$;
create trigger project_key_grant_supersede_only before update on project_key_grant
    for each row execute function project_key_grant_guard();

-- 6. In-place migration progress (protocol 9.3): resumable, one open row per project.
create table project_e2ee_migration (
    id              uuid        primary key default gen_random_uuid(),
    project_id      uuid        not null references project_settings (space_id),
    direction       text        not null check (direction in ('seal', 'declassify')),
    step            text        not null default 'begun'
                      check (step in ('begun', 'epoch_opened', 'sealing', 'verified', 'completed', 'aborted')),
    started_by      uuid        not null references identity (id),
    started_at      timestamptz not null default now(),
    completed_at    timestamptz,
    last_error_code text        check (last_error_code is null or length(last_error_code) <= 64)
);
create unique index project_e2ee_migration_open on project_e2ee_migration (project_id)
    where completed_at is null;

-- 7. Storage-boundary guard. A sealed document accepts only DYNOSEAL containers and typed v4
--    structural records; a plaintext document refuses both (no mixed-mode confusion).
--    Literals: 'DYNOSEAL' and 'DYNOTYP\0\x04' (engine-core e2ee::seal::MAGIC, e2ee::state::MAGIC).
create function checkpoint_object_mode_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
declare
    mode text := (select encryption from public.document where id = new.document_id);
    sealed_bytes boolean := substring(new.bytes from 1 for 8) = '\x44594e4f5345414c'::bytea
        or substring(new.bytes from 1 for 9) = '\x44594e4f5459500004'::bytea;
begin
    if mode = 'sealed' and not sealed_bytes then
        raise exception 'a sealed document accepts only sealed or structural objects' using errcode = '23514', constraint = 'encryption_mode';
    elsif mode is distinct from 'sealed' and sealed_bytes then
        raise exception 'a plaintext document refuses sealed objects' using errcode = '23514', constraint = 'encryption_mode';
    end if;
    return new;
end $$;
create trigger checkpoint_object_mode before insert on checkpoint_object
    for each row execute function checkpoint_object_mode_guard();

-- The per-document event log is not used by sealed documents in Phase 1 (decision 035):
-- every event for one must be the sealed wrapper {"v":1,"clear":..,"sealed":..}.
create function event_mode_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if (select encryption from public.document where id = new.document_id) = 'sealed'
       and not (jsonb_typeof(new.payload) = 'object' and new.payload ? 'sealed'
                and new.payload->>'v' = '1' and jsonb_typeof(new.payload->'sealed') = 'string') then
        raise exception 'a sealed document accepts only sealed event payloads' using errcode = '23514', constraint = 'encryption_mode';
    end if;
    return new;
end $$;
create trigger event_mode before insert on event
    for each row execute function event_mode_guard();

-- 8. Immutability, as in 0033 and 0036.
do $$ declare t text; begin
    foreach t in array array['device_encryption_key', 'project_e2ee_log', 'project_key_epoch'] loop
        execute format('create trigger immutable_update before update or delete on %I
                        for each row execute function event_immutable()', t);
        execute format('create trigger immutable_truncate before truncate on %I
                        for each statement execute function event_immutable()', t);
    end loop;
end $$;

revoke all on device_encryption_key, project_e2ee_log, project_key_epoch, project_key_grant,
    project_e2ee_migration from public;
revoke execute on function project_key_grant_guard(), checkpoint_object_mode_guard(),
    event_mode_guard() from public;
