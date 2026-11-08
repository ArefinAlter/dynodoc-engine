-- Customer-managed at-rest envelope encryption, Phase 0 (docs/END-TO-END-ENCRYPTION.md 7.7,
-- docs/AT-REST-ENVELOPE.md). NOT end-to-end: the running service unwraps data keys and reads
-- content. kms_key names a key-encryption key at a provider (never key material); data_key
-- holds each project's data key wrapped by that provider. Unwrapped keys exist only in
-- process memory for the cache lifetime.
create table kms_key (
    id          uuid        primary key default gen_random_uuid(),
    provider    text        not null check (provider in
                  ('aws-kms', 'azure-keyvault', 'gcp-kms', 'vault-transit', 'pkcs11', 'file')),
    -- ARN, URL, key name or directory; never secret material.
    key_ref     text        not null check (length(key_ref) between 1 and 512),
    purpose     text        not null check (purpose in ('data', 'backup')),
    status      text        not null default 'active'
                  check (status in ('active', 'retiring', 'retired', 'disabled')),
    created_at  timestamptz not null default now()
);
create unique index kms_key_one_active on kms_key (purpose) where status = 'active';

create table data_key (
    id          integer     generated always as identity primary key,
    -- Null: installation scope (data outside any project).
    project_id  uuid        references project_settings (space_id),
    kms_key_id  uuid        not null references kms_key (id),
    kek_version integer     not null check (kek_version >= 1),
    wrapped     bytea       not null check (octet_length(wrapped) between 16 and 4096),
    state       text        not null default 'active'
                  check (state in ('active', 'decrypt_only')),
    created_at  timestamptz not null default now(),
    retired_at  timestamptz,
    check ((state = 'active') = (retired_at is null))
);
create unique index data_key_active on data_key (coalesce(project_id,
    '00000000-0000-0000-0000-000000000000'::uuid)) where state = 'active';

-- A data key only moves forward: active -> decrypt_only, and a rewrap changes only the wrapped
-- bytes and the KEK version. Crypto-erasure deletes the rows (an audited operator action).
create function data_key_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if new.id <> old.id or new.project_id is distinct from old.project_id
       or new.created_at <> old.created_at
       or (old.state = 'decrypt_only' and new.state = 'active') then
        raise exception 'data keys only rewrap or retire' using errcode = '23514';
    end if;
    return new;
end $$;
create trigger data_key_forward before update on data_key
    for each row execute function data_key_guard();

revoke all on kms_key, data_key from public;
revoke execute on function data_key_guard() from public;
