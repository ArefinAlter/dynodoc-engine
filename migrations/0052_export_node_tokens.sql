-- 0052_export_node_tokens.sql
-- Per-export node tokens: map random export-scoped tokens to stable block IDs.
-- Tokens are identity carriers, never bearer permission.
-- Stored as SHA-256 hashes only. Rows leave only with their document on audited erasure.

create table export_node_token (
    id uuid primary key default gen_random_uuid(),
    export_id uuid not null,
    document_id uuid not null references document(id) on delete cascade,
    seq bigint not null check (seq >= 0),
    created_by uuid not null references identity(id),
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    token_hash bytea not null,
    node_id text not null,
    idempotency_key text
);

create unique index export_node_token_export_hash
    on export_node_token(export_id, token_hash);

create index export_node_token_lookup
    on export_node_token(document_id, export_id, token_hash);

create index export_node_token_doc_export
    on export_node_token(document_id, export_id);

create index export_node_token_node
    on export_node_token(document_id, node_id);

create index export_node_token_idem
    on export_node_token(created_by, idempotency_key)
    where idempotency_key is not null;

create function export_node_token_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if new.id is distinct from old.id
        or new.export_id is distinct from old.export_id
        or new.document_id is distinct from old.document_id
        or new.seq is distinct from old.seq
        or new.created_by is distinct from old.created_by
        or new.created_at is distinct from old.created_at
        or new.token_hash is distinct from old.token_hash
        or new.node_id is distinct from old.node_id
        or new.idempotency_key is distinct from old.idempotency_key
        or old.revoked_at is not null
        or new.revoked_at is null then
        raise exception 'export node tokens can only be revoked, once';
    end if;
    return new;
end $$;

create trigger export_node_token_revoke_only before update on export_node_token
    for each row execute function export_node_token_guard();

create function export_node_token_erasure_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
begin
    if pg_trigger_depth() > 1 and exists(
        select 1 from public.erasure_receipt r
        where r.resource_id = old.document_id
          and r.kind = 'documents'
          and r.transaction_id = txid_current()
    ) then
        return old;
    end if;
    raise exception 'export node tokens are immutable outside audited whole-resource erasure';
end $$;

create trigger export_node_token_no_delete before delete on export_node_token
    for each row execute function export_node_token_erasure_guard();

revoke all on export_node_token from public;
revoke execute on function export_node_token_guard(), export_node_token_erasure_guard() from public;
