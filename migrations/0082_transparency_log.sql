-- Transparency log (docs/DESIGN-WITNESSES-AND-TRANSPARENCY.md sections 4.3 and 4.7,
-- decision 032). The runtime login only appends to the outbox, in the transaction
-- of the event that causes a leaf, and creates a project's blinding key once. The
-- log worker (`engine-cli transparency log-worker`, operator credential, one leader
-- under an advisory lock) integrates outbox rows into the tile tree, signs a
-- checkpoint with the log key, and stores the witnesses' cosignatures. Every row is
-- immutable; tiles are written once per path (partial tiles have their own paths).
create table transparency_project_key (
    project_id uuid primary key references project_settings(space_id),
    tag_key bytea not null check(octet_length(tag_key)=32),
    created_at timestamptz not null default now()
);
create table transparency_outbox (
    seq bigint generated always as identity primary key,
    leaf_type text not null check(leaf_type in ('ref','rot','hzn','evh')),
    leaf bytea not null check(octet_length(leaf) between 1 and 256),
    -- Internal lookup only (inclusion routes); never published: leaves are blinded.
    project_id uuid references project_settings(space_id),
    subject text check(subject ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now()
);
create index transparency_outbox_subject on transparency_outbox(project_id,subject);
create table transparency_leaf (
    leaf_index bigint primary key check(leaf_index>=0),
    outbox_seq bigint not null unique references transparency_outbox(seq),
    created_at timestamptz not null default now()
);
create table transparency_tile (
    id bigint generated always as identity primary key,
    path text not null unique check(path ~ '^tile/[0-9a-z./]+$'),
    bytes bytea not null check(octet_length(bytes) between 1 and 131072)
);
create table transparency_checkpoint (
    size bigint primary key check(size>=0),
    root bytea not null check(octet_length(root)=32),
    note text not null check(octet_length(note) between 1 and 65536),
    created_at timestamptz not null default now()
);
create table transparency_cosignature (
    size bigint not null references transparency_checkpoint(size),
    witness text not null check(octet_length(witness) between 1 and 256),
    line text not null check(octet_length(line) between 1 and 1024),
    created_at timestamptz not null default now(),
    primary key(size,witness)
);
-- One row per anchored hour; `count` 0 means no document changed (no leaf).
create table transparency_event_anchor (
    interval_id bigint primary key check(interval_id>=0),
    root bytea not null check(octet_length(root)=32),
    count bigint not null check(count>=0),
    outbox_seq bigint unique references transparency_outbox(seq),
    created_at timestamptz not null default now(),
    check((count=0)=(outbox_seq is null))
);
-- The tuples behind an anchor root. The tag hides the document; the operator
-- recomputes it from the installation and document UUIDs to export a proof.
create table transparency_event_heads (
    interval_id bigint not null references transparency_event_anchor(interval_id),
    doc_tag bytea not null check(octet_length(doc_tag)=32),
    seq bigint not null check(seq>=0),
    chain_hash bytea not null check(octet_length(chain_hash)=32),
    primary key(interval_id,doc_tag)
);

do $$ declare t text; begin
    foreach t in array array['transparency_project_key','transparency_outbox','transparency_leaf','transparency_tile','transparency_checkpoint','transparency_cosignature','transparency_event_anchor','transparency_event_heads'] loop
        execute format('create trigger transparency_no_update before update on %I for each row execute function event_immutable()',t);
        execute format('create trigger transparency_no_delete before delete on %I for each row execute function event_immutable()',t);
        execute format('create trigger transparency_no_truncate before truncate on %I for each statement execute function event_immutable()',t);
    end loop;
end $$;
revoke all on transparency_project_key,transparency_outbox,transparency_leaf,transparency_tile,transparency_checkpoint,transparency_cosignature,transparency_event_anchor,transparency_event_heads from public;
