-- 0053_byte_order_collation.sql
-- Consistent ID and position collation (docs/04 §B.3.2, docs/13).
--
-- Postgres databases created with locale collations (e.g. en_US.utf8) sort
-- punctuation, upper/lower letters, and fractional index keys differently
-- from native Rust byte order (BTreeMap / slice::sort).
--
-- Setting COLLATE "C" explicitly on relational node identifiers, their parent
-- references, position keys, and foreign references guarantees exact parity
-- between SQL ordering and in-memory engine ordering across all environments,
-- preserving exact strings, content hashes, and foreign key validity.

-- 1. Temporarily drop foreign keys referencing node(id) so that both referenced
-- and referencing columns can have their collation updated to "C".
alter table event drop constraint if exists event_target_node_id_fkey;
alter table node drop constraint if exists node_parent_id_fkey;

-- 2. Alter target columns to use deterministic byte-order collation ("C").
alter table node alter column id type text collate "C";
alter table node alter column parent_id type text collate "C";
alter table node alter column pos type text collate "C";
alter table event alter column target_node_id type text collate "C";
alter table change_request_review alter column node_id type text collate "C";

-- If export_node_token exists (from 0052 in merged environments), update it too.
do $$
begin
    if exists (
        select 1 from information_schema.columns
        where table_schema = 'public'
          and table_name = 'export_node_token'
          and column_name = 'node_id'
    ) then
        execute 'alter table export_node_token alter column node_id type text collate "C"';
    end if;
end $$;

-- 3. Restore foreign keys referencing node(id).
alter table node
    add constraint node_parent_id_fkey
    foreign key (parent_id) references node(id) on delete cascade;

alter table event
    add constraint event_target_node_id_fkey
    foreign key (target_node_id) references node(id);
