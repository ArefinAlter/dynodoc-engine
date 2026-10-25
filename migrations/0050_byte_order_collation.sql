-- 0050_byte_order_collation.sql
-- Pin database collation for identifier and ordering columns to "C" (byte-order)
-- collation so PostgreSQL ORDER BY matches Rust byte-order string comparisons exactly.

alter table node
    alter column id type text collate "C",
    alter column parent_id type text collate "C",
    alter column pos type text collate "C";

alter table event
    alter column id type text collate "C",
    alter column target_node_id type text collate "C";
