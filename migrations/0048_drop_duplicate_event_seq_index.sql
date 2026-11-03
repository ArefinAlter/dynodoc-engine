-- The event sequence unique constraint indexes these exact same keys and order.
-- Keep snapshot_latest_idx pending cross-document sort-usage review, and keep
-- node_fields_gin pending external query-usage review. event_target_node_idx
-- remains necessary for foreign-key checks during audited erasure.
drop index public.event_document_seq_idx;
