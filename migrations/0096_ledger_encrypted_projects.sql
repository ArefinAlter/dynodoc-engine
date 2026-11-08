-- Ledger mode in encrypted projects (decisions 028 and 035).
--
-- block_hash_key: 'plain' block hashes are SHA-256 of the block's stable JSON (decision 028);
-- 'keyed' ones are HMAC-SHA-256 under the document's ledger block key, which derives from a
-- document key the service never holds, so a short paragraph cannot be confirmed by guessing.
-- The service cannot recompute a keyed hash, so it never treats a keyed block as one whose full
-- state it holds (agents cannot propose on it). block_key_epoch names the epoch whose document
-- key the block key derives from; it is fixed with the mode.
alter table document_storage
    add column block_hash_key text not null default 'plain'
        check (block_hash_key in ('plain', 'keyed')),
    add column block_key_epoch integer check (block_key_epoch is null or block_key_epoch >= 1),
    add constraint document_storage_keyed_epoch
        check ((block_hash_key = 'keyed') = (block_key_epoch is not null));
