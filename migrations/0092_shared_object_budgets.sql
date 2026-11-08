-- Shared-object budgets sized by measurement (decision 034). A compact v3 checkpoint
-- stores about fifteen objects per paragraph, so the 250,000-object document default of
-- schema 34 stopped checkpoints at roughly 16,000 paragraphs and the 1,000,000-object
-- account default at roughly 66,000, far below the byte budgets (1 GiB per document,
-- 4 GiB per account), which stay unchanged and remain the storage bound. Rows still at
-- the old defaults move to the new ones; rows an operator set are left as they are.
alter table checkpoint_storage_document alter column object_limit set default 16000000;
alter table checkpoint_storage_account alter column object_limit set default 64000000;
update checkpoint_storage_document set object_limit = 16000000 where object_limit = 250000;
update checkpoint_storage_account set object_limit = 64000000 where object_limit = 1000000;
