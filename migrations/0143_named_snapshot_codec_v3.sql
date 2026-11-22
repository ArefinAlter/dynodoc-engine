-- Named/deployed snapshots may refer to typed shared state v2 or compact v3.
-- Existing envelopes, receipts and rows are unchanged; only the accepted version widens.
-- Deploy v3-capable readers before opting any publisher into shared-v3.
alter table snapshot drop constraint snapshot_state_reference;
alter table snapshot drop constraint snapshot_reference_shape;
alter table snapshot drop column state_root;
alter table snapshot add column state_root text generated always as
    (case when state->>'$dynodoc_state' in ('2','3') then state->>'root' end) stored;
alter table snapshot add constraint snapshot_reference_shape check (
    not (state ? '$dynodoc_state') or coalesce(
        state->'$dynodoc_state' in ('2'::jsonb,'3'::jsonb) and jsonb_typeof(state->'root')='string'
        and (state-'$dynodoc_state'-'root')='{}'::jsonb
        and state_root ~ '^[0-9a-f]{64}$', false));
alter table snapshot add constraint snapshot_state_reference
    foreign key(document_id,state_root) references checkpoint_object(document_id,address)
    deferrable initially deferred;
