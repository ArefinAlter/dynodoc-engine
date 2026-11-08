-- The remaining transparency leaf types (docs/DESIGN-WITNESSES-AND-TRANSPARENCY.md 4.1, decision
-- 042): `rot` for a receipt authority rotation or recovery (inserted by the operator command in
-- the transaction that installs the statement), `ver` for a named project release (inserted by
-- the API in the release's transaction) and `suc` for a log key rotation (inserted by the log
-- worker's rotate command, the first leaf the new key signs). The installation's blinding key
-- `k_installation` keys the rotation tag; it is created once by the operator credential and the
-- runtime only reads it.
alter table transparency_outbox drop constraint transparency_outbox_leaf_type_check;
alter table transparency_outbox add constraint transparency_outbox_leaf_type_check
    check (leaf_type in ('ref','rot','hzn','evh','ver','suc'));
create table transparency_installation_key (
    singleton boolean primary key default true check(singleton),
    tag_key bytea not null check(octet_length(tag_key)=32),
    created_at timestamptz not null default now()
);
create trigger transparency_no_update before update on transparency_installation_key
    for each row execute function event_immutable();
create trigger transparency_no_delete before delete on transparency_installation_key
    for each row execute function event_immutable();
create trigger transparency_no_truncate before truncate on transparency_installation_key
    for each statement execute function event_immutable();
revoke all on transparency_installation_key from public;
