-- At-rest envelope encryption, Phase 0 backfill (decision 041; docs/AT-REST-ENVELOPE.md). NOT
-- end-to-end: the running service unwraps data keys and reads content.
--
-- checkpoint_object rows were immutable (0025). The backfill (`engine-cli kms backfill`, the
-- operator's migration login) re-encrypts existing rows in place, so exactly one update shape
-- is allowed: the same document and address, a plaintext object becoming a `DYNOENC` envelope.
-- Objects of encrypted projects (`DYNOSEAL`, typed v4) never change, and an envelope never goes
-- back to plaintext. Whether the envelope opens to the old bytes is checked by the backfill
-- (compare-and-set on the old bytes); the database cannot hold the key to check it.
create function checkpoint_object_at_rest_guard() returns trigger
language plpgsql set search_path = pg_catalog, public as $$
declare
    enc constant bytea := '\x44594e4f454e4300'::bytea;  -- 'DYNOENC' and a zero byte
begin
    if new.document_id <> old.document_id or new.address <> old.address
       or substring(new.bytes from 1 for 8) <> enc
       or substring(old.bytes from 1 for 8) = enc
       or substring(old.bytes from 1 for 8) = '\x44594e4f5345414c'::bytea
       or substring(old.bytes from 1 for 9) = '\x44594e4f5459500004'::bytea then
        raise exception 'checkpoint objects only change from plaintext to an at-rest envelope'
            using errcode = '23514', constraint = 'checkpoint_object_at_rest';
    end if;
    return new;
end $$;
drop trigger checkpoint_object_no_update on checkpoint_object;
create trigger checkpoint_object_no_update before update on checkpoint_object
    for each row execute function checkpoint_object_at_rest_guard();

-- An envelope is a few dozen bytes longer than its object: keep the storage budgets close.
-- Re-encryption is never refused for quota (it changes no content), so a budget already at its
-- limit stays at the limit.
create function account_shared_object_update() returns trigger
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
declare item record;
begin
    for item in
        select n.document_id, sum(octet_length(n.bytes) - octet_length(o.bytes)) as grown
        from new_objects n join old_objects o using (document_id, address)
        group by n.document_id order by n.document_id
    loop
        update public.checkpoint_storage_document set bytes_used = least(bytes_used + item.grown, byte_limit)
            where document_id = item.document_id;
        update public.checkpoint_storage_account a set bytes_used = least(a.bytes_used + item.grown, a.byte_limit)
            from public.checkpoint_storage_document q
            where q.document_id = item.document_id and a.identity_id = q.identity_id;
    end loop;
    return null;
end $$;
create trigger checkpoint_objects_account_update after update on checkpoint_object
    referencing old table as old_objects new table as new_objects
    for each statement execute function account_shared_object_update();

revoke execute on function checkpoint_object_at_rest_guard(), account_shared_object_update()
    from public;
