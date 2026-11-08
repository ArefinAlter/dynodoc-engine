-- Live event fan-out across API replicas (docs/SELF-HOSTED-EDITION.md 6.2, decision 037).
--
-- One notification per document per inserting statement, sent inside the inserting transaction
-- and so delivered only on commit, in commit order: `<document uuid>:<first seq>:<last seq>`
-- on channel `dynodoc_event` (under 100 bytes; event bodies are never in the payload). An API
-- process in `DYNODOC_EVENT_FANOUT=postgres` mode listens and reads the range from `event` for
-- the documents it has live streams for. In the default `local` mode nobody listens and a
-- notification costs a few bytes in the queue until commit.
--
-- Additive: history and its append-only guards are unchanged. The function is not a security
-- definer; the runtime login fires it as itself (pg_notify is available to every role).
create function event_notify() returns trigger
language plpgsql set search_path = pg_catalog, public, pg_temp as $$
begin
    perform pg_notify('dynodoc_event', s.document_id::text || ':' || s.first_seq::text || ':' || s.last_seq::text)
       from (select document_id, min(seq) as first_seq, max(seq) as last_seq
               from new_rows group by document_id) s;
    return null;
end $$;
revoke all on function event_notify() from public;
create trigger event_notify_after_insert
    after insert on event referencing new table as new_rows
    for each statement execute function event_notify();
