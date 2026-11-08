-- Sealed agent authorship (decision 038, attribution layer C of docs/AI-AGENT-CONNECTORS.md 6.3).
--
-- When a person merges an AI agent's change request, the server appends one `ChangeAttributed`
-- event after the merged content events, in the same transaction. It names the agent, the person
-- it acted for, the merger, the approvals and, for every merged event, the agent session turn that
-- produced it (or the person whose edit took the block over). It is an ordinary event: its
-- payload is framed into content_hash and the chain, so a changed record breaks verification.
-- No existing event changes, and no row is rewritten: documents without agent merges never hold
-- the new type. Readers built before this schema refuse such a document (an unknown event type);
-- the API refuses a schema newer than its own, so rolling back means restoring the dump.

alter table event drop constraint event_type_check;
alter table event add constraint event_type_check check (type in (
 'NodeCreated','NodeMoved','NodeDeleted','NodeRestored','FieldEdited','RichTextPatched',
 'ChoiceAdded','ChoiceRemoved','CommentAdded','CommentReplied','CommentResolved',
 'SuggestionProposed','SuggestionAccepted','SuggestionRejected','Deployed','ChangeAttributed'
));

-- Block history reads the seal that covers an event; seals are few per document.
create index event_attribution_idx on event(document_id, seq) where type = 'ChangeAttributed';
