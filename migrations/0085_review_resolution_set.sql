-- Decision 033: an approval of a v4 merge with automatic resolutions under review
-- binds the resolution-set hash the reviewer was shown (node-conflict design 6.4).
-- Nullable: reviews of other commits bind nothing, and earlier rows are unchanged.
alter table project_history_review
    add column resolution_set text check (resolution_set ~ '^[0-9a-f]{64}$');
