-- Refresh-token reuse detection (security review of main 362d4b1, finding 6). A refresh now
-- finds and rotates its grant in one statement, and the grant keeps the hashes of the last 16
-- refresh tokens it rotated away from. One of them presented again means a copy exists
-- somewhere else (RFC 9700 section 4.14.2): the grant's key is revoked, which ends the grant.
alter table oauth_grant add column rotated_hashes bytea[] not null default '{}'
    check (cardinality(rotated_hashes) <= 16);
