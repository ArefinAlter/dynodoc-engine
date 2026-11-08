-- A device's signing key and encryption key rotate independently (decision 035, OQ-CR-5, owner
-- decision of 6 November 2026; the CLI's `dynodoc-key-v2` file). A signing key may bind a new
-- encryption key, and its newest binding is the current one; a new signing key of the same
-- account may bind the encryption key it kept. Bindings stay append-only (0095). The API refuses
-- an encryption key another account has bound. Additive for every existing row.
drop index device_encryption_key_one_per_signing_key;
alter table device_encryption_key drop constraint device_encryption_key_public_key_key;
create unique index device_encryption_key_pair on device_encryption_key (signing_key_id, public_key);
create index device_encryption_key_public on device_encryption_key (public_key);
