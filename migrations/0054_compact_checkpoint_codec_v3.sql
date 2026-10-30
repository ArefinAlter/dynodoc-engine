-- Additive codec capability. Existing immutable manifests keep their v1/v2 roots.
-- Deploy v3-capable readers before opting any publisher into compact-v3.
alter table shared_checkpoint drop constraint shared_checkpoint_codec_version_check;
alter table shared_checkpoint add constraint shared_checkpoint_codec_version_check
    check (codec_version in (1, 2, 3));
