-- Local SQLite schema 3 -> 4, run once inside the transaction that applies the first
-- history horizon (docs/DESIGN-COMMIT-PRUNING.md section 5.3, decision 032). Additive:
-- no existing row, address, signature or trigger changes. Schema-3 binaries refuse a
-- schema-4 file up front, so a pruned repository never reads as "missing commit".
--
-- history_horizon keeps the canonical signed envelope and the normalized policy it was
-- applied under (so `horizon-verify` can recompute the policy hash and the signature
-- requirement offline). Rows are immutable.
create table history_horizon (
    sequence integer primary key check(sequence>=1),
    address text not null unique check(length(address)=64),
    envelope blob not null check(length(envelope) between 1 and 69632),
    policy blob not null check(length(policy) between 1 and 65536),
    applied_wall_ms integer not null
);
create trigger history_horizon_no_update before update on history_horizon
    begin select raise(abort,'immutable horizon'); end;
create trigger history_horizon_no_delete before delete on history_horizon
    begin select raise(abort,'immutable horizon'); end;

-- A horizon whose released history was restored from its archive. The horizon row
-- stays (the chain is append-only); its skeleton, frontier and released-state rows go.
create table history_rehydration (
    sequence integer primary key references history_horizon(sequence),
    archive_sha256 text not null check(length(archive_sha256)=64),
    rehydrated_wall_ms integer not null
);
create trigger history_rehydration_no_update before update on history_rehydration
    begin select raise(abort,'immutable rehydration'); end;
create trigger history_rehydration_no_delete before delete on history_rehydration
    begin select raise(abort,'immutable rehydration'); end;

-- Released commits: address, ordered parents (0, 64 or 128 hex digits) and height.
create table history_skeleton (
    address text primary key check(length(address)=64),
    parents text not null check(length(parents) in (0,64,128)),
    height integer not null check(height>=0),
    horizon_sequence integer not null references history_horizon(sequence)
);
create table history_frontier (
    child text not null check(length(child)=64),
    parent text not null check(length(parent)=64),
    parent_height integer not null check(parent_height>=0),
    horizon_sequence integer not null references history_horizon(sequence),
    primary key(child,parent)
);
create table history_released_state (
    document text not null,
    state_root text not null check(length(state_root)=64),
    horizon_sequence integer not null references history_horizon(sequence),
    primary key(document,state_root)
);
-- Rows change only by rehydration of their own horizon.
create trigger history_skeleton_no_update before update on history_skeleton
    begin select raise(abort,'immutable skeleton'); end;
create trigger history_skeleton_no_delete before delete on history_skeleton
    when not exists(select 1 from history_rehydration where sequence=old.horizon_sequence)
    begin select raise(abort,'immutable skeleton'); end;
create trigger history_frontier_no_update before update on history_frontier
    begin select raise(abort,'immutable frontier'); end;
create trigger history_frontier_no_delete before delete on history_frontier
    when not exists(select 1 from history_rehydration where sequence=old.horizon_sequence)
    begin select raise(abort,'immutable frontier'); end;
create trigger history_released_state_no_update before update on history_released_state
    begin select raise(abort,'immutable released state'); end;
create trigger history_released_state_no_delete before delete on history_released_state
    when not exists(select 1 from history_rehydration where sequence=old.horizon_sequence)
    begin select raise(abort,'immutable released state'); end;

-- Skeleton entries from a remote's verified horizon chain for commits this repository
-- holds no body for (a shallow fetch, design phase P4). A cache of verified remote
-- facts, not a local horizon: a row goes when the commit's body is imported.
create table history_remote_skeleton (
    address text primary key check(length(address)=64),
    parents text not null check(length(parents) in (0,64,128)),
    height integer not null check(height>=0),
    horizon text not null check(length(horizon)=64),
    sequence integer not null check(sequence>=1)
);

-- Releasing a commit body or an object drops and restores the immutability guards
-- inside the applying transaction, exactly as the staged-object collector does, and
-- lowers the capacity counters explicitly before comparing them with a recount (H9).
-- Skeleton and horizon rows are not charged to the local counters (decision 032).
update local_meta set version=4 where singleton=1;
