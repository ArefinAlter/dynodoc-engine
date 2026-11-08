//! dynodoc engine core.
//!
//! The irreducible foundation: append-only hash-chained event log (stage 14),
//! snapshotted fold / materialization (stage 15), semantic ops + governance
//! (stage 16), referential integrity + semantic merge (stage 21).
//!
//! `log`, `materializer`/`snapshot`, `ops`, `governance`, the referential-integrity
//! pass, the ODK expression parser, and the semantic three-way merge are implemented
//! (stages 14–16 and 21).
//!
//! Without the default `persistence` feature only the pure modules build: hashing, fold,
//! operations, rich text, merge, integrity, expressions, governance and similarity. That
//! set has no database, runtime, clock or random source and compiles to
//! `wasm32-unknown-unknown` (`crates/engine-wasm`, decision 036).

#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

#[cfg(feature = "persistence")]
pub mod at_rest;
#[cfg(feature = "persistence")]
pub mod database;
pub mod e2ee;
#[cfg(feature = "persistence")]
pub mod event_merkle;
pub mod expr;
pub mod governance;
pub mod hashing;
pub mod integrity;
#[cfg(feature = "persistence")]
pub mod log;
pub mod materializer;
// The benchmark runs the policy merge, which needs persistence (decision 042).
#[cfg(feature = "persistence")]
pub mod merge_bench;
pub mod merge_policy;
// Server-side Office package reading for streaming import (decision 034); not in the pure build.
#[cfg(feature = "persistence")]
pub mod ooxml;
pub mod ops;
#[cfg(feature = "persistence")]
pub mod projection;
pub mod repository;
pub mod richtext;
pub mod shared_checkpoint;
pub mod similarity;
#[cfg(feature = "persistence")]
pub mod snapshot;
#[cfg(feature = "persistence")]
pub mod snapshot_verification;
#[cfg(feature = "persistence")]
pub mod transparency;
pub mod workspace_merge;
