# Core and API panic audit

Production core and API libraries and the API binary warn on Clippy's
`unwrap_used` and `expect_used`; `task lint` makes warnings failures. Unit-test
code keeps ordinary assertions. No crate-wide allowance suppresses these lints.

The SSE registry now recovers its valid HashMap after a poisoned lock. A regression
poisons the real mutex, reconnects, and checks the per-document subscriber cap.
History range handling and portable receipt history return typed errors instead
of extracting unchecked optional values. Event readers and hashes are unchanged.

Remaining expectations have an explicit local proof and a function-local lint
allowance with its reason. They cover immutable validated options, fixed-width
cryptographic output, checked content headers and infallible owned JSON encoding.
Changing a listed proof requires revisiting the allowance.

| Source | Function | Proof |
| --- | --- | --- |
| `engine-api/src/agent/error.rs` | `agent_details` | details is the JSON object literal constructed above |
| `engine-api/src/auth/agent.rs` | `binding` | an agent login always carries its device binding |
| `engine-api/src/auth/token.rs` | `device_footer` | static footer claim |
| `engine-api/src/pagination.rs` | `encode` | cursor serialization is infallible |
| `engine-api/src/product.rs` | `pseudonym` | the configured SHA-256 HMAC has 32 bytes |
| `engine-api/src/project_activity.rs` | `project_activity_feed` | the folds guard checked the last group is present |
| `engine-core/src/governance.rs` | `plan_acceptance` | authorize() confirmed the suggestion is pending, so it exists |
| `engine-core/src/log.rs` | `write_canonical` | scalar JSON is infallible |
| `engine-core/src/log.rs` | `write_json_string` | string JSON is infallible |
| `engine-core/src/merge_policy/default.rs` | `policy` | the built-in default policy is valid |
| `engine-core/src/merge_policy/evidence.rs` | `to_json` | evidence is plain JSON data |
| `engine-core/src/merge_policy/policy.rs` | `canonical_value` | a policy is plain JSON data |
| `engine-core/src/merge_policy/registry.rs` | `builtin` | built-in strategy ids are unique |
| `engine-core/src/repository/horizon.rs` | `sha256` | ring SHA-256 always returns exactly 32 bytes |
| `engine-core/src/repository/horizon.rs` | `raw` | Address construction validates exactly 64 hexadecimal digits |
| `engine-core/src/repository/horizon.rs` | `address_of` | hex encoding 32 bytes yields a valid 64-digit Address |
| `engine-core/src/repository/horizon/plan.rs` | `build` | the while-let guard found the last stack entry |
| `engine-core/src/repository/horizon/plan.rs` | `compute_hash` | a plan is an object |
| `engine-core/src/repository/horizon/plan.rs` | `plan` | Graph::build validated every recovery reference exists |
| `engine-core/src/repository/horizon/policy.rs` | `canonical_bytes` | a policy value always encodes |
| `engine-core/src/richtext.rs` | `build` | the enclosing branch checked props(b) is present |
| `engine-core/src/richtext.rs` | `compact_event` | owned event fields serialize to JSON |
| `engine-core/src/richtext.rs` | `intern` | canonical JSON is valid UTF-8 |
| `engine-core/src/shared_checkpoint/content.rs` | `decode` | the matching branch checked the header length; the matching branch checked at least 21 bytes |
| `engine-core/src/shared_checkpoint/content.rs` | `finish` | the branch checked exactly one reference |
| `engine-core/src/shared_checkpoint/content.rs` | `reference` | reference callers pass a checked 40-byte record |
| `engine-core/src/transparency/assurance.rs` | `verify_checkpoint` | a cosignature carries a time |
| `engine-core/src/transparency/leaf.rs` | `mac` | configured SHA-256 HMAC returns 32 bytes |
| `engine-core/src/transparency/merkle.rs` | `root` | the full tree is stored |
| `engine-core/src/transparency/note.rs` | `key_id` | the digest prefix or checked signature prefix contains four bytes |
| `engine-core/src/transparency/note.rs` | `parse` | the digest prefix or checked signature prefix contains four bytes |
| `engine-core/src/transparency/note.rs` | `verifier_key` | Ed25519 public keys contain exactly 32 bytes |
| `engine-core/src/transparency/tiles.rs` | `node` | chunks_exact(32) yields only 32-byte slices |
| `engine-core/src/workspace_merge.rs` | `diff` | the preceding branch handled an absent prior node |
| `engine-core/src/workspace_merge.rs` | `merge_with` | the absent-base branch continued above; the absent-team branch continued above |

Nearby content-parser and cryptographic slices were checked against their length
guards. This adds no `indexing_slicing` gate and does not claim all Rust code is
panic-free: assertions, allocation failures and dependencies remain separate.
The existing historical replay, corruption and parser suites remain required.

Suggestion acceptance now uses a checked lookup after authorization on the same
immutable state. Its documented expectation replaces the older unchecked map
index and retains the already-proven pending-suggestion invariant. The production
scan includes shared checkpoints, snapshot verification, database and workload
modules; their existing conditional/error handling needs no blanket allowance.
