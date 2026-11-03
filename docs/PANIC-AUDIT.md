# Core and API panic audit

Production core and API libraries enforce Clippy's `unwrap_used` and `expect_used`
under `-D warnings`. SSE registries recover valid state after poisoned locks, and
history range and receipt lookups return typed errors rather than unwrapping options.

Remaining expectations have an explicit local proof and a function-local lint allowance:

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

Remaining assertions, allocation failures, and third-party dependencies are covered by existing historical replay and parser test suites.
