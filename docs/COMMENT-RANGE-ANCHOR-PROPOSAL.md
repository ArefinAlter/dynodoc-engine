# Comment range anchors

Proposal, 30 October 2026. This is not an implemented wire contract.

## Choice

Use a checked range inside one stable node. Keep comments at node level when a
range cannot be verified. Defer durable span IDs to the nested-identity contract.
This gives existing editors a small adapter without changing historical replay.

An anchor records the document ID, node ID, base revision, content hash, half-open
range and selected text. Count Unicode scalars, as rich-text patches do. Reject
offsets inside an inline atom. Bound the quote and surrounding context in bytes.
Use the existing rich-text flattening rules; formatting is not text identity.

## Resolution

At the checked base, verify the content hash, bounds and selected text together.
Reject a different document, missing node or unsupported structure.

After edits, transform the range only through supported, verified patches.
Insertion at a boundary stays outside the selection. Insertion strictly inside
extends it. An overlapping deletion, node split/join or missing history makes
the range unresolved. Keep the original anchor and show the node-level thread.
Quote/context search may suggest a new range. It must not silently reattach it.
Repeated quotes remain ambiguous. Reattachment requires an explicit user action.

## Compatibility and access

Keep existing CommentAdded payloads, event hashes, snapshots and receipts intact.
Do not add optional anchor bytes to the existing event serializer. Before shipping
anchors, define a versioned event/read contract and coordinate all consumers.
Existing unanchored comments and node-level comments must still load unchanged.

Every create, read and reattachment checks current document access. Connector
grants retain their existing node scope and cannot gain merge permission.
The API verifies anchors against retained server content, not a client assertion.
Native comment carriers and the web display belong to the application repository.

## Implementation acceptance

Cover emoji, combining text, inline atoms, empty ranges, repeated quotes, boundary
inserts, overlapping deletes, missing history and inaccessible documents.
Prove old event bytes and snapshot receipts stay unchanged. Test export/import
and explicit reattachment in each supported editor before claiming native support.
