# History archive transport container format (v1)

15 October 2026. This defines the offline/streaming transport container for Dynodoc
project history and dependency closures. It provides verified transport across local
repositories, air-gapped environments, and independent audit tools.

## Byte contract

The stream begins with a 9-byte magic prefix:
```
b"DYNOARC\0\x01"
```
where `\x01` denotes archive container version 1.

### Frame layout

Every frame consists of a 4-byte little-endian length prefix followed by canonical UTF-8
JSON (lexically sorted keys, no insignificant whitespace).
```
[ 4-byte u32 LE length ][ canonical JSON payload ]
```
The maximum payload length per frame is 2 MiB (2,097,152 bytes). Empty frames (length 0)
and frames exceeding 2 MiB are strictly rejected.

### Frame sequence

Frames follow a strict state machine:
1. **Header frame** (strictly first):
   ```json
   {"head":"<64-hex>","kind":"header","project":"<uuid>","version":1}
   ```
   Fixes the archive format version (1), project UUID, and the single selected head commit address.
   Unknown fields are rejected.

2. **Object frames** (zero or more, preceding commits):
   ```json
   {"address":"<64-hex>","data":"<base64>","document":"<uuid>","kind":"object"}
   ```
   Carries the document UUID, content address, and strict canonical RFC 4648 base64-encoded
   canonical checkpoint object bytes. Address and object bytes are verified with `validate_stored`.
   Duplicate object keys `(document, address)` are rejected.

3. **Commit frames** (one or more, dependency-first):
   ```json
   {"address":"<64-hex>","envelope":"<base64>","kind":"commit"}
   ```
   Carries the commit address and base64-encoded verified `SignedCommit` envelope.
   Commits are topologically ordered dependency-first: all parent and recovery dependencies
   must appear in preceding commit frames within the archive. The final commit frame must
   match the `head` address specified in the header. Duplicate commit addresses are rejected.

4. **Footer frame** (strictly final):
   ```json
   {"bytes_before_footer":<u64>,"commits":<u64>,"kind":"footer","objects":<u64>,"sha256":"<64-hex>"}
   ```
   Contains exact counts of object and commit frames, the byte offset `bytes_before_footer`
   from byte 0 of the container magic up to the start of the footer frame's length prefix,
   and a lowercase 64-hex SHA-256 digest over all preceding bytes (including magic and frame
   length prefixes).

The footer acts as an exact truncation and framing check; it is not an independent signature.
Any trailing bytes after the footer payload are rejected.

## Bounds and streaming guarantees

- Readers validate base64 length estimates before allocating decoded buffers.
- Readers must not buffer the entire archive in memory; streaming validation operates
  frame-by-frame with bounded memory $O(\text{commit count})$.
- Total objects, total commits, total archive bytes, and per-frame bytes are governed by
  configurable `ArchiveLimits`.

## Versioning and scope boundaries

Archive container v1 carries existing portable commits (versions 1, 2, and 3) and their
referenced typed-v2 shared checkpoint object graphs. Archive version 1, Checkpoint v3,
SQLite schema 3, and SignedCommit version 3 are distinct version dimensions.

## Offline verification and integrity anchoring

An independently obtained expected head commit address anchors archive integrity.
A self-signed archive alone does not establish account authority, timestamps, server
freshness, or native-format fidelity: an attacker could author a validly signed self-consistent
fork. The expected head, obtained out-of-band or from an authoritative pin, ties the
archive's cryptographic closure to the operator's trusted history.

The offline verifier (`engine-cli archive-verify FILE --project UUID --expect-head ADDRESS`):
- Operates entirely offline with no target repository, network access, account keys, or branch writes.
- Uses bounded private temporary storage for frame staging and graph reachability validation.
- Requires the exact dependency and object closure: every commit must be reachable from `head`,
  and every object must be reachable from file roots within those commits.
- Rejects extraneous commits, unreferenced objects, duplicate frame keys (even identical),
  tampered signatures/payloads, and truncated or trailing data.
- Returns nonzero on any integrity or closure failure, or emits JSON summary with verified counts on success.
