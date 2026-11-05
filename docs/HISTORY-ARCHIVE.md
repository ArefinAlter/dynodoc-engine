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
- `ArchiveReader` reads frame by frame and keeps only the seen object and commit keys.
  The closure checks behind `archive-verify` and `archive-import` write each object to
  private temporary disk but keep the parsed commit envelopes in memory, so their
  memory grows with the commit bytes in the archive (at most the total byte limit).
- Total objects, total commits, total archive bytes, and per-frame bytes are governed by
  configurable `ArchiveLimits`. Defaults: 100,000 objects, 10,000 commits, 2 MiB per
  frame and 512 MiB per archive.
- The format has no compression and carries no file names: staged objects are named by
  their position, so archive content never chooses a path on disk.

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

The offline verifier (`engine-cli archive-verify FILE --project UUID --expect-head ADDRESS`; it
refuses an incremental archive, whose base and history are not in the file, and so never reports a
delta as a verified complete history):
- Operates entirely offline with no target repository, network access, account keys, or branch writes.
- Uses bounded private temporary storage for frame staging and graph reachability validation.
- Requires the exact dependency and object closure: every commit must be reachable from `head`,
  and every object must be reachable from file roots within those commits.
- Rejects extraneous commits, unreferenced objects, duplicate frame keys (even identical),
  tampered signatures/payloads, and truncated or trailing data.
- Returns nonzero on any integrity or closure failure, or emits JSON summary with verified counts on success.

The same check is available as `engine-cli repository DATABASE PROJECT archive-verify FILE
--expect-head ADDRESS`, which does not open the database.

## Export and import

`engine-cli repository DATABASE PROJECT archive-export HEAD [--since BASE] --out FILE` opens the database
read-only and writes the dependency closure of `HEAD` (parents and recovery sources) and
every object those commits reference. When `--since BASE` is provided, graph traversal stops at
the base closure, emitting only newly added commits and referenced objects not present in the
base closure. `HEAD` must be a direct or indirect descendant of `BASE` (or equal, yielding an
empty delta archive). Other branches and staged objects outside that
closure are not included. The archive does include every file of every commit in the
closure, with commit messages and author keys: share it only with readers allowed to see
that whole history. The output is a new owner-only file (an existing path is refused); it is
removed if the export fails and synced to disk before success is reported.

`engine-cli repository DATABASE PROJECT archive-import FILE --expect-head ADDRESS` runs the
complete offline verification first, including a semantic import into a disposable private
repository, before it creates, opens or upgrades the target database. It then copies the
objects in transfer batches (at most 64 objects / 1 MiB each) and the commits in dependency
order. It never creates or moves a branch and never raises storage limits. If the target
fails part way, for example at its capacity limit, the error reports how many objects and
commits were already imported; those rows stay, like any committed transfer batch, and
are charged to capacity. A retry is idempotent. Moving a branch to the imported head is a
separate, explicit step.

## Normalized state export

`engine-cli repository DATABASE PROJECT export-file --commit ADDRESS --path PATH --out FILE`
(local, read-only) and `engine-cli sync ... export-file --commit ADDRESS --path PATH --out FILE`
(remote, `history:read`; fetched objects go to a private temporary directory that is
removed afterwards, never to the local repository) write one historical file as a
`dynodoc.state-export` version 1 JSON envelope: `format`, `version`, `path`, the complete
signed commit and the reconstructed `DocumentState`. It is the normalized document model,
not a DOCX, XLSX or PPTX file. The signed commit is needed for verification and names
every path, document id and state root in the project at that commit, with its message
and author key. The output is a new owner-only file of at most 64 MiB.

`engine-cli state-export-verify FILE --project UUID --expect-commit ADDRESS --path PATH`
works offline. It rejects duplicate JSON keys, trailing data, unknown fields, another
format or version, and a file over 64 MiB. It checks that the commit signature is valid
for the key inside the commit, that the commit address equals the expected address and
the project the expected project, and that re-encoding the supplied state with the
typed-v2 rules gives exactly the state root the signed commit lists for `PATH`.

What this proves: the state is exactly the one that commit records for that path. The
anchor is the expected commit address, which you must obtain independently (for example
from a branch head you trust or a server receipt). The signature alone only proves that
someone holding the embedded key signed it; it does not identify an account or device,
prove the timestamp, or show that the commit is still current on any server. It also
does not prove that a native Office file opened from this state matches the original.
