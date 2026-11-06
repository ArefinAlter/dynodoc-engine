# State Export Provenance Attestation

## Overview

Dynodoc engine normalized state export files (`.json`) capture canonical document
state envelopes at specific commit revisions. To satisfy Part 6 independent audit
requirements without requiring full repository exchange or access to server authority
databases, the engine provides cryptographic provenance attestations.

Attestations are stored in companion `.dynoattest` files alongside exported state
files. They cryptographically bind the exact state payload to an authority epoch,
signer key, commit address, and project UUID.

---

## Companion Attestation Format (`.dynoattest`)

A companion attestation file is written alongside `<filename>.json` as
`<filename>.json.dynoattest` with `0600` permissions (Unix). It contains a strict
canonical JSON object:

```json
{
  "version": 1,
  "project": "4d436d2c-3696-4eb0-b081-d89eb835943a",
  "authority_epoch": 2,
  "commit": "49d5c8f7ad5ad471e7e03fbfd9dc0f73620807e94559451a995f6b7a200c3e46",
  "signer_key": "321c87f3cc4c3fea4c588ae6028f3ac5128f397faf3c6e3b393bb14aa3633733",
  "state_digest": "5e9225c895fca4656e9b85b3fb91298490629f719d01c2cc9d3b5cb70e0b9c0c",
  "signature": "c2ab0352e586c53f8d4e30c0d26abdd9b5b79b631b79268843f4193c3215dd9c...",
  "issued_at_ms": 1793946931638
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `version` | `u32` | Format version (currently `1`). |
| `project` | `Uuid` | Document project identifier. |
| `authority_epoch` | `u32` | Authority epoch at signing time (`>= 1`). |
| `commit` | `Address` | 64-character hex SHA-256 commit address containing this state. |
| `signer_key` | `String` | 64-character hex Ed25519 public key of the certifying authority. |
| `state_digest` | `String` | SHA-256 hash of the exact UTF-8 / binary bytes of the state export file. |
| `signature` | `String` | 128-character hex Ed25519 signature over canonical signing payload. |
| `issued_at_ms` | `i64` | UTC timestamp in milliseconds when attestation was issued. |

---

## Canonical Signing Payload

The signing payload is constructed deterministically from the metadata:

```text
dynodoc.state-export.attestation:v1\n
project:<project-uuid>\n
epoch:<authority-epoch>\n
commit:<commit-hex>\n
digest:<state-digest-hex>\n
issued_at_ms:<issued-at-ms>\n
```

Signing is performed with standard RFC 8032 Ed25519 keys (`ring::signature::ED25519`).

---

## Verification Policy

When verifying an attestation with `AttestationVerificationPolicy`:

1. **State Digest:** The SHA-256 hash of the state export file on disk is computed and compared to `state_digest`. Any bit alteration, whitespace variation, or truncation causes `DigestMismatch`.
2. **Signature Validity:** The Ed25519 signature is verified against `signer_key` using the canonical payload. Tampered signatures cause `SignatureFailed`.
3. **Project Binding:** If the policy expects a project UUID, it must match `project`. Mismatch causes `ProjectMismatch`.
4. **Commit Binding:** If the policy expects a commit address, it must match `commit`. Mismatch causes `CommitMismatch`.
5. **Authority Epoch Bounds:**
   - If `min_epoch` is specified and `authority_epoch < min_epoch`, verification fails with `ExpiredEpoch`.
   - If `max_epoch` is specified and `authority_epoch > max_epoch`, verification fails with `FutureEpoch`.
6. **Trusted Signer Keys:** If `trusted_keys` is non-empty, `signer_key` must appear in the trusted key set. If not present, verification fails with `UntrustedKey`.

---

## CLI Usage

### Exporting with Automatic Attestation

```bash
dynodoc-engine export-file \
  --commit <commit-hash> \
  --path "Financials.docx" \
  --out /tmp/financials.json \
  --attest-key /path/to/authority.key \
  --attest-epoch 2
```
Emits `/tmp/financials.json` and companion `/tmp/financials.json.dynoattest`.

### Signing an Existing State Export File

```bash
dynodoc-engine state-export-attest /tmp/financials.json \
  --project <project-uuid> \
  --commit <commit-hash> \
  --epoch 2 \
  --key /path/to/authority.key
```

### Verifying State Export and Attestation

```bash
# Verifies envelope syntax, document state tree, and companion attestation:
dynodoc-engine state-export-verify /tmp/financials.json \
  --project <project-uuid> \
  --expect-commit <commit-hash> \
  --path "Financials.docx" \
  --trusted-key <pubkey-hex> \
  --min-epoch 1
```

All verification operations operate offline without database connections, WAL allocation, or write transactions.
