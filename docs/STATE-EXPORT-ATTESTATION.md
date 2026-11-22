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

A signature proves only that the key written in the attestation signed these bytes. It says
nothing about who holds that key, so a verdict about authority needs a trust anchor that
the verifier configured itself. An embedded signer key, or an epoch range the caller
supplies, does not create one.

Verification is `Authority` by default and needs at least one trusted key; with none it
fails with `NoTrustAnchor` instead of accepting any signer. `SignatureOnly` must be asked
for (`--signature-only`); it cannot be combined with trusted keys, and its result is
labelled `signature_only` so it is never read as trusted.

When verifying with `AttestationVerificationPolicy`:

1. **Policy:** contradictory settings fail with `InconsistentPolicy` (minimum epoch above the maximum, signature-only with trusted keys, a key window that ends before it starts).
2. **State Digest:** The SHA-256 hash of the state export file on disk is compared to `state_digest`. Any bit alteration, whitespace variation, or truncation causes `DigestMismatch`.
3. **Project and Commit Binding:** If the policy expects a project UUID or a commit address, it must match, else `ProjectMismatch` or `CommitMismatch`. The CLI always sets both from the export it verified.
4. **Epoch Limits:** `min_epoch` and `max_epoch` are plain limits (`ExpiredEpoch`, `FutureEpoch`). They are not rotation or revocation and do not show the signer was authorized at a real time.
5. **Trusted Signer Key:** In `Authority` mode `signer_key` must be a configured trusted key (`UntrustedKey`). Each trusted key carries its own epoch window, inclusive, with an optional end for a retired or revoked key; an attestation outside it fails with `KeyEpochOutsideWindow`. The CLI trusts a key in every epoch; narrower windows are set through the library.
6. **Signature Validity:** The Ed25519 signature is verified against `signer_key` using the canonical payload. Tampered signatures cause `SignatureFailed`.

The result is `Authority` or `SignatureOnly`. Neither is a timestamp-authenticity claim:
`issued_at_ms` is whatever the signer wrote.

An attestation is checked only when asked for. `state-export-verify` verifies the signed
manifest, the path and the full typed state root as always, and checks an attestation only
when `--attestation`, `--trusted-key`, `--min-epoch`, `--max-epoch` or `--signature-only`
is given; a `.dynoattest` file that merely sits next to the export is neither verified nor
trusted (the output says `attestation_not_checked`). When asked, both checks use one
bounded read of the export, so they describe the same bytes.

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
# Verifies envelope syntax and document state tree; with a trusted key, also the
# companion attestation as an authority verdict:
dynodoc-engine state-export-verify /tmp/financials.json \
  --project <project-uuid> \
  --expect-commit <commit-hash> \
  --path "Financials.docx" \
  --trusted-key <pubkey-hex> \
  --min-epoch 1

# Signature only, trusting nobody; the result is labelled signature_only:
dynodoc-engine state-export-verify /tmp/financials.json ... --signature-only
```

All verification operations operate offline without database connections, WAL allocation, or write transactions.
