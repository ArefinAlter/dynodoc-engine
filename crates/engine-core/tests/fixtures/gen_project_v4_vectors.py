#!/usr/bin/env python3
"""Independent generator for project-v4.json (Python standard library only).

Run:  python -I gen_project_v4_vectors.py      (rewrites project-v4.json next to this
file; the output is deterministic, so a clean `git diff` afterwards shows the
committed file is reproduced, and a second run changes nothing.)

Nothing here shares code with the Rust modules under test
(crates/engine-core/src/repository/{relocation,project}.rs). It implements, from
the text of docs/DESIGN-CROSS-DOCUMENT-MERGE.md and decision 033:

  * relocation_id = hex SHA-256(b"dynodoc.relocation\x00v1\x00" || kind || 0 ||
    from_document || 0 || roots joined by "," || 0 || to_document || 0 ||
    to_parent || 0 || to_position), UUIDs hyphenated lowercase;
  * dest_id(n) = the 26-character Crockford base32 ULID text of the first 16 bytes
    of SHA-256(b"dynodoc.node-derive\x00v1\x00" || relocation_id as 32 bytes || n);
  * the v4 commit canonical form (sorted keys, compact separators, UTF-8), its
    address SHA-256(b"dynodoc.project-commit\x00v4\x00" || canonical) and the Ed25519
    signature over b"dynodoc.project-commit-signature\x00v4\x00" || address bytes, with
    the public synthetic seed of 32 bytes of 7;
  * the commit-level resolution-set hash SHA-256(b"dynodoc.resolution-set\x00v1\x00" ||
    canonical JSON of [{document, strategy, resolution_set}] in record order).

The Ed25519 block is copied unchanged from gen_transparency_vectors.py and checked
against RFC 8032 section 7.1 on every run. Both sides were written by one author
from one specification: the vectors catch implementation bugs and drift, not a
shared misreading. State addresses are placeholders; no document content exists.
"""
import hashlib
import json
import os

# ---- Ed25519 (RFC 8032 section 5.1, pure Python) ---------------------------
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def inv(x):
    return pow(x, P - 2, P)


def recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


G_Y = 4 * inv(5) % P
G_X = recover_x(G_Y, 0)
G = (G_X, G_Y, 1, G_X * G_Y % P)


def point_add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    DD = 2 * a[2] * b[2] % P
    E, F, GG, H = B - A, DD - C, DD + C, B + A
    return (E * F % P, GG * H % P, F * GG % P, E * H % P)


def point_mul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = point_add(q, point)
        point = point_add(point, point)
        s >>= 1
    return q


def point_equal(a, b):
    if (a[0] * b[2] - b[0] * a[2]) % P != 0:
        return False
    return (a[1] * b[2] - b[1] * a[2]) % P == 0


def point_compress(point):
    zinv = inv(point[2])
    x, y = point[0] * zinv % P, point[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def point_decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def sha512(data):
    return hashlib.sha512(data).digest()


def sha512_modq(data):
    return int.from_bytes(sha512(data), "little") % Q


def secret_expand(secret):
    assert len(secret) == 32
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed_public(secret):
    a, _ = secret_expand(secret)
    return point_compress(point_mul(a, G))


def ed_sign(secret, msg):
    a, prefix = secret_expand(secret)
    public = point_compress(point_mul(a, G))
    r = sha512_modq(prefix + msg)
    big_r = point_compress(point_mul(r, G))
    h = sha512_modq(big_r + public + msg)
    s = (r + h * a) % Q
    return big_r + int.to_bytes(s, 32, "little")


def ed_verify(public, msg, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = point_decompress(public)
    r = point_decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:
        return False
    h = sha512_modq(signature[:32] + public + msg)
    return point_equal(point_mul(s, G), point_add(r, point_mul(h, a)))


RFC8032_VECTORS = [
    # (secret, public, message, signature) from RFC 8032 section 7.1, recalled from memory.
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


def check_ed25519():
    checked = 0
    for secret, public, message, signature in RFC8032_VECTORS:
        secret, message, signature = map(bytes.fromhex, (secret, message, signature))
        got_public = ed_public(secret)
        got_signature = ed_sign(secret, message)
        if got_public.hex() != public:
            raise SystemExit("RFC 8032 public key mismatch for " + secret.hex()[:8])
        if got_signature != signature:
            raise SystemExit("RFC 8032 signature mismatch for " + secret.hex()[:8])
        if not ed_verify(got_public, message, signature):
            raise SystemExit("RFC 8032 verification failed for " + secret.hex()[:8])
        if ed_verify(got_public, message + b"x", signature):
            raise SystemExit("verification accepted a different message")
        checked += 1
    return checked




def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def relocation_id(kind, from_doc, roots, to_doc, parent, position):
    parts = [kind, from_doc, ",".join(roots), to_doc, parent, position]
    return hashlib.sha256(b"dynodoc.relocation\x00v1\x00" + b"\x00".join(p.encode("utf-8") for p in parts)).hexdigest()


def dest_id(rid, node):
    digest = hashlib.sha256(b"dynodoc.node-derive\x00v1\x00" + bytes.fromhex(rid) + node.encode("utf-8")).digest()
    n = int.from_bytes(digest[:16], "big")
    return "".join(CROCKFORD[(n >> (5 * (25 - i))) & 31] for i in range(26))


SEED = bytes([7] * 32)
PUBLIC = ed_public(SEED).hex()


def signed(commit):
    commit = dict(commit, author_key=PUBLIC)
    body = canonical(commit)
    address = hashlib.sha256(b"dynodoc.project-commit\x00v4\x00" + body).hexdigest()
    signature = ed_sign(SEED, b"dynodoc.project-commit-signature\x00v4\x00" + bytes.fromhex(address)).hex()
    return {"canonical": body.decode("utf-8"), "address": address, "signed": {"commit": commit, "signature": signature}}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    rfc = check_ed25519()
    with open(os.path.join(here, "merge-policy-v1.json"), encoding="utf-8") as f:
        minimal = next(v for v in json.load(f)["vectors"] if v["name"] == "minimal")
    project = "00000000-0000-0000-0000-000000000005"
    p_doc = "00000000-0000-0000-0000-0000000000a1"
    a_doc = "00000000-0000-0000-0000-0000000000a2"
    x_doc = "00000000-0000-0000-0000-0000000000a3"
    root, s2, n5 = "01JR0000000000000000000000", "01JS2000000000000000000000", "01JN5000000000000000000000"
    rid = relocation_id("split", p_doc, [s2], a_doc, root, "a3")
    relocation = {
        "id": rid,
        "kind": "split",
        "from": {"document": p_doc, "roots": [s2]},
        "to": {"document": a_doc, "parent": root, "position": "a3"},
        "count": 14,
        "source_state_after": "33" * 32,
        "dest_state_after": "44" * 32,
    }
    split = signed({
        "version": 4,
        "project": project,
        "parents": ["11" * 32],
        "files": {
            "Proposal.docx": {"document": p_doc, "state": "33" * 32},
            "Appendix.docx": {"document": a_doc, "state": "44" * 32},
        },
        "authored_at_ms": 1700000000000,
        "message": "Split the methods section into an appendix",
        "relocations": [relocation],
    })
    records = [
        {
            "id": "r1",
            "strategy": "dynodoc.project.rename-follow.v1",
            "document": x_doc,
            "base": "50" * 32, "left": "50" * 32, "right": "55" * 32, "merged": "55" * 32,
            "path": {"base": "Budget.xlsx", "left": "Finance/Budget.xlsx", "right": "Budget.xlsx", "merged": "Finance/Budget.xlsx"},
        },
        {
            "id": "r2",
            "strategy": "dynodoc.project.edit-follows-move.v1",
            "document": a_doc,
            "base": None, "left": "44" * 32, "right": None, "merged": "66" * 32,
            "relocation": rid,
            "follows": "left",
            "source": {"document": p_doc, "base": "88" * 32, "left": "33" * 32, "right": "99" * 32, "merged": "77" * 32},
            "needs_review": True,
            "resolution_set": "ab" * 32,
        },
    ]
    merge = signed({
        "version": 4,
        "project": project,
        "parents": ["11" * 32, "22" * 32],
        "files": {
            "Finance/Budget.xlsx": {"document": x_doc, "state": "55" * 32},
            "Appendix.docx": {"document": a_doc, "state": "66" * 32},
            "Proposal.docx": {"document": p_doc, "state": "77" * 32},
        },
        "authored_at_ms": 1700000000001,
        "message": "Merge the appendix split and the budget rename",
        "project_resolutions": records,
        "merge_policy": {"hash": minimal["sha256"], "policy": json.loads(minimal["canonical"])},
    })
    entries = [{"document": r["document"], "strategy": r["strategy"], "resolution_set": r.get("resolution_set")} for r in records]
    merge["resolution_set_hash"] = hashlib.sha256(b"dynodoc.resolution-set\x00v1\x00" + canonical(entries)).hexdigest()
    out = {
        "generator": "Independent Python SHA-256, canonical JSON, Crockford ULID and RFC 8032 Ed25519 (%d RFC vectors checked); public synthetic seed 7; placeholder states" % rfc,
        "relocation": {
            "spec": {"kind": "split", "from_document": p_doc, "roots": [s2], "to_document": a_doc, "parent": root, "position": "a3"},
            "id": rid,
            "dest_ids": {node: dest_id(rid, node) for node in [root, s2, n5]},
        },
        "split_commit": split,
        "merge_commit": merge,
    }
    with open(os.path.join(here, "project-v4.json"), "w", encoding="utf-8", newline=chr(10)) as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write(chr(10))


if __name__ == "__main__":
    main()
