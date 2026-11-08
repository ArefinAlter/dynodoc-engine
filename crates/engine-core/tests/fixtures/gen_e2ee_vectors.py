#!/usr/bin/env python3
"""Independent generator for e2ee-v1.json (no dynodoc code).

Needs the PyPI package `cryptography` (OpenSSL AES-256-GCM, X25519, Ed25519); HKDF, HMAC
and SHA-256 come from the standard library (`hmac`, `hashlib`), and HPKE base mode is written
here from RFC 9180 sections 4, 5.1 and 7.1. Run from an empty scratch directory:

    python -m pip install --target DEPS cryptography
    python -I gen_e2ee_vectors.py DEPS > e2ee-v1.json

The output is deterministic. Every key, seed, salt and ephemeral seed is synthetic and
public; none may ever protect real data.

Written from docs/E2EE-CRYPTOGRAPHIC-DESIGN.md (sections 4 to 11 and appendix A) and the
refinements of docs/decisions/035, not from the Rust or TypeScript modules. Both reproduce
every value byte for byte (`tests/e2ee_vectors_test.rs` in the app, `src/e2ee.test.ts` in the
SDK). Never regenerate the fixture to make an implementation pass.

Cross-checks run on every execution (the script aborts if any fails):
  * HKDF-SHA-256 against RFC 5869 test case 1;
  * HPKE base mode against RFC 9180 appendix A.1.1 (X25519, HKDF-SHA256, AES-128-GCM);
  * the sealed object of the design's appendix A, computed there with Node.js WebCrypto;
  * every ciphertext opens again.
"""
import base64
import hashlib
import hmac
import json
import struct
import sys

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else ".")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def check(cond, what):
    if not cond:
        raise SystemExit("self-check failed: " + what)


def h(b):
    return b.hex()


def sha256(*parts):
    d = hashlib.sha256()
    for p in parts:
        d.update(p)
    return d.digest()


def hmac256(key, *parts):
    m = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(p)
    return m.digest()


def hkdf_extract(salt, ikm):
    return hmac256(salt if salt else b"\x00" * 32, ikm)


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac256(prk, t, info, bytes([i]))
        out += t
        i += 1
    return out[:length]


def hkdf(ikm, salt, info, length):
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


check(h(hkdf(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
             bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)) ==
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
      "RFC 5869 test case 1")


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def lp(b):
    return struct.pack(">Q", len(b)) + b


def uuid_bytes(u):
    return bytes.fromhex(u.replace("-", ""))


def x_pub(sk):
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed_pub(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed_sign(seed, message):
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


# ---- HPKE base mode, RFC 9180 -------------------------------------------------------------
def i2osp(n, w):
    return n.to_bytes(w, "big")


KEM_X25519 = 0x20
KEM_SUITE = b"KEM" + i2osp(KEM_X25519, 2)


def hpke_suite(aead):
    return b"HPKE" + i2osp(KEM_X25519, 2) + i2osp(1, 2) + i2osp(aead, 2)


def labeled_extract(suite, salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return hkdf_expand(prk, i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length)


def derive_keypair(ikm):
    prk = labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm)
    sk = labeled_expand(KEM_SUITE, prk, b"sk", b"", 32)
    return sk, x_pub(sk)


def hpke_seal(pk_r, info, aad, pt, ikm_e, aead=2):
    sk_e, pk_e = derive_keypair(ikm_e)
    dh = X25519PrivateKey.from_private_bytes(sk_e).exchange(X25519PublicKey.from_public_bytes(pk_r))
    kem_context = pk_e + pk_r
    eae = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    shared = labeled_expand(KEM_SUITE, eae, b"shared_secret", kem_context, 32)
    suite = hpke_suite(aead)
    nk = 32 if aead == 2 else 16
    psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(suite, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(suite, shared, b"secret", b"")
    key = labeled_expand(suite, secret, b"key", context, nk)
    nonce = labeled_expand(suite, secret, b"base_nonce", context, 12)
    return pk_e, AESGCM(key).encrypt(nonce, pt, aad), {"shared": shared, "key": key, "nonce": nonce, "sk_e": sk_e}


# RFC 9180 A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
_enc, _ct, _k = hpke_seal(
    x_pub(bytes.fromhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")),
    bytes.fromhex("4f6465206f6e2061204772656369616e2055726e"),
    bytes.fromhex("436f756e742d30"),
    bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479"),
    bytes.fromhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"), aead=1)
check(h(_k["sk_e"]) == "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736", "RFC 9180 skEm")
check(h(_enc) == "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431", "RFC 9180 enc")
check(h(_k["shared"]) == "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc", "RFC 9180 shared secret")
check(h(_k["key"]) == "4531685d41d65f03dc48f6b8302c05b0", "RFC 9180 key")
check(h(_k["nonce"]) == "56d890e5accaaf011cff4b7d", "RFC 9180 base nonce")
check(h(_ct) == "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a", "RFC 9180 ciphertext")

# ---- key hierarchy (design 4) --------------------------------------------------------------
def meta_key(root):
    return hkdf(root, b"", b"dynodoc.k.meta.v1", 32)


def cid_key(root):
    return hkdf(root, b"", b"dynodoc.k.cid.v1", 32)


def doc_key(root, project, document):
    return hkdf(root, b"", b"dynodoc.k.doc.v1" + uuid_bytes(project) + uuid_bytes(document), 32)


def ledger_block_key(kdoc):
    return hkdf(kdoc, b"", b"dynodoc.k.ledger-block.v1", 32)


def key_id(epoch, root):
    return sha256(b"dynodoc.key-id.v1\x00", struct.pack(">I", epoch), root)[:8]


# ---- sealed objects (design 8) -------------------------------------------------------------
KINDS = {"node_fields": 1, "text_chunk": 2, "comment": 3, "suggestion": 4, "meta": 5,
         "asset_chunk": 6, "bundle": 7, "event": 8, "state_index": 9}
BUCKETS = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]


def padded(n):
    for b in BUCKETS:
        if b >= n:
            return b
    return n


def aad(project, document, node, kind, epoch, revision, refs):
    return (lp(b"dynodoc.seal.v1") + lp(uuid_bytes(project)) +
            lp(uuid_bytes(document) if document else b"\x00" * 16) + lp(node.encode()) +
            lp(bytes([kind])) + struct.pack(">I", epoch) + struct.pack(">Q", revision) +
            lp(b"\x01") + lp(sha256(b"".join(refs))))


def body(kcid, kind, content):
    c = canon(content)
    cid = hmac256(kcid, b"dynodoc.cid.v1\x00", bytes([kind]), c)
    return canon({"cid": h(cid), ("fields" if kind == 1 else "value"): content, "v": 1}), cid


def seal(key, kid, kcid, project, document, node, kind, epoch, revision, refs, content, salt, pad_byte=0):
    refs = sorted(refs)
    b, cid = body(kcid, kind, content)
    framed = struct.pack(">I", len(b)) + b
    plain = framed + bytes([pad_byte]) * 0 + b"\x00" * (padded(len(framed)) - len(framed))
    if pad_byte:
        plain = plain[:-1] + bytes([pad_byte])
    a = aad(project, document, node, kind, epoch, revision, refs)
    okm = hkdf(key, salt, b"dynodoc.seal.v1/aead+nonce+commit\x00\x01", 76)
    k, nonce, ck = okm[:32], okm[32:44], okm[44:76]
    commitment = hmac256(ck, a)[:16]
    header = (b"DYNOSEAL" + bytes([1, 1, kind, 0]) + struct.pack(">I", epoch) + kid + salt +
              commitment + struct.pack(">H", len(refs)) + b"".join(refs))
    sealed = AESGCM(k).encrypt(nonce, plain, a)
    out = header + sealed
    check(AESGCM(k).decrypt(nonce, sealed, a) == plain, "seal opens")
    return out, {"aad": h(a), "aead_key": h(k), "nonce": h(nonce), "commit_key": h(ck),
                 "key_commitment": h(commitment), "cid": h(cid), "body": b.decode(),
                 "address": h(sha256(b"dynodoc.sealed-object\x00v1\x00", out))}


P = "a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf"
D = "b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf"
NODE = "01J9ZK3Q8M2V7N4X5C6D7E8F9G"
PER3 = bytes(range(32))
FIELDS = {"content": {"content": [{"text": "Revenue grew 5%.", "type": "text"}], "type": "paragraph"},
          "label": "Revenue grew 5%."}

keys_out = []
for epoch, root in [(3, PER3), (4, bytes(range(32, 64)))]:
    keys_out.append({"epoch": epoch, "root": h(root), "project": P, "document": D,
                     "meta": h(meta_key(root)), "cid": h(cid_key(root)),
                     "doc": h(doc_key(root, P, D)), "key_id": h(key_id(epoch, root)),
                     "ledger_block": h(ledger_block_key(doc_key(root, P, D)))})

seal_cases = []


def seal_case(name, keyname, document, node, kind, epoch, revision, refs, content, salt, root=PER3):
    key = {"doc": doc_key(root, P, D), "meta": meta_key(root)}[keyname]
    out, d = seal(key, key_id(epoch, root), cid_key(root), P, document, node, KINDS[kind], epoch,
                  revision, refs, content, salt)
    case = {"name": name, "root": h(root), "key": keyname, "project": P, "document": document,
            "node": node, "kind": kind, "epoch": epoch, "revision": revision,
            "refs": [h(r) for r in refs], "content": content, "salt": h(salt), "envelope": h(out)}
    case.update(d)
    seal_cases.append(case)
    return out, d


SALT_A = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" * 2)
env_a, det_a = seal_case("design appendix A", "doc", D, NODE, "node_fields", 3, 5, [], FIELDS, SALT_A)
# The design's appendix A values were computed with Node.js WebCrypto on 14 October 2026.
check(det_a["cid"] == "4113aa16937b961695bf48598ef4266f827efef9cb28d255df8d269d9bc80fec", "appendix A cid")
check(det_a["aead_key"] == "b8014bbc339853a12ee86a14c27a8ac4a5ae7ad5d54df3d055a9c9d6bf6ffbe7", "appendix A key")
check(det_a["nonce"] == "bc41609ee16409ad3bfac475", "appendix A nonce")
check(det_a["key_commitment"] == "d9d3eefc6923e82b1015ea358c1e2c84", "appendix A commitment")
check(h(env_a[:74]) == "44594e4f5345414c0101010000000003085428cdbf120f89c0c1c2c3c4c5c6c7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd9d3eefc6923e82b1015ea358c1e2c840000", "appendix A header")
check(h(env_a[74:106]) == "67883ffe13ce3904ac25e05d103765dfb6d41c3b44935e13ffc0d39185f96d63", "appendix A ciphertext")
check(h(env_a[-16:]) == "d95345f60fdf7c6c496ca640f1e68add", "appendix A tag")
check(det_a["address"] == "89e8e004de5459434f86d553f6064f1b2da33d49a2be9b982d64381cfd4ac250", "appendix A address")
check(len(env_a) == 346 and len(bytes.fromhex(det_a["aad"])) == 175, "appendix A sizes")

refs = [sha256(b"child-2"), sha256(b"child-1")]
seal_case("project-level message with two child references", "meta", None, "commit.message", "meta",
          1, 0, refs, "Quarterly figures, second draft", bytes([0xd0 + (i % 16) for i in range(32)]), root=PER3)
seal_case("comment at a bucket boundary (framed 128 -> 128)", "doc", D, "comment:0", "comment", 3, 0, [],
          "x" * (128 - 4 - len(body(cid_key(PER3), 3, "")[0])), bytes([0x11] * 32))
seal_case("comment one byte over a bucket (framed 129 -> 256)", "doc", D, "comment:1", "comment", 3, 0, [],
          "x" * (129 - 4 - len(body(cid_key(PER3), 3, "")[0])), bytes([0x12] * 32))
seal_case("event with non-ASCII text", "doc", D, "01JA0000000000000000000000", "event", 4, 17, [],
          {"field": "label", "value": "Résumé — ঢাকা"}, bytes([0x13] * 32), root=bytes(range(32, 64)))

# Negative cases on case A: each must be refused by the reader.
def flip(b, i):
    b = bytearray(b)
    b[i] ^= 1
    return bytes(b)


negative = []
for name, i in [("magic", 0), ("format version", 8), ("suite", 9), ("kind byte", 10), ("flags", 11),
                ("epoch", 15), ("key id", 16), ("salt", 30), ("key commitment", 60), ("ref count", 73),
                ("ciphertext", 100), ("tag", 345)]:
    negative.append({"name": "flipped " + name, "envelope": h(flip(env_a, i)), "context": {}})
for name, change in [("revision", {"revision": 6}), ("node", {"node": "01J9ZK3Q8M2V7N4X5C6D7E8F9H"}),
                     ("document", {"document": P}), ("project", {"project": D}),
                     ("epoch", {"epoch": 4}), ("kind", {"kind": "comment"})]:
    negative.append({"name": "context " + name, "envelope": h(env_a), "context": change})
negative.append({"name": "truncated tag", "envelope": h(env_a[:-1]), "context": {}})
padbad, _ = seal(doc_key(PER3, P, D), key_id(3, PER3), cid_key(PER3), P, D, NODE, 1, 3, 5, [], FIELDS, SALT_A, pad_byte=1)
negative.append({"name": "nonzero padding under a valid tag", "envelope": h(padbad), "context": {}})
r1, r2 = sorted([sha256(b"a"), sha256(b"b")])
unsorted = (b"DYNOSEAL" + bytes([1, 1, 1, 0]) + struct.pack(">I", 3) + key_id(3, PER3) + SALT_A + b"\x00" * 16 +
            struct.pack(">H", 2) + r2 + r1 + env_a[74:])
negative.append({"name": "unsorted child references", "envelope": h(unsorted), "context": {}})

# ---- grants (design 7, decision 035) -------------------------------------------------------
CREATOR = bytes([0x22] * 32)
RECIPIENT = sha256(b"dynodoc test recipient 1")
DEVICE = "1d4e8f3a-6b2c-4a4d-8c10-3f7b9a2e5d11"


def grant_info(project, epoch, scope, device):
    info = b"dynodoc.key-grant\x00v1\x00" + uuid_bytes(project) + struct.pack(">I", epoch)
    info += b"\x00" if scope["kind"] == "project" else b"\x01" + uuid_bytes(scope["document"])
    return info + (uuid_bytes(device) if device else b"\x00" * 16)


def make_grant(fields, secret, ikm):
    g = dict(fields)
    g["created_by_key"] = h(ed_pub(CREATOR))
    no = {k: v for k, v in g.items() if k not in ("enc", "ciphertext", "signature", "epoch_record")}
    a = sha256(canon(no))
    info = grant_info(g["project"], g["epoch"], g["scope"], g["recipient_device"])
    enc, ct, _ = hpke_seal(bytes.fromhex(g["recipient_key"]), info, a, secret, ikm)
    g["enc"], g["ciphertext"] = h(enc), h(ct)
    signed = sha256(canon({k: v for k, v in g.items() if k != "signature"}))
    g["signature"] = h(ed_sign(CREATOR, b"dynodoc.key-grant-signature\x00v1\x00" + signed))
    digest = sha256(b"dynodoc.key-grant-digest\x00v1\x00", enc, ct)
    return g, {"info": h(info), "aad": h(a), "hash": h(signed), "digest_entry": h(digest)}


PER4 = bytes(range(32, 64))
base = {"version": 1, "project": P, "epoch": 4, "scope": {"kind": "project"}, "recipient_kind": "device",
        "recipient_device": DEVICE, "recipient_key": h(x_pub(RECIPIENT)),
        "suite": {"kem": 32, "kdf": 1, "aead": 2}, "epoch_record": h(sha256(b"epoch record 4")),
        "created_at_ms": 1791000000000, "enc": "", "ciphertext": "", "signature": "", "created_by_key": ""}
g1, d1 = make_grant(base, PER4, bytes([0x33] * 32))
second = dict(base, recipient_device=None, recipient_kind="recovery", recipient_key=h(x_pub(sha256(b"recovery recipient"))))
g2, d2 = make_grant(second, PER4, bytes([0x34] * 32))
entries = sorted([(bytes.fromhex(g1["recipient_key"]), bytes.fromhex(d1["digest_entry"])),
                  (bytes.fromhex(g2["recipient_key"]), bytes.fromhex(d2["digest_entry"]))])
recipients_digest = h(sha256(b"".join(k + d for k, d in entries)))
kd3, kd4 = doc_key(PER3, P, D), doc_key(PER4, P, D)
dlist = canon([{"cid": h(cid_key(PER3)), "epoch": 3, "key": h(kd3), "key_id": h(key_id(3, PER3))},
               {"cid": h(cid_key(PER4)), "epoch": 4, "key": h(kd4), "key_id": h(key_id(4, PER4))}])
agent = dict(base, scope={"kind": "document", "document": D}, recipient_kind="agent", recipient_device=None,
             recipient_key=h(x_pub(sha256(b"agent pane key"))),
             delegation={"expires_at_ms": 1791003600000, "purpose": "agent", "read_only": True})
g3, d3 = make_grant(agent, dlist, bytes([0x35] * 32))
grants = [{"grant": g1, "secret": h(PER4), "recipient_secret": h(RECIPIENT), **d1},
          {"grant": g2, "secret": h(PER4), "recipient_secret": h(sha256(b"recovery recipient")), **d2},
          {"grant": g3, "secret": dlist.decode(), "recipient_secret": h(sha256(b"agent pane key")), **d3}]

# ---- epoch record, binding, fingerprint, membership log ------------------------------------
record = {"version": 1, "project": P, "epoch": 4, "previous_epoch_record": h(sha256(b"epoch record 3")),
          "reason": "member_removed", "suite": 1, "key_id": h(key_id(4, PER4)),
          "recipients_digest": recipients_digest, "membership_head": h(sha256(b"head")),
          "history_policy": "full", "created_by_key": h(ed_pub(CREATOR)), "created_at_ms": 1791000000000}
record_hash = sha256(b"dynodoc.epoch-record\x00v1\x00", canon(record))
epoch_record = {"record": record, "hash": h(record_hash),
                "signature": h(ed_sign(CREATOR, b"dynodoc.epoch-record-signature\x00v1\x00" + record_hash))}

DSK = bytes([0x44] * 32)
binding_msg = {"version": 1, "authority": "5d7f0000-0000-4000-8000-000000000001",
               "identity": "2e8a0000-0000-4000-8000-000000000002", "signing_key": h(ed_pub(DSK)),
               "encryption_key": h(x_pub(RECIPIENT)), "created_at_ms": 1791043200000}
fp = sha256(b"dynodoc.device-fingerprint\x00v1\x00", ed_pub(DSK), x_pub(RECIPIENT))
fp_bytes = fp + sha256(fp)
digits = " ".join("%05d" % (int.from_bytes(fp_bytes[i:i + 5], "big") % 100000) for i in range(0, 60, 5))
binding = {"message": binding_msg,
           "signature": h(ed_sign(DSK, b"dynodoc.device-encryption-binding\x00v1\x00" + canon(binding_msg))),
           "fingerprint": h(fp), "digits": digits}

OWNER, BOB = bytes([0x22] * 32), bytes([0x55] * 32)
OWNER_ID, BOB_ID = "00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000b0"


def entry(index, previous, kind, body_, signer):
    e = {"version": 1, "project": P, "index": index, "previous": previous, "type": kind, "body": body_,
         "signer_key": h(ed_pub(signer)), "created_at_ms": 1791000000000 + index}
    eh = sha256(b"dynodoc.membership-log\x00v1\x00", canon(e))
    return {"entry": e, "signature": h(ed_sign(signer, b"dynodoc.membership-log-signature\x00v1\x00" + eh))}, h(eh)


log, prev = [], None
for kind, body_, signer in [
    ("genesis", {"identity": OWNER_ID, "signing_key": h(ed_pub(OWNER)), "encryption_key": h(x_pub(sha256(b"owner enc")))}, OWNER),
    ("member_add", {"identity": BOB_ID, "role": "editor", "devices": [{"signing_key": h(ed_pub(BOB)), "encryption_key": h(x_pub(sha256(b"bob enc")))}]}, OWNER),
    ("device_add", {"identity": BOB_ID, "signing_key": h(ed_pub(bytes([0x57] * 32))), "encryption_key": h(x_pub(sha256(b"bob enc 2")))}, BOB),
    ("epoch_open", {"epoch": 1, "record_hash": h(sha256(b"epoch 1"))}, OWNER),
    ("member_remove", {"identity": BOB_ID}, OWNER),
    ("epoch_open", {"epoch": 2, "record_hash": h(sha256(b"epoch 2"))}, OWNER),
]:
    signed, eh = entry(len(log), prev, kind, body_, signer)
    log.append({"signed": signed, "hash": eh})
    prev = eh
rejected = []
bad, _ = entry(2, log[1]["hash"], "member_add", {"identity": "00000000-0000-4000-8000-0000000000c0", "role": "editor"}, BOB)
rejected.append({"name": "an editor adds a member", "after": 2, "signed": bad})
bad, _ = entry(4, log[1]["hash"], "member_remove", {"identity": BOB_ID}, OWNER)
rejected.append({"name": "wrong previous hash", "after": 4, "signed": bad})
bad = json.loads(json.dumps(log[4]["signed"]))
bad["signature"] = bad["signature"][:-2] + ("00" if bad["signature"][-2:] != "00" else "01")
rejected.append({"name": "altered signature", "after": 4, "signed": bad})
bad, _ = entry(6, log[5]["hash"], "device_add", {"identity": BOB_ID, "signing_key": h(ed_pub(bytes([0x56] * 32))), "encryption_key": h(x_pub(sha256(b"x")))}, BOB)
rejected.append({"name": "a removed member's key adds a device", "after": 6, "signed": bad})

# ---- recovery key (design 11.2) -----------------------------------------------------------
ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
RK = bytes(range(0x40, 0x60))
bits = "".join("{:08b}".format(b) for b in RK) + "0000"
chars = "".join(ALPHA[int(bits[i:i + 5], 2)] for i in range(0, 260, 5))
chk = sha256(b"dynodoc.recovery.v1/check", RK)
c10 = (chk[0] << 2) | (chk[1] >> 6)
chars += ALPHA[c10 >> 5] + ALPHA[c10 & 31]
text = "-".join([chars[i:i + 4] for i in range(0, 52, 4)] + [chars[52:]])
seed = hkdf(RK, b"", b"dynodoc.recovery.v1/seed", 32)
recovery = {"key": h(RK), "text": text,
            "recipient_public": h(x_pub(hkdf_expand(seed, b"x25519", 32))),
            "signer_public": h(ed_pub(hkdf_expand(seed, b"ed25519", 32))),
            "escrow_secret": h(bytes([0x66] * 32)),
            "escrow_public": h(x_pub(hkdf(bytes([0x66] * 32), b"", b"dynodoc.escrow.v1/x25519", 32)))}

# ---- ledger relay answer and block hashes (decision 035) -----------------------------------
block = {"block_hash": "f" * 64, "content": "Revenue grew 5%.", "label": "Résumé"}
stable = canon({k: v for k, v in block.items() if k != "block_hash"})
lbk = ledger_block_key(doc_key(PER3, P, D))
subject = sha256(b"block subject")
REQUESTER = sha256(b"relay requester")
rinfo = b"dynodoc.ledger-relay\x00v1\x00" + uuid_bytes(D) + b"\x01" + subject
renc, rct, _ = hpke_seal(x_pub(REQUESTER), rinfo, b"", stable, bytes([0x77] * 32))
ledger = {"fields": block, "unkeyed": h(sha256(stable)), "ledger_block_key": h(lbk),
          "keyed": h(hmac256(lbk, b"dynodoc.ledger-block\x00v1\x00", stable)),
          "relay": {"document": D, "kind": "block", "subject": h(subject),
                    "requester_secret": h(REQUESTER),
                    "requester_key_b64url": base64.urlsafe_b64encode(x_pub(REQUESTER)).decode().rstrip("="),
                    "payload": stable.decode(), "ikm": h(bytes([0x77] * 32)), "info": h(rinfo),
                    "sealed": h(renc + rct)}}

padding = [{"framed": n, "padded": padded(n)} for n in [1, 128, 129, 256, 257, 4096, 65536, 65537, 100000]]

sys.stdout.buffer.write((json.dumps({
    "version": 1,
    "about": "Synthetic vectors for encrypted projects (decision 035). Independent producer: gen_e2ee_vectors.py. Never regenerate to make a check pass.",
    "keys": keys_out, "seal": seal_cases, "seal_negative": negative, "grants": grants,
    "recipients_digest": recipients_digest, "creator_public": h(ed_pub(CREATOR)), "epoch_record": epoch_record,
    "binding": binding, "log": log, "log_rejected": rejected, "recovery": recovery, "ledger": ledger,
    "padding": padding,
}, indent=1, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
