#!/usr/bin/env python3
"""Known-answer vectors for ZeroByte Relay Protocol v1.

This is the independent reference every SDK and the relay test against. It
shares no code with any of them: ChaCha20, Poly1305 and the AEAD construction
are RFC 8439 written out below and checked against RFC 8439 §2.5.2 and §2.8.2
before use; HKDF is RFC 5869 over the Python standard library `hmac`/`hashlib`.

    python3 spec/vectors.py > spec/vectors.json

Standard library only (tested with Python 3.14). Never regenerate vectors from
an implementation under test; change this file, review the diff, and copy the
result into each SDK.
"""

import base64
import hashlib
import hmac
import json
import struct
import uuid

# ---------------------------------------------------------------- RFC 8439


def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter] + list(struct.unpack("<3I", nonce))
    work = state[:]
    for _ in range(10):
        _quarter(work, 0, 4, 8, 12); _quarter(work, 1, 5, 9, 13)
        _quarter(work, 2, 6, 10, 14); _quarter(work, 3, 7, 11, 15)
        _quarter(work, 0, 5, 10, 15); _quarter(work, 1, 6, 11, 12)
        _quarter(work, 2, 7, 8, 13); _quarter(work, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w + s) & 0xFFFFFFFF for w, s in zip(work, state)])


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], block))
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * ((16 - len(b) % 16) % 16)


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, plaintext)
    mac = aad + _pad16(aad) + ct + _pad16(ct)
    mac += struct.pack("<QQ", len(aad), len(ct))
    return ct + poly1305(otk, mac)


def _self_check() -> None:
    # RFC 8439 §2.5.2
    tag = poly1305(
        bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
        b"Cryptographic Forum Research Group",
    )
    assert tag.hex() == "a8061dc1305136c6c22b8baf0c0127a9", tag.hex()
    # RFC 8439 §2.8.2
    sealed = aead_seal(
        bytes(range(0x80, 0xA0)),
        bytes.fromhex("070000004041424344454647"),
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
        b"tip for the future, sunscreen would be it.",
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
    )
    assert sealed[:-16].hex() == (
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    ), sealed[:-16].hex()
    assert sealed[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", sealed[-16:].hex()


# ---------------------------------------------------------------- RFC 5869


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def _hkdf_self_check() -> None:
    # RFC 5869 Appendix A.1
    okm = hkdf(
        bytes([0x0B] * 22),
        bytes(range(0x00, 0x0D)),
        bytes(range(0xF0, 0xFA)),
        42,
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ), okm.hex()


# ---------------------------------------------------------------- Protocol v1

# The labels keep the name of the protocol's first application. They are part
# of the wire format: changing them is a new protocol version.
MAILBOX_INFO = b"derived-relay-mailbox-v1"
TOKEN_INFO = b"derived-relay-token-v1"
P2C_INFO = b"derived-relay-p2c-v1"
C2P_INFO = b"derived-relay-c2p-v1"

VERSION = 1
P2C, C2P = 1, 2


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def credentials(link_key: bytes, link_id: bytes) -> dict:
    assert len(link_key) == 32 and len(link_id) == 16
    token = hkdf(link_key, link_id, TOKEN_INFO, 32)
    return {
        "linkKey": link_key.hex(),
        "linkId": link_id.hex(),
        "mailbox": hkdf(link_key, link_id, MAILBOX_INFO, 16).hex(),
        "token": token.hex(),
        "bearer": b64url(token),
        "tokenDigest": hashlib.sha256(token).hexdigest(),
        "p2cKey": hkdf(link_key, link_id, P2C_INFO, 32).hex(),
        "c2pKey": hkdf(link_key, link_id, C2P_INFO, 32).hex(),
    }


def header(direction: int, sequence: int, version: int = VERSION) -> bytes:
    return bytes([version, direction]) + struct.pack(">Q", sequence)


def seal(creds: dict, direction: int, sequence: int, nonce: bytes, plaintext: bytes) -> bytes:
    key = bytes.fromhex(creds["p2cKey" if direction == P2C else "c2pKey"])
    h = header(direction, sequence)
    return h + nonce + aead_seal(key, nonce, plaintext, h + bytes.fromhex(creds["mailbox"]))


def wire(envelopes: list) -> bytes:
    out = struct.pack(">I", len(envelopes))
    for e in envelopes:
        out += struct.pack(">I", len(e)) + e
    return out


def main() -> None:
    _self_check()
    _hkdf_self_check()

    # Set 0 is the one Derived's own tests use; set 1 is unrelated input.
    sets = [
        credentials(bytes(range(0x00, 0x20)), uuid.UUID("6F1C2A3B-4D5E-4F60-8172-93A4B5C6D7E8").bytes),
        credentials(
            hashlib.sha256(b"zerobyte relay v1 vector set 1").digest(),
            uuid.UUID("01a1601b-fa85-7d58-b2a2-1416e0a6b054").bytes,
        ),
    ]

    cases = [
        (0, P2C, 1, bytes([0x07] * 12), b"Derived relay v1"),
        (0, C2P, 3, bytes([0x07] * 12), b""),
        (1, P2C, 2**64 - 1, bytes(range(0x30, 0x3C)), bytes(range(256)) * 2 + b"tail"),
        (1, C2P, 256, bytes(range(0xA0, 0xAC)), "zażółć gęślą jaźń".encode()),
    ]
    envelopes = []
    for index, direction, sequence, nonce, plaintext in cases:
        envelopes.append({
            "credentials": index,
            "direction": direction,
            "sequence": str(sequence),
            "nonce": nonce.hex(),
            "plaintext": plaintext.hex(),
            "envelope": seal(sets[index], direction, sequence, nonce, plaintext).hex(),
        })

    good = bytes.fromhex(envelopes[0]["envelope"])
    flipped_tag = good[:-1] + bytes([good[-1] ^ 0x01])
    flipped_body = good[:30] + bytes([good[30] ^ 0x80]) + good[31:]
    renumbered = good[:2] + struct.pack(">Q", 2) + good[10:]
    redirected = bytes([1, C2P]) + good[2:]
    version_two = bytes([2]) + good[1:]
    rejections = [
        {"credentials": 0, "direction": P2C, "after": None, "envelope": flipped_tag.hex(),
         "error": "authentication_failed", "why": "last tag byte flipped"},
        {"credentials": 0, "direction": P2C, "after": None, "envelope": flipped_body.hex(),
         "error": "authentication_failed", "why": "ciphertext bit flipped"},
        {"credentials": 0, "direction": P2C, "after": None, "envelope": renumbered.hex(),
         "error": "authentication_failed", "why": "sequence in the header changed to 2"},
        {"credentials": 1, "direction": P2C, "after": None, "envelope": good.hex(),
         "error": "authentication_failed", "why": "opened with another link's keys"},
        {"credentials": 0, "direction": C2P, "after": None, "envelope": redirected.hex(),
         "error": "authentication_failed", "why": "direction byte changed; read as c2p"},
        {"credentials": 0, "direction": C2P, "after": None, "envelope": good.hex(),
         "error": "wrong_direction", "why": "p2c envelope read as c2p"},
        {"credentials": 0, "direction": P2C, "after": "1", "envelope": good.hex(),
         "error": "replayed", "why": "sequence 1 after 1 was accepted"},
        {"credentials": 0, "direction": P2C, "after": None, "envelope": version_two.hex(),
         "error": "unsupported_version", "why": "version byte 2"},
        {"credentials": 0, "direction": P2C, "after": None, "envelope": good[:37].hex(),
         "error": "malformed", "why": "37 bytes, shorter than the 38-byte overhead"},
        {"credentials": 0, "direction": P2C, "after": None,
         "envelope": (bytes([1, 3]) + good[2:]).hex(),
         "error": "malformed", "why": "direction byte 3"},
    ]

    e0 = bytes.fromhex(envelopes[0]["envelope"])
    e1 = bytes.fromhex(envelopes[1]["envelope"])
    wires = [
        {"envelopes": [], "body": wire([]).hex()},
        {"envelopes": [e0.hex(), e1.hex()], "body": wire([e0, e1]).hex()},
    ]
    wire_rejections = [
        {"body": "", "why": "no count"},
        {"body": wire([e0])[:-1].hex(), "why": "last envelope truncated"},
        {"body": (wire([e0]) + b"\x00").hex(), "why": "trailing byte"},
        {"body": struct.pack(">I", 65).hex(), "why": "count above 64"},
        {"body": (struct.pack(">I", 1) + struct.pack(">I", 1_048_576 + 39)).hex(),
         "why": "length above the envelope limit"},
    ]

    print(json.dumps({
        "protocol": "zerobyte-relay-v1",
        "note": "Generated by spec/vectors.py. Byte strings are lowercase hex; "
                "sequences are decimal strings (UInt64).",
        "labels": {
            "mailbox": MAILBOX_INFO.decode(),
            "token": TOKEN_INFO.decode(),
            "p2c": P2C_INFO.decode(),
            "c2p": C2P_INFO.decode(),
        },
        "credentials": sets,
        "envelopes": envelopes,
        "rejections": rejections,
        "wire": wires,
        "wireRejections": wire_rejections,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
