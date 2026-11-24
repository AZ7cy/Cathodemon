"""ChaCha20 stream cipher + Poly1305 MAC + ChaCha20-Poly1305 AEAD.

A from-scratch implementation of RFC 8439, using only the Python standard
library. Validated against the RFC's published test vectors (see tests).
No third-party code.
"""
from __future__ import annotations

import hmac
import struct

_MASK32 = 0xFFFFFFFF
_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"


def _rotl(x: int, n: int) -> int:
    x &= _MASK32
    return ((x << n) & _MASK32) | (x >> (32 - n))


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _MASK32; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK32; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32; s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = list(_CONST) + list(struct.unpack("<8I", key)) + [counter & _MASK32] + list(struct.unpack("<3I", nonce))
    w = state[:]
    for _ in range(10):  # 20 rounds = 10 column+diagonal double rounds
        _quarter_round(w, 0, 4, 8, 12)
        _quarter_round(w, 1, 5, 9, 13)
        _quarter_round(w, 2, 6, 10, 14)
        _quarter_round(w, 3, 7, 11, 15)
        _quarter_round(w, 0, 5, 10, 15)
        _quarter_round(w, 1, 6, 11, 12)
        _quarter_round(w, 2, 7, 8, 13)
        _quarter_round(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + state[i]) & _MASK32 for i in range(16)])


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 keystream XOR. key=32 bytes, nonce=12 bytes."""
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("key must be 32 bytes and nonce 12 bytes")
    out = bytearray(len(data))
    for i in range(0, len(data), 64):
        ks = _chacha_block(key, counter + (i >> 6), nonce)
        chunk = data[i:i + 64]
        for j, b in enumerate(chunk):
            out[i + j] = b ^ ks[j]
    return bytes(out)


_P1305 = (1 << 130) - 5


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """One-time Poly1305 authenticator. key = 32-byte one-time key."""
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") | (1 << (8 * len(block)))
        acc = ((acc + n) * r) % _P1305
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _poly_key_gen(key: bytes, nonce: bytes) -> bytes:
    return _chacha_block(key, 0, nonce)[:32]


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"\x00" * (16 - rem) if rem else b""


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """RFC 8439 AEAD_CHACHA20_POLY1305. Returns (ciphertext, 16-byte tag)."""
    otk = _poly_key_gen(key, nonce)
    ct = chacha20(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    return ct, poly1305_mac(mac_data, otk)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Verify the tag (constant-time) and decrypt. Raises ValueError on mismatch."""
    otk = _poly_key_gen(key, nonce)
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    expected = poly1305_mac(mac_data, otk)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed - the message was tampered with or the key is wrong")
    return chacha20(key, 1, nonce, ciphertext)
