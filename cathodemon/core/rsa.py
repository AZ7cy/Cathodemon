"""RSA from scratch: key generation, OAEP encryption, PKCS#1 v1.5 signatures.

Standard-library only (secrets for randomness, hashlib for SHA-256, Python's
arbitrary-precision integers for the modular arithmetic). Follows RFC 8017.
No third-party code.
"""
from __future__ import annotations

import hashlib
import math
import secrets

_E = 65537
_HLEN = 32  # SHA-256 output length
# ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 section 9.2, note 1)
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):  # Miller-Rabin
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


def generate(bits: int = 2048) -> dict:
    """Generate an RSA keypair. Returns dict with n, e, d, p, q, bits."""
    half = bits // 2
    while True:
        p = _random_prime(half)
        q = _random_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(_E, phi) != 1:
            continue
        return {"n": n, "e": _E, "d": pow(_E, -1, phi), "p": p, "q": q, "bits": bits}


def _i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _mgf1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _key_bytes(key: dict) -> int:
    return (key["n"].bit_length() + 7) // 8


# ---- OAEP encryption (RFC 8017 section 7.1) ----
def encrypt_oaep(pub: dict, message: bytes, label: bytes = b"") -> bytes:
    n, e = pub["n"], pub["e"]
    k = (n.bit_length() + 7) // 8
    if len(message) > k - 2 * _HLEN - 2:
        raise ValueError("message too long for this key")
    l_hash = hashlib.sha256(label).digest()
    ps = b"\x00" * (k - len(message) - 2 * _HLEN - 2)
    db = l_hash + ps + b"\x01" + message
    seed = secrets.token_bytes(_HLEN)
    db_mask = _mgf1(seed, k - _HLEN - 1)
    masked_db = _xor(db, db_mask)
    seed_mask = _mgf1(masked_db, _HLEN)
    masked_seed = _xor(seed, seed_mask)
    em = b"\x00" + masked_seed + masked_db
    c = pow(_os2ip(em), e, n)
    return _i2osp(c, k)


def decrypt_oaep(priv: dict, ciphertext: bytes, label: bytes = b"") -> bytes:
    n, d = priv["n"], priv["d"]
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("bad ciphertext length")
    m = pow(_os2ip(ciphertext), d, n)
    em = _i2osp(m, k)
    l_hash = hashlib.sha256(label).digest()
    y, masked_seed, masked_db = em[0], em[1:1 + _HLEN], em[1 + _HLEN:]
    seed = _xor(masked_seed, _mgf1(masked_db, _HLEN))
    db = _xor(masked_db, _mgf1(seed, k - _HLEN - 1))
    l_hash2 = db[:_HLEN]
    rest = db[_HLEN:]
    idx = rest.find(b"\x01")
    if y != 0 or l_hash2 != l_hash or idx < 0 or any(rest[:idx]):
        raise ValueError("decryption error")
    return rest[idx + 1:]


# ---- PKCS#1 v1.5 signatures (RFC 8017 section 8.2) ----
def _emsa_pkcs1(message: bytes, k: int) -> bytes:
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        raise ValueError("key too small")
    ps = b"\xff" * (k - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def sign_pkcs1(priv: dict, message: bytes) -> bytes:
    n, d = priv["n"], priv["d"]
    k = (n.bit_length() + 7) // 8
    em = _emsa_pkcs1(message, k)
    return _i2osp(pow(_os2ip(em), d, n), k)


def verify_pkcs1(pub: dict, message: bytes, signature: bytes) -> bool:
    n, e = pub["n"], pub["e"]
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    try:
        em = _i2osp(pow(_os2ip(signature), e, n), k)
    except (ValueError, OverflowError):
        return False
    return secrets.compare_digest(em, _emsa_pkcs1(message, k))
