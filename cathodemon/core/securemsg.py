"""Cathodemon Secure Message - identities, armored keys and encrypted/signed mail.

Built entirely on our own rsa.py + chacha.py and the standard library
(hashlib.scrypt for passphrase protection, secrets for randomness). This is an
original, self-contained scheme - NOT OpenPGP - for an educational tool.

Format (all payloads are base64 of UTF-8 JSON, wrapped in ASCII-armor lines):
  PUBLIC KEY : {name,email,created,n,e}
  PRIVATE KEY: public fields in the clear + scrypt+ChaCha20-Poly1305 blob of {d,p,q}
  MESSAGE    : RSA-OAEP-wrapped ChaCha20-Poly1305 session key + signature
  SIGNED     : human-readable body followed by a detached RSA signature
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from . import rsa, chacha

KEYRING_PATH = Path.home() / ".cathodemon" / "keyring.json"
_SCRYPT = {"n": 1 << 14, "r": 8, "p": 1}
_MAXMEM = 64 * 1024 * 1024


# --------------------------------------------------------------- armor helpers
def _armor(kind: str, payload: dict) -> str:
    raw = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    body = "\n".join(raw[i:i + 64] for i in range(0, len(raw), 64))
    return f"-----BEGIN CATHODEMON {kind}-----\n{body}\n-----END CATHODEMON {kind}-----"


def _dearmor(text: str, kind: str) -> dict:
    marker_b = f"-----BEGIN CATHODEMON {kind}-----"
    marker_e = f"-----END CATHODEMON {kind}-----"
    if marker_b not in text or marker_e not in text:
        raise ValueError(f"not a CATHODEMON {kind} block")
    inner = text.split(marker_b, 1)[1].split(marker_e, 1)[0]
    raw = "".join(inner.split())
    return json.loads(base64.b64decode(raw).decode("utf-8"))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _ub64(text: str) -> bytes:
    return base64.b64decode(text)


# --------------------------------------------------------------- fingerprints
def fingerprint_of(n: int, e: int) -> str:
    material = n.to_bytes((n.bit_length() + 7) // 8, "big") + e.to_bytes(4, "big")
    return hashlib.sha256(material).hexdigest()[:40].upper()


def format_fingerprint(fp: str) -> str:
    s = fp.replace(" ", "").upper()
    return " ".join(s[i:i + 4] for i in range(0, len(s), 4))


# --------------------------------------------------------------- public keys
def _public_armor(name, email, created, n, e) -> str:
    return _armor("PUBLIC KEY", {"v": 1, "type": "public", "name": name, "email": email,
                                 "created": created, "n": format(n, "x"), "e": e})


def load_public(armored: str) -> dict:
    d = _dearmor(armored, "PUBLIC KEY")
    n, e = int(d["n"], 16), int(d["e"])
    return {"name": d.get("name", ""), "email": d.get("email", ""),
            "created": d.get("created"), "n": n, "e": e, "fingerprint": fingerprint_of(n, e)}


# --------------------------------------------------------------- identities
def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, dklen=32, maxmem=_MAXMEM, **_SCRYPT)


def generate_identity(name: str, email: str, passphrase: str, bits: int = 2048) -> dict:
    key = rsa.generate(bits)
    created = datetime.now(timezone.utc).isoformat()
    public = _public_armor(name, email, created, key["n"], key["e"])
    private = _wrap_private(name, email, created, key, passphrase)
    return {"fingerprint": fingerprint_of(key["n"], key["e"]), "name": name, "email": email,
            "created": created, "public": public, "private": private, "is_private": True}


def _wrap_private(name, email, created, key, passphrase) -> str:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    secret = json.dumps({"d": format(key["d"], "x"), "p": format(key["p"], "x"),
                         "q": format(key["q"], "x")}).encode("utf-8")
    dk = _derive_key(passphrase, salt)
    ct, tag = chacha.aead_encrypt(dk, nonce, secret, aad=b"cathodemon-privkey")
    return _armor("PRIVATE KEY", {
        "v": 1, "type": "private", "name": name, "email": email, "created": created,
        "n": format(key["n"], "x"), "e": key["e"],
        "kdf": "scrypt", "params": _SCRYPT,
        "salt": _b64(salt), "nonce": _b64(nonce), "tag": _b64(tag), "ct": _b64(ct)})


def key_meta(armored: str) -> dict:
    """Inspect a public OR private armor block without needing the passphrase."""
    if "CATHODEMON PRIVATE KEY" in armored:
        d = _dearmor(armored, "PRIVATE KEY")
        n, e = int(d["n"], 16), int(d["e"])
        return {"fingerprint": fingerprint_of(n, e), "name": d.get("name", ""),
                "email": d.get("email", ""), "created": d.get("created"), "is_private": True,
                "public_armored": _public_armor(d.get("name"), d.get("email"), d.get("created"), n, e)}
    pub = load_public(armored)
    return {"fingerprint": pub["fingerprint"], "name": pub["name"], "email": pub["email"],
            "created": pub["created"], "is_private": False, "public_armored": armored}


def _unlock(identity: dict, passphrase: str) -> dict:
    d = _dearmor(identity["private"], "PRIVATE KEY")
    dk = _derive_key(passphrase, _ub64(d["salt"]))
    try:
        secret = chacha.aead_decrypt(dk, _ub64(d["nonce"]), _ub64(d["ct"]), _ub64(d["tag"]),
                                     aad=b"cathodemon-privkey")
    except ValueError as exc:
        raise ValueError("Wrong passphrase for this identity.") from exc
    s = json.loads(secret)
    return {"n": int(d["n"], 16), "e": int(d["e"]), "d": int(s["d"], 16),
            "p": int(s["p"], 16), "q": int(s["q"], 16)}


# --------------------------------------------------------------- messages
def encrypt_and_sign(identity: dict, recipient_public: str, body: str, passphrase: str) -> str:
    priv = _unlock(identity, passphrase)
    recip = load_public(recipient_public)
    body_bytes = body.encode("utf-8")
    session_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    sender_fp = fingerprint_of(priv["n"], priv["e"])
    ct, tag = chacha.aead_encrypt(session_key, nonce, body_bytes, aad=sender_fp.encode())
    try:
        wrapped = rsa.encrypt_oaep({"n": recip["n"], "e": recip["e"]}, session_key)
    except ValueError as exc:
        raise ValueError(f"Could not encrypt to this recipient's key ({exc}).") from exc
    sig = rsa.sign_pkcs1(priv, body_bytes)
    meta = _dearmor(identity["private"], "PRIVATE KEY") if "private" in identity else {}
    return _armor("MESSAGE", {
        "v": 1, "sender_fp": sender_fp, "sender_name": meta.get("name", ""),
        "sender_email": meta.get("email", ""), "recipient_fp": recip["fingerprint"],
        "ek": _b64(wrapped), "nonce": _b64(nonce), "ct": _b64(ct), "tag": _b64(tag),
        "sig": _b64(sig)})


def _verdict(level: str, text: str) -> dict:
    return {"level": level, "text": text}


def _verify_sig(body_bytes: bytes, sig: bytes, sender_public, sender_person) -> dict:
    if sender_public is None:
        return _verdict("unverified", "The message is signed, but you didn't pick an expected "
                        "sender, so it couldn't be checked. Add the sender as a contact and "
                        "select them to verify.")
    pub = load_public(sender_public)
    if rsa.verify_pkcs1({"n": pub["n"], "e": pub["e"]}, body_bytes, sig):
        who = (f"{sender_person['name']} <{sender_person['email']}>" if sender_person
               else f"{pub['name']} <{pub['email']}>")
        return _verdict("valid", f"Signature VALID - genuinely from {who}. The contents were "
                        f"not tampered with.")
    name = sender_person["name"] if sender_person else "the expected sender"
    return _verdict("invalid", f"Signature did NOT verify against {name}. Treat as forged or altered.")


def decrypt_and_verify(armored: str, identity: dict, passphrase: str,
                       sender_public=None, sender_person=None) -> dict:
    text = armored.strip()
    if "CATHODEMON SIGNED MESSAGE" in text:
        body, sig_blob = _split_signed(text)
        sig = _ub64(sig_blob["sig"])
        verdict = _verify_sig(body.encode("utf-8"), sig, sender_public, sender_person)
        return {"text": body, "verdict": verdict}
    if "CATHODEMON MESSAGE" in text:
        d = _dearmor(text, "MESSAGE")
        priv = _unlock(identity, passphrase)
        try:
            session_key = rsa.decrypt_oaep(priv, _ub64(d["ek"]))
        except ValueError as exc:
            raise ValueError("Wrong passphrase, or this message isn't addressed to you.") from exc
        try:
            body_bytes = chacha.aead_decrypt(session_key, _ub64(d["nonce"]), _ub64(d["ct"]),
                                             _ub64(d["tag"]), aad=d.get("sender_fp", "").encode())
        except ValueError as exc:
            raise ValueError("The message failed its integrity check (tampered or corrupt).") from exc
        verdict = _verify_sig(body_bytes, _ub64(d["sig"]), sender_public, sender_person)
        return {"text": body_bytes.decode("utf-8", "replace"), "verdict": verdict}
    raise ValueError("That is not a CATHODEMON message or signed block.")


# --------------------------------------------------------------- signed-only
_SIGN_BODY_HDR = "-----BEGIN CATHODEMON SIGNED MESSAGE-----"
_SIGN_SIG_HDR = "-----BEGIN CATHODEMON SIGNATURE-----"
_SIGN_END = "-----END CATHODEMON SIGNED MESSAGE-----"


def sign_only(identity: dict, body: str, passphrase: str) -> str:
    priv = _unlock(identity, passphrase)
    canonical = body.rstrip("\n")
    sig = rsa.sign_pkcs1(priv, canonical.encode("utf-8"))
    meta = _dearmor(identity["private"], "PRIVATE KEY")
    sig_payload = _b64(json.dumps({
        "sender_fp": fingerprint_of(priv["n"], priv["e"]), "name": meta.get("name", ""),
        "email": meta.get("email", ""), "sig": _b64(sig)}).encode("utf-8"))
    wrapped = "\n".join(sig_payload[i:i + 64] for i in range(0, len(sig_payload), 64))
    return f"{_SIGN_BODY_HDR}\n{canonical}\n{_SIGN_SIG_HDR}\n{wrapped}\n{_SIGN_END}"


def _split_signed(text: str):
    body = text.split(_SIGN_BODY_HDR, 1)[1].split(_SIGN_SIG_HDR, 1)[0].strip("\n")
    sig_raw = text.split(_SIGN_SIG_HDR, 1)[1].split(_SIGN_END, 1)[0]
    sig_blob = json.loads(base64.b64decode("".join(sig_raw.split())).decode("utf-8"))
    return body, sig_blob


# --------------------------------------------------------------- keyring
def load_keyring() -> dict:
    try:
        data = json.loads(KEYRING_PATH.read_text(encoding="utf-8"))
        data.setdefault("identities", [])
        data.setdefault("contacts", [])
        return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"identities": [], "contacts": []}


def save_keyring(kr: dict) -> None:
    KEYRING_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEYRING_PATH.write_text(json.dumps(kr, indent=2), encoding="utf-8")
