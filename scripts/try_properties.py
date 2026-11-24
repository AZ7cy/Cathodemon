"""Property-based tests for Cathodemon (see .kiro/specs/property-based-tests).

Each property is a "for any input" rule. The runner in pbt.py checks it against
many seeded random inputs and shrinks any failure. Run it directly:

    python -S scripts/try_properties.py

Set CATHODEMON_PBT_RUNS (default 100) for more inputs, and CATHODEMON_PBT_SEED
to reproduce a specific failure. Standard library only.

Note: the keys, nonces and messages here are randomized *test inputs*, drawn
from a seeded RNG so failures reproduce. They are not real secrets; the app
itself still makes every real key and nonce with `secrets`.
"""
from __future__ import annotations

import math
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

from cathodemon.core import blocklist, chacha, dnswire as w, leaks, passwords, rsa  # noqa: E402
from pbt import (Binary, Booleans, DnsNames, Integers, Lists, SampledFrom, Text, Tuples,  # noqa: E402
                 check)

# One slow-to-make RSA key, reused by the crypto properties (see the spec).
RSA_KEY = rsa.generate(1024)
BUILTIN = blocklist.parse_list(blocklist.BUILTIN_PATH.read_text(encoding="utf-8"))
BUILTIN_LIST = sorted(BUILTIN)
WIDE = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        " !@#$%^&*()-_=+[]{};:,.<>/?|\u00e1\u00e9\u00f1\u00fc\u00df\u6f22\u5b57")
LOWER = "abcdefghijklmnopqrstuvwxyz"
LABEL = LOWER + "0123456789"
RECORDS = Lists(Tuples(Booleans(), Binary(16, 16), Integers(0, 86400)), 0, 20)
QTYPES = SampledFrom([w.A, w.AAAA, w.MX, w.TXT, w.NS, w.CAA, w.HTTPS])
EDNS = SampledFrom([None, 512, 1232, 4096])


def _answers(name, records):
    out = []
    for is_v6, raw, ttl in records:
        if is_v6:
            out.append(w.make_rr(name, w.AAAA, ttl, socket.inet_ntop(socket.AF_INET6, raw)))
        else:
            out.append(w.make_rr(name, w.A, ttl, socket.inet_ntoa(raw[:4])))
    return out


def _query(name):
    return w.Message(id=0x1234, flags=0x0100, questions=[(name, w.A, 1)])


# ---- 1. DNS query round-trip (requirement 2.1) ----
def prop_query_roundtrip(value):
    name, qtype, edns = value
    qid, pkt = w.build_query(name, qtype, edns_payload=edns)
    m = w.parse_message(pkt)
    return (m.id == qid and len(m.questions) == 1 and m.questions[0][0] == name
            and m.questions[0][1] == qtype and m.edns_payload == edns)


# ---- 2. DNS response round-trip (requirement 2.2) ----
def prop_response_roundtrip(value):
    name, records = value
    answers = _answers(name, records)
    m = w.parse_message(w.build_response(_query(name), w.NOERROR, answers, max_size=65535))
    if len(m.answers) != len(answers):
        return False
    for got, want in zip(m.answers, answers):
        if got.name != name or got.rtype != want.rtype or got.ttl != want.ttl or got.value != want.value:
            return False
    return True


# ---- 3. Size limit and truncation (requirements 2.3, 2.4) ----
def prop_size_limit(value):
    name, records, limit = value
    answers = _answers(name, records)
    q = _query(name)
    full = w.build_response(q, w.NOERROR, answers, max_size=65535)
    limited = w.build_response(q, w.NOERROR, answers, max_size=limit)
    if len(limited) > limit:
        return False
    if len(full) > limit:
        m = w.parse_message(limited)
        return m.truncated and len(m.answers) == 0
    return True


# ---- 4. Parsing never crashes on bad input (requirement 2.5) ----
def prop_parse_garbage(data):
    try:
        w.parse_message(data)
    except ValueError:
        pass
    return True  # any other exception propagates and fails the property


def prop_parse_mutated(value):
    name, records, idx = value
    msg = bytearray(w.build_response(_query(name), w.NOERROR, _answers(name, records), max_size=65535))
    msg[idx % len(msg)] ^= 0x80
    try:
        w.parse_message(bytes(msg))
    except ValueError:
        pass
    return True


# ---- 5. AEAD round-trip (requirement 3.1) ----
def prop_aead_roundtrip(value):
    key, nonce, pt, aad = value
    ct, tag = chacha.aead_encrypt(key, nonce, pt, aad)
    return chacha.aead_decrypt(key, nonce, ct, tag, aad) == pt


# ---- 6. AEAD rejects tampering (requirement 3.2) ----
def prop_aead_tamper(value):
    key, nonce, pt, aad, bitpos = value
    ct, tag = chacha.aead_encrypt(key, nonce, pt, aad)
    blob = bytearray(ct) + bytearray(tag) + bytearray(aad)
    pos = bitpos % (len(blob) * 8)
    blob[pos // 8] ^= 1 << (pos % 8)
    n = len(ct)
    try:
        chacha.aead_decrypt(key, nonce, bytes(blob[:n]), bytes(blob[n:n + 16]), bytes(blob[n + 16:]))
    except ValueError:
        return True
    return False  # the change went undetected


# ---- 7. RSA-OAEP round-trip (requirement 3.3) ----
def prop_oaep_roundtrip(value):
    message, label = value
    return rsa.decrypt_oaep(RSA_KEY, rsa.encrypt_oaep(RSA_KEY, message, label), label) == message


# ---- 8. Signatures verify and reject (requirement 3.4) ----
def prop_signatures(value):
    message, other = value
    sig = rsa.sign_pkcs1(RSA_KEY, message)
    if not rsa.verify_pkcs1(RSA_KEY, message, sig):
        return False
    if other == message:
        other = message + b"\x00"
    return not rsa.verify_pkcs1(RSA_KEY, other, sig)


# ---- 9. A block covers every subdomain (requirement 4.1) ----
def prop_block_subdomains(value):
    domain, prefix = value
    name = ".".join(prefix + [domain])
    rules = blocklist.Rules(BUILTIN, set(), set())
    return rules.decide(name)[0] == "block"


# ---- 10. The allow list wins (requirement 4.2) ----
def prop_allow_wins(value):
    sld, tld, sub = value
    domain = sld + tld
    name = ".".join(sub + [domain])
    rules = blocklist.Rules(BUILTIN, {domain}, {domain})
    return rules.decide(name)[0] == "allow"


# ---- 11. Case and a trailing dot don't change the decision (requirement 4.3) ----
_INVARIANCE_NAMES = ["blocked.example", "x.blocked.example", "allow.example",
                     "sub.allow.example", "printer", "host.lan", "name.local",
                     "deep.sub.example", "use-application-dns.net", BUILTIN_LIST[0]]


def prop_case_and_dot(name):
    rules = blocklist.Rules(BUILTIN, {"blocked.example"}, {"allow.example"})
    base = rules.decide(name)
    for variant in (name.upper(), name.capitalize(), name + ".", name.swapcase() + "."):
        if rules.decide(variant) != base:
            return False
    return True


# ---- 12. Local names are answered locally (requirement 4.4) ----
def prop_local_names(value):
    base, suffix, extra = value
    name = base if suffix is None else f"{extra}.{base}.{suffix}"
    rules = blocklist.Rules(BUILTIN, set(), set())
    return rules.decide(name)[0] == "local"


# ---- 13. Passphrase shape and entropy (requirements 5.1, 5.2) ----
def prop_passphrase(value):
    count, sep, caps, num = value
    phrase, bits = passwords.generate_passphrase(count, sep, caps, num)
    expected_words = max(3, min(12, count))
    parts = phrase.split(sep)
    if num:
        words, number = parts[:-1], parts[-1]
        if not (number.isdigit() and len(number) <= 4 and 0 <= int(number) <= 9999):
            return False
    else:
        words = parts
    if len(words) != expected_words or any(len(wd) != 5 or not wd.isalpha() for wd in words):
        return False
    expected_bits = expected_words * passwords._BITS_PER_WORD + (math.log2(10000) if num else 0)
    return math.isclose(bits, expected_bits, rel_tol=1e-9)


# ---- 14. Strength score and label stay in range (requirement 5.3) ----
def prop_strength_range(text):
    r = passwords.estimate_strength(text)
    return 0 <= r["score"] <= 4 and r["label"] == passwords.STRENGTH_LABELS[r["score"]]


# ---- 15. Leak check statuses (requirements 5.4, 5.5) ----
def prop_leak_status(text):
    return leaks.check(text)["status"] in ("leaked", "pattern", "clear")


def prop_leaked_entries(entry):
    return all(leaks.check(v)["status"] == "leaked"
               for v in (entry, entry.upper(), entry.capitalize(), entry.swapcase()))


PROPERTIES = [
    ("DNS query round-trips", Tuples(DnsNames(), QTYPES, EDNS), prop_query_roundtrip),
    ("DNS response round-trips", Tuples(DnsNames(), RECORDS), prop_response_roundtrip),
    ("DNS response respects the size limit", Tuples(DnsNames(), RECORDS, Integers(512, 4096)), prop_size_limit),
    ("DNS parser survives random bytes", Binary(0, 600), prop_parse_garbage),
    ("DNS parser survives a mutated message", Tuples(DnsNames(), RECORDS, Integers(0, 100000)), prop_parse_mutated),
    ("ChaCha20-Poly1305 round-trips", Tuples(Binary(32, 32), Binary(12, 12), Binary(0, 1500), Binary(0, 64)), prop_aead_roundtrip),
    ("ChaCha20-Poly1305 rejects tampering", Tuples(Binary(32, 32), Binary(12, 12), Binary(0, 200), Binary(0, 64), Integers(0, 10 ** 7)), prop_aead_tamper),
    ("RSA-OAEP round-trips", Tuples(Binary(0, 62), Binary(0, 16)), prop_oaep_roundtrip),
    ("RSA signatures verify and reject", Tuples(Binary(0, 500), Binary(0, 500)), prop_signatures),
    ("A block covers every subdomain", Tuples(SampledFrom(BUILTIN_LIST), Lists(Text(LABEL, 1, 10), 1, 3)), prop_block_subdomains),
    ("The allow list beats a block", Tuples(Text(LOWER, 3, 10), SampledFrom([".com", ".net", ".example"]), Lists(Text(LABEL, 1, 8), 0, 2)), prop_allow_wins),
    ("Case and a trailing dot don't matter", SampledFrom(_INVARIANCE_NAMES), prop_case_and_dot),
    ("Local names are answered locally", Tuples(Text(LOWER, 1, 12), SampledFrom([None, "lan", "local", "home.arpa", "internal"]), Text(LOWER, 1, 8)), prop_local_names),
    ("Passphrases have the right shape and entropy", Tuples(Integers(-5, 30), SampledFrom(["-", ".", "_"]), Booleans(), Booleans()), prop_passphrase),
    ("Strength score and label stay in range", Text(WIDE, 1, 64), prop_strength_range),
    ("Leak check returns a valid status", Text(WIDE, 0, 24), prop_leak_status),
    ("Known leaked passwords are flagged in any case", SampledFrom(sorted(leaks.LEAKED)), prop_leaked_entries),
]


def main():
    ok = True
    for name, gen, prop in PROPERTIES:
        res = check(name, gen, prop)
        ok = ok and res.passed
        print(f"{'PASS' if res.passed else 'FAIL'}  {name}  (seed {res.seed}, {res.runs} runs)")
        if not res.passed:
            print(f"        failing input: {res.failing!r}")
            print(f"        shrunk to:     {res.shrunk!r}")
            if res.error:
                print(f"        error:         {res.error}")
    print("\n" + ("ALL PROPERTIES HELD" if ok else "SOME PROPERTIES FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
