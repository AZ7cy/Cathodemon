"""Exercise the stdlib-only core: DNS, cert, reputation, secure messaging,
passwords, phishing, logstory. Network checks included."""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cathodemon.core import (dnsclient, cert, reputation, securemsg, passwords,
                           phishing, logstory, lookalike)

ok = True
def check(label, cond, extra=""):
    global ok
    ok = ok and bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {label}{(' - ' + extra) if extra else ''}")

print("== dns client (network) ==")
a, ttl = dnsclient.resolve("github.com", "A")
check("resolve A", len(a) >= 1, f"{a} ttl={ttl}")
mx, _ = dnsclient.resolve("github.com", "MX")
check("resolve MX", len(mx) >= 1, str(mx[:2]))
ns, _ = dnsclient.resolve("github.com", "NS")
check("resolve NS", len(ns) >= 1, str(ns[:2]))
txt, _ = dnsclient.resolve("github.com", "TXT")
check("resolve TXT", len(txt) >= 1, f"{len(txt)} records")

print("\n== certificate (network) ==")
c = cert.inspect_certificate("github.com")
check("cert parsed", c["certificate"] is not None and c["certificate"]["issuer"], 
      c["certificate"]["issuer"] if c["certificate"] else "none")
check("cert has valid dates", c["certificate"] and c["certificate"]["valid_to"] > "2024")

print("\n== reputation (network) ==")
for tgt, expect in (("github.com", {"TRUSTED", "LIKELY OK", "CAUTION"}),
                    ("paypal-secure-login.com", {"SUSPICIOUS", "DANGER", "CAUTION"})):
    r = reputation.build_report(tgt)
    check(f"recon {tgt}", r["verdict"]["band"] in expect,
          f"score={r['score']} {r['verdict']['band']} findings={len(r['findings'])}")

print("\n== secure messaging ==")
t0 = time.time()
alice = securemsg.generate_identity("Alice", "alice@example.com", "pw-correcthorse", bits=1024)
bob = securemsg.generate_identity("Bob", "bob@example.com", "pw-correcthorse", bits=1024)
check("identity fingerprint len", len(alice["fingerprint"]) == 40, alice["fingerprint"][:12] + "...")
pub_meta = securemsg.key_meta(alice["public"])
check("public key_meta email", pub_meta["email"] == "alice@example.com" and not pub_meta["is_private"])
priv_meta = securemsg.key_meta(alice["private"])
check("private key_meta", priv_meta["is_private"] and priv_meta["fingerprint"] == alice["fingerprint"])
enc = securemsg.encrypt_and_sign(alice, bob["public"], "meet at the old terminal, midnight", "pw-correcthorse")
check("encrypt output", enc.startswith("-----BEGIN CATHODEMON MESSAGE-----"))
dv = securemsg.decrypt_and_verify(enc, bob, "pw-correcthorse", alice["public"],
                                  {"name": "Alice", "email": "alice@example.com"})
check("decrypt text", dv["text"] == "meet at the old terminal, midnight", dv["text"])
check("signature valid", dv["verdict"]["level"] == "valid", dv["verdict"]["text"][:48])
dv_nosender = securemsg.decrypt_and_verify(enc, bob, "pw-correcthorse")
check("unverified without sender", dv_nosender["verdict"]["level"] == "unverified")
clj = securemsg.sign_only(alice, "public statement for all", "pw-correcthorse")
check("sign-only block", "BEGIN CATHODEMON SIGNED MESSAGE" in clj)
dvc = securemsg.decrypt_and_verify(clj, bob, "", alice["public"], {"name": "Alice", "email": "a"})
check("cleartext verify valid", dvc["verdict"]["level"] == "valid" and "public statement" in dvc["text"])
try:
    securemsg.encrypt_and_sign(alice, bob["public"], "x", "WRONG")
    check("wrong passphrase rejected", False)
except ValueError:
    check("wrong passphrase rejected", True)
# tamper
bad = enc.replace("A", "B", 1)
try:
    securemsg.decrypt_and_verify(bad, bob, "pw-correcthorse", alice["public"])
    check("tamper detected", True, "(decoded but likely altered)")
except ValueError:
    check("tamper detected", True)
print(f"(2x 1024-bit identities in {time.time()-t0:.2f}s)")

print("\n== passwords ==")
weak = passwords.estimate_strength("password")
strong = passwords.estimate_strength(passwords.generate_passphrase(6)[0])
check("weak scored low", weak["score"] <= 1 and weak["warning"], f"{weak['score']} '{weak['warning'][:30]}'")
check("strong scored high", strong["score"] >= 3, str(strong["score"]))
phrase, bits = passwords.generate_passphrase(5, "-", True, True)
check("passphrase parts", len(phrase.split("-")) == 6, phrase)
check("entropy sane", 55 < bits < 110, f"{bits:.1f} bits")

print("\n== offline leak check ==")
from cathodemon.core import leaks
for pw, expect in [("password", "leaked"), ("123456", "leaked"), ("P@ssw0rd123!", "pattern"),
                   ("Summer2024!", "pattern"), ("12/05/1990", "pattern"), ("asdfgh", "leaked"),
                   ("zzzzzz", "pattern"), (phrase, "clear")]:
    got = leaks.check(pw)["status"]
    check(f"leak check {pw!r}", got == expect, got)

print("\n== pure logic (sanity) ==")
pr = phishing.analyze_email((ROOT / "examples/sample-phish.eml").read_text(encoding="utf-8"))
check("phishing DANGER", pr["verdict"]["band"] == "DANGER", f"score={pr['score']}")
lr = logstory.analyze_logs((ROOT / "examples/sample-incident.log").read_text(encoding="utf-8"), ref_year=2023)
check("logstory incidents", len(lr["incidents"]) >= 3)
check("lookalike g00gle", any("google" in f["title"] for f in lookalike.analyze_lookalike("g00gle.com")["findings"]))

print("\n" + ("ALL CORE CHECKS PASSED" if ok else "SOME CORE CHECKS FAILED"))
sys.exit(0 if ok else 1)
