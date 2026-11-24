"""Validate the hand-written crypto against official RFC 8439 test vectors
and RSA round-trips. Pure stdlib."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cathodemon.core import chacha, rsa

ok = True
def check(label, cond, extra=""):
    global ok
    ok = ok and bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {label}{(' - ' + extra) if extra else ''}")

# ---- Poly1305 (RFC 8439 section 2.5.2) ----
poly_key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
poly_msg = b"Cryptographic Forum Research Group"
poly_tag = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
check("Poly1305 RFC vector", chacha.poly1305_mac(poly_msg, poly_key) == poly_tag)

# ---- AEAD ChaCha20-Poly1305 (RFC 8439 section 2.8.2) ----
key = bytes(range(0x80, 0xA0))
nonce = bytes.fromhex("070000004041424344454647")
aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you only "
             b"one tip for the future, sunscreen would be it.")
exp_ct = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116")
exp_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
ct, tag = chacha.aead_encrypt(key, nonce, plaintext, aad)
check("AEAD ciphertext matches RFC 8439", ct == exp_ct, ct.hex()[:24] + "...")
check("AEAD tag matches RFC 8439", tag == exp_tag, tag.hex())
back = chacha.aead_decrypt(key, nonce, ct, tag, aad)
check("AEAD decrypt round-trip", back == plaintext)
tampered = bytearray(ct); tampered[0] ^= 1
try:
    chacha.aead_decrypt(key, nonce, bytes(tampered), tag, aad); check("AEAD rejects tamper", False)
except ValueError:
    check("AEAD rejects tamper", True)

# ---- RSA ----
t0 = time.time()
k1 = rsa.generate(1024)
msg = b"attack at dawn - the old terminal, midnight"
ct2 = rsa.encrypt_oaep(k1, msg)
check("RSA-OAEP round-trip", rsa.decrypt_oaep(k1, ct2) == msg)
sig = rsa.sign_pkcs1(k1, msg)
check("RSA sign/verify", rsa.verify_pkcs1(k1, msg, sig))
check("RSA verify rejects altered message", not rsa.verify_pkcs1(k1, msg + b"!", sig))
k2 = rsa.generate(1024)
check("RSA verify rejects wrong key", not rsa.verify_pkcs1(k2, msg, sig))
try:
    rsa.decrypt_oaep(k2, ct2); check("RSA-OAEP rejects wrong key", False)
except ValueError:
    check("RSA-OAEP rejects wrong key", True)
print(f"(1024-bit keygen x2 in {time.time()-t0:.2f}s)")

t1 = time.time()
rsa.generate(2048)
print(f"(2048-bit keygen in {time.time()-t1:.2f}s)")

print("\n" + ("ALL CRYPTO CHECKS PASSED" if ok else "SOME CRYPTO CHECKS FAILED"))
sys.exit(0 if ok else 1)
