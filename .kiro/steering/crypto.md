---
inclusion: fileMatch
fileMatchPattern: ["cathodemon/core/rsa.py", "cathodemon/core/chacha.py", "cathodemon/core/securemsg.py"]
---

# Cryptography rules

This crypto is hand-written for learning. Keep it correct and honest.

- Follow the standards exactly: RFC 8439 for ChaCha20-Poly1305, and RFC 8017
  for RSA-OAEP and PKCS#1 v1.5 signatures. After any change, run
  `python -S scripts/try_crypto.py`. The RFC test vectors must still match
  byte for byte.
- Use `secrets` for every key, nonce, salt and prime. Never use `random`.
- Compare authentication tags and signatures with `hmac.compare_digest` or
  `secrets.compare_digest`, never with `==`.
- Give every encryption a fresh random nonce. Never reuse a nonce with the
  same key.
- Never log, print or save a passphrase, a private key or a decrypted message.
  Private keys are stored only encrypted (scrypt, then ChaCha20-Poly1305).
- When decryption fails, keep the error vague ("wrong passphrase, or this
  message isn't addressed to you") so it doesn't reveal which check failed.
- Don't present this as a replacement for audited tools. The README tells
  people to use GnuPG or age for secrets that really matter.
