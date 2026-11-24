# Security Policy

Cathodemon is an educational project built for the Kiroween 2026 hackathon. It
revives classic security tools and implements its own cryptography using only
the Python standard library.

## Status and scope

- The cryptography (RSA-OAEP and PKCS#1 v1.5 from RFC 8017, ChaCha20-Poly1305
  from RFC 8439) is hand-written and checked against the RFCs' official test
  vectors, but it has **not** been independently audited.
- **Do not** use Cathodemon to protect secrets that really matter. For that,
  use audited tools such as GnuPG or age. The README says the same.
- Everything runs on your own machine. Nothing is uploaded. Private keys live
  only in `~/.cathodemon/keyring.json`, encrypted with your passphrase
  (scrypt + ChaCha20-Poly1305). Recon contacts only the site you check and the
  DNS hierarchy; DNS Shield answers only your local network unless you change
  that.

## Reporting a vulnerability

If you find a security issue, please report it privately through GitHub's
"Report a vulnerability" (Security advisories) on this repository, or open an
issue that describes the problem without sensitive details. Please don't include
real private keys, passphrases or personal data in a report.

## Good habits when running it

- Keep your keyring passphrase strong and private. It is the only thing
  protecting an exported private key.
- A private key you back up from Mail is written as a `*.asc` file. Those are
  git-ignored, so you don't commit one by mistake.
