---
inclusion: always
---

# Cathodemon

A retro-terminal home security suite for the desktop, with a green-on-black
CRT look. Built with Kiro for Kiroween 2026 (Resurrection category). Owner:
AZ7cy.

## Tools

- **Mail** (`ui/mail_view.py`, `core/securemsg.py`, `core/phishing.py`): keys,
  sign and encrypt, decrypt and verify, and a plain-language phishing check.
- **Recon** (`ui/recon_view.py`, `core/reputation.py`): DNS, certificate and
  look-alike report for a domain or URL.
- **Vault** (`ui/vault_view.py`, `core/passwords.py`, `core/leaks.py`):
  strength, offline leak check, passphrases and a habits audit.
- **Chronicle** (`ui/chronicle_view.py`, `core/logstory.py`): raw logs into an
  incident timeline and story.
- **DNS Shield** (`ui/dns_view.py`, `core/sinkhole.py`, `core/blocklist.py`,
  `shield.py`): a DNS server that blocks ads, trackers and look-alike domains.

## How the code is organised

- `cathodemon/core/` holds the logic and no GUI code, so it can be tested on
  its own.
- `cathodemon/ui/` has one view per tool, built from the helpers in
  `widgets.py` and the colours in `theme.py`.
- Tkinter isn't thread-safe. Run network or slow work through
  `workers.run_async`, never on the main thread.
- User data lives in `~/.cathodemon/` (the keyring and DNS Shield lists).
- Samples and demos use the made-up bank "Ebonmarsh" and the reserved names
  `example.com` and `*.example`, never real brands. The Kiroween video rules
  ban third-party trademarks.

## Commands

`cdm` is short for `python -m cathodemon`. On Windows, run it from the project
folder (`.\cdm` in PowerShell); elsewhere, use `python -m cathodemon` with the
same commands.

- Run the app: `cdm`
- DNS Shield without the window: `cdm shield --port 5353`
- Every test, with installed packages hidden: `cdm test`. One suite:
  `cdm test crypto` (suites: audit, crypto, dns, core, gui; dns and core use
  the network)
- Import audit: `cdm audit`

## Privacy promises

- Passwords, private keys and logs never leave the device.
- Recon only contacts the DNS hierarchy and the site being scanned.
- DNS Shield answers only devices on the local network unless told otherwise.
