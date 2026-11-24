---
inclusion: always
---

# Own code only

Everything in Cathodemon is written in this repository. The owner checks this
closely, so follow these rules exactly.

## Rules

- Use only the Python standard library (Python 3.11+). Never add a pip
  package, a requirements file, vendored code, snippets copied from other
  projects, or a Docker image.
- Don't bundle or download other people's data: no third-party blocklists,
  wordlists, password lists, fonts or ASCII-art generators. Write the data for
  this project instead, like `cathodemon/data/blocklist.txt`,
  `cathodemon/core/leaks.py` and the block letters in `cathodemon/ui/banner.py`.
- Don't call third-party services such as public DNS resolvers,
  DNS-over-HTTPS providers, breach-check APIs or WHOIS servers. The app may
  only contact the DNS hierarchy (through `cathodemon/core/resolver.py`) and
  the site a user asks Recon to scan.
- Implementing a public standard (an RFC) is fine. Copying someone else's
  implementation is not. Check crypto against the RFC's official test vectors.
- If a task seems to need a third-party package, data set or service, stop and
  ask the owner before doing anything.

## Checks

- `python scripts/audit_imports.py` must report 0 third-party imports and 0
  dynamic imports, exec or eval. A hook reminds the agent to run it after every
  Python file it saves.
- Every test must pass with installed packages hidden, for example
  `python -S scripts/try_core.py`.
- Keep `LICENSE` as the standard MIT text with "Copyright (c) 2026 AZ7cy", so
  GitHub detects it. The Kiroween 2026 rules require a license GitHub detects.
