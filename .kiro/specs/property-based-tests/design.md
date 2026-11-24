# Design Document

## Overview

Two new files go in `scripts/`, next to the existing test suites:

- `scripts/pbt.py`: the property-test runner and the input generators.
- `scripts/try_properties.py`: the properties for the DNS code, the crypto,
  DNS Shield's rules and the password tools.

App code changes only if a property finds a bug. Both new files use only the
standard library.

## Architecture

```
try_properties.py        defines each property as a function of one input
        |
        v
pbt.check(name, gen, prop)        seeded random.Random, N runs
        |  on the first failure
        v
pbt.shrink(gen, value, prop)      simplest input that still fails
        |
        v
Result -> one PASS or FAIL line with the seed, the failing input
          and the shrunk input
```

## Components and interfaces

### Generators (`scripts/pbt.py`)

A generator is an object with two methods:

- `draw(rng)` returns a random value, using only the `random.Random` it is
  given, so a seed reproduces every input.
- `shrink(value)` yields simpler candidate values, simplest first.

| Generator | Draws | Shrinks towards |
|---|---|---|
| `integers(lo, hi)` | an int from lo to hi | lo, then halfway between |
| `booleans()` | True or False | False |
| `binary(min_len, max_len)` | bytes | shorter, then zero bytes |
| `text(alphabet, min_len, max_len)` | a string | shorter, then the alphabet's first character |
| `lists(gen, min_len, max_len)` | a list | fewer items, then simpler items |
| `tuples(*gens)` | a tuple | each part in turn |
| `sampled_from(seq)` | one item of seq | earlier items |
| `dns_names()` | a valid name of 1 to 4 labels, each 1 to 20 of `a-z0-9-`, never starting or ending with `-` | fewer and shorter labels |

### Runner

`check(name, gen, prop, runs=None, seed=None) -> Result`

- `runs` defaults to `CATHODEMON_PBT_RUNS`, or 100.
- `seed` defaults to `CATHODEMON_PBT_SEED`, or a fresh seed from
  `random.SystemRandom`.
- A property fails when it returns False or raises an exception.
- On a failure, shrinking repeatedly keeps the first candidate from
  `gen.shrink(value)` that still fails, for at most 200 steps.
- `Result` holds the name, passed, seed, runs, the failing input, the shrunk
  input and the error text.

## Correctness properties

Each property is a "for any" rule taken from the requirements.

1. **Query round-trip.** For any valid name, any record type from A, AAAA,
   MX, TXT, NS, CAA and HTTPS, and any EDNS size (none, or 512 to 4,096),
   parsing `build_query(...)` returns the same ID, name, type and EDNS size.
   *Validates 2.1.*
2. **Response round-trip.** For any name and 0 to 20 A or AAAA records with
   TTLs from 0 to 86,400, `parse_message(build_response(..., max_size=65535))`
   returns the same records in the same order, with names in lowercase.
   *Validates 2.2.*
3. **Size limit.** For any such response and any limit from 512 to 4,096, the
   message is no longer than the limit. When the full message would be
   longer, the TC flag is set and there are no answers. *Validates 2.3 and
   2.4.*
4. **Garbage in.** For any 0 to 600 random bytes, and for any valid message
   with random bytes changed, `parse_message` returns a message or raises
   ValueError. *Validates 2.5.*
5. **AEAD round-trip.** For any 32-byte key, 12-byte nonce, plaintext of 0
   to 1,500 bytes and associated data of 0 to 64 bytes, decrypting the
   output of `aead_encrypt` returns the plaintext. *Validates 3.1.*
6. **AEAD tamper.** For any such message and any single bit position across
   the ciphertext, the tag and the associated data, flipping that bit makes
   `aead_decrypt` raise ValueError. *Validates 3.2.*
7. **OAEP round-trip.** For any message of 0 to 62 bytes (the limit for a
   1,024-bit key with SHA-256) and any label, `decrypt_oaep(encrypt_oaep(m))`
   returns m. *Validates 3.3.*
8. **Signatures.** For any message of 0 to 500 bytes, `verify_pkcs1` accepts
   its signature, and rejects that signature for any different message.
   *Validates 3.4.*
9. **Blocks cover subdomains.** For any domain on the built-in list with 1 to
   3 random labels in front of it, `decide` returns "block".
   *Validates 4.1.*
10. **Allow wins.** For any public-looking domain on both the allow and block
    lists, `decide` allows it and every name under it. *Validates 4.2.*
11. **Case and trailing dot.** For any name, `decide` returns the same result
    after random letter case changes and an added trailing dot.
    *Validates 4.3.*
12. **Local names.** For any single label, or any name ending in `.lan`,
    `.local`, `.home.arpa` or `.internal`, `decide` returns "local".
    *Validates 4.4.*
13. **Passphrase shape.** For any word count from -5 to 30, any separator in
    `-`, `.` and `_`, and both settings for capitals and the number, the
    phrase has clamp(count, 3, 12) five-letter words, plus a number of up to
    four digits when asked for, and the reported bits match the formula.
    *Validates 5.1 and 5.2.*
14. **Strength range.** For any text of 1 to 64 characters, including
    non-Latin characters, `estimate_strength` returns a score from 0 to 4 and
    `STRENGTH_LABELS[score]` as the label. *Validates 5.3.*
15. **Leak check.** For any text, `leaks.check` returns one of the three
    statuses, and for any `LEAKED` entry with random letter case it returns
    "leaked". *Validates 5.4 and 5.5.*

## Test setup

- RSA keys are slow to make, so generate one 1,024-bit key per run and reuse
  it for properties 7 and 8.
- Build DNS Shield rules with `Rules(builtin, set(), set())` from
  `cathodemon/data/blocklist.txt`, not with `load_rules()`, so the owner's own
  lists in `~/.cathodemon` can't change the results.
- Properties 10 and 11 use made-up names under `.example`, `.com` and `.net`.
  No property touches the network.

## Error handling

- An exception inside a property counts as a failure. The report shows the
  exception type and message.
- The runner checks every property even after one fails, then exits with
  code 1.

## Testing strategy

- Use the default 100 runs while developing, and `CATHODEMON_PBT_RUNS=1000`
  before submitting.
- Repeat a failure exactly with `CATHODEMON_PBT_SEED=<seed>`.
- When a property finds a bug, fix it and add the shrunk input as a fixed
  example in the matching existing suite, so the bug can't come back.
- Before marking the work done, run `python scripts/audit_imports.py` and
  `python -S scripts/try_properties.py`.
