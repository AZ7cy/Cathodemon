# Requirements Document

## Introduction

Cathodemon's tests check fixed examples. This feature adds property-based
tests. Each property states a rule that must hold for any input, and a test
runner checks the rule against hundreds of random inputs. When a rule fails,
the runner shrinks the input to the smallest one that still fails, so the bug
is easy to see.

Cathodemon may only use the Python standard library (see the own-code-only
steering file). The runner is therefore written for this project; Hypothesis
and other property-testing packages must not be used.

## Requirements

### Requirement 1: A property-test runner built on the standard library

**User Story:** As the owner, I want a small property-test runner written for
this project, so that I get property-based testing without adding a
third-party package.

#### Acceptance Criteria

1. WHEN a property is checked THE SYSTEM SHALL call it with a fixed number of
   generated inputs: 100 by default, or the value of `CATHODEMON_PBT_RUNS`
   when that is set.
2. THE SYSTEM SHALL draw every input from a seeded `random.Random`, using the
   value of `CATHODEMON_PBT_SEED` when it is set and a fresh random seed
   otherwise.
3. IF a property returns False or raises an exception THEN THE SYSTEM SHALL
   report the property's name, the seed and the failing input.
4. IF a property fails THEN THE SYSTEM SHALL try simpler versions of the
   failing input and report the simplest one that still fails.
5. THE SYSTEM SHALL import only standard-library modules, so that
   `python scripts/audit_imports.py` still reports no third-party imports.

### Requirement 2: DNS messages survive encoding and decoding

**User Story:** As the owner, I want the DNS packet code checked against
random names and records, so that DNS Shield and Recon never mangle a message
or crash on a bad one.

#### Acceptance Criteria

1. WHEN a query is built for any valid name, record type and EDNS size THE
   SYSTEM SHALL parse it back to the same ID, name, record type and EDNS size.
2. WHEN a response with any list of A and AAAA records is built without a
   size limit THE SYSTEM SHALL parse it back to the same records, in the same
   order, with the same TTLs and addresses and with names in lowercase.
3. WHEN a response is built with any size limit of 512 bytes or more THE
   SYSTEM SHALL return a message no longer than that limit.
4. IF the records don't fit within the size limit THEN THE SYSTEM SHALL set
   the truncated (TC) flag and include no records.
5. WHEN any random bytes are parsed THE SYSTEM SHALL either return a message
   or raise ValueError, and SHALL never raise any other kind of exception.

### Requirement 3: Encryption and signatures always round-trip

**User Story:** As a Mail user, I want the hand-written crypto checked against
random keys and messages, so that a message I encrypt or sign always opens
correctly and tampering is always caught.

#### Acceptance Criteria

1. WHEN any plaintext of 0 to 1,500 bytes and any associated data of 0 to 64
   bytes are encrypted with ChaCha20-Poly1305 under any key and nonce THE
   SYSTEM SHALL decrypt them back to the same plaintext.
2. IF any single bit of the ciphertext, the tag or the associated data is
   changed THEN THE SYSTEM SHALL refuse to decrypt and raise ValueError.
3. WHEN any message short enough for the key is encrypted with RSA-OAEP THE
   SYSTEM SHALL decrypt it back to the same message.
4. WHEN any message is signed THE SYSTEM SHALL accept the signature for that
   message and reject it for any different message.

### Requirement 4: DNS Shield decisions are consistent

**User Story:** As a DNS Shield user, I want the blocking rules checked
against random names, so that blocks, allows and local answers behave the
same way every time.

#### Acceptance Criteria

1. WHEN a domain is on a block list THE SYSTEM SHALL also block every name
   under it.
2. WHEN a domain is on both the allow list and a block list THE SYSTEM SHALL
   allow it and every name under it.
3. THE SYSTEM SHALL make the same decision for a name whatever its letter
   case, and whether or not it ends with a dot.
4. WHEN a name has a single label, or ends in a local suffix such as `.lan`,
   `.local`, `.home.arpa` or `.internal`, THE SYSTEM SHALL answer it locally.

### Requirement 5: Password tools report accurately

**User Story:** As a Vault user, I want the password tools checked against
random input, so that what they tell me is always accurate.

#### Acceptance Criteria

1. WHEN a passphrase is generated for any word count from 3 to 12, any
   separator the app offers, and either setting for capitals and the extra
   number THE SYSTEM SHALL return exactly that many five-letter words, plus
   the number when asked for, and an entropy figure equal to the word count
   times the bits per word, plus log2(10000) for the number.
2. WHEN a word count below 3 or above 12 is requested THE SYSTEM SHALL use 3
   or 12 instead.
3. WHEN the strength of any text of 1 to 64 characters is estimated THE
   SYSTEM SHALL return a score from 0 to 4 and the label that matches it.
4. WHEN any text is checked against known leaks THE SYSTEM SHALL return
   "leaked", "pattern" or "clear".
5. WHEN any entry on the leaked-password list is checked, in any mix of
   letter case, THE SYSTEM SHALL return "leaked".

### Requirement 6: One command runs every property

**User Story:** As the owner, I want one command that runs every property, so
that I can check the whole project before submitting it.

#### Acceptance Criteria

1. WHEN `python -S scripts/try_properties.py` is run THE SYSTEM SHALL check
   every property and print one PASS or FAIL line for each, with the seed it
   used.
2. IF any property fails THEN THE SYSTEM SHALL exit with code 1, and
   otherwise with code 0.
3. THE SYSTEM SHALL finish every property in under 60 seconds on a typical
   laptop at the default number of runs.
