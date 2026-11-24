# Implementation Plan

- [x] 1. Build the property-test runner in `scripts/pbt.py`
  - [x] 1.1 Add the generators (integers, booleans, binary, text, lists, tuples, sampled_from and dns_names), each with `draw` and `shrink`
    - Draw only from the `random.Random` passed in, so a seed reproduces every input
    - _Requirements: 1.1, 1.2, 1.4_
  - [x] 1.2 Add `check()` with seeded runs, the `CATHODEMON_PBT_RUNS` and `CATHODEMON_PBT_SEED` settings, and a `Result` holding the seed and failing input
    - A property fails when it returns False or raises
    - _Requirements: 1.1, 1.2, 1.3_
  - [x] 1.3 Add shrinking that keeps the first simpler input that still fails, for at most 200 steps
    - _Requirements: 1.4_
  - [x] 1.4 Run `python scripts/audit_imports.py` and confirm the runner uses only the standard library
    - _Requirements: 1.5_

- [x] 2. Write the DNS message properties (properties 1 to 4 in the design)
  - Query round-trip, response round-trip, size limit and truncation, and random bytes
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [x] 3. Write the crypto properties (properties 5 to 8)
  - Generate one 1,024-bit RSA key per run and reuse it
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [x] 4. Write the DNS Shield rule properties (properties 9 to 12)
  - Build the rules from the built-in list only, not with `load_rules()`
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 5. Write the password tool properties (properties 13 to 15)
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [x] 6. Add `scripts/try_properties.py`, which runs every property, prints one PASS or FAIL line with the seed for each, and exits with code 1 if any failed
  - _Requirements: 6.1, 6.2_

- [x] 7. Check the result against the project rules
  - Time a full run at the default 100 inputs and keep it under 60 seconds
  - Run it with `python -S`, then run the import audit
  - Add the command to the Tests section of `README.md`
  - _Requirements: 1.5, 6.1, 6.3_

- [x] 8. Fix any bug a property finds, and add its shrunk input as a fixed example in the matching existing test suite
  - No property found a bug on this run, so no new fixed examples were needed.
  - _Requirements: 2.5, 3.2, 4.3, 5.4_
