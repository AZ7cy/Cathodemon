#!/usr/bin/env python3
"""Convenience launcher: same as `python -m cathodemon`, and takes the same commands."""
from cathodemon.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
