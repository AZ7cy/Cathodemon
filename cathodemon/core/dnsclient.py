"""Recon's DNS lookups, answered by Cathodemon's own resolver.

The resolver walks the DNS hierarchy from the root itself, so no third-party
DNS service sees or answers these lookups. Standard library only.
"""
from __future__ import annotations

from . import dnswire as w
from .resolver import shared_resolver

TYPES = {"A": w.A, "AAAA": w.AAAA, "MX": w.MX, "NS": w.NS, "TXT": w.TXT,
         "CAA": w.CAA, "CNAME": w.CNAME, "SOA": w.SOA}


def to_ascii(name: str) -> str:
    """Convert an international domain name to the ASCII (punycode) form DNS uses."""
    name = name.strip().rstrip(".")
    try:
        name.encode("ascii")
        return name.lower()
    except UnicodeEncodeError:
        return name.encode("idna").decode("ascii").lower()


def resolve(name: str, rtype: str):
    """Return (values, ttl) for one record type. values is [] when there are none."""
    qtype = TYPES[rtype]
    ans = shared_resolver().resolve(to_ascii(name), qtype)
    records = [rr for rr in ans.records if rr.rtype == qtype and rr.value is not None]
    ttl = min((rr.ttl for rr in records), default=None)
    return [rr.value for rr in records], ttl
