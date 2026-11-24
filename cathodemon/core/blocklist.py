"""DNS Shield rules: decide whether a name is blocked, allowed or answered locally.

Sources, in order of priority:
1. Local names (printer, *.lan, private reverse lookups...) never leave the network.
2. Your allow list always wins.
3. Your block list, then Cathodemon's built-in list (data/blocklist.txt).
4. Smart blocking: look-alike phishing domains, detected by Cathodemon's own
   look-alike logic rather than a downloaded feed.
Standard library only.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .lookalike import BRANDS, _normalize, registrable_parts, to_unicode

BUILTIN_PATH = Path(__file__).resolve().parent.parent / "data" / "blocklist.txt"
USER_DIR = Path.home() / ".cathodemon"
USER_BLOCK_PATH = USER_DIR / "shield-block.txt"
USER_ALLOW_PATH = USER_DIR / "shield-allow.txt"

# Reserved or private suffixes that must never be sent to the internet.
LOCAL_SUFFIXES = ("local", "localdomain", "lan", "home", "home.arpa", "internal",
                  "invalid", "test", "onion")
# Firefox asks for this name; "no such domain" tells it to keep using this DNS
# server instead of switching to its own encrypted DNS provider.
CANARY = "use-application-dns.net"

# Words that turn "brand-in-someone-else's-domain" into a credential-phishing pattern.
_KEYWORDS = ("login", "signin", "logon", "verify", "verification", "secure", "account",
             "update", "confirm", "unlock", "recover", "billing", "wallet", "support",
             "password", "delivery", "redelivery", "package", "parcel", "tracking",
             "shipment", "refund", "invoice", "auth")
_HOST_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")


def parse_list(text: str) -> set:
    """Read one domain per line. Also accepts hosts-file lines ("0.0.0.0 example.com")."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        name = parts[-1] if len(parts) > 1 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1") else parts[0]
        name = name.rstrip(".")
        if name and name != "localhost" and _HOST_RE.match(name):
            out.add(name)
    return out


def _read(path: Path) -> set:
    try:
        return parse_list(path.read_text(encoding="utf-8"))
    except OSError:
        return set()


def _suffix_match(name: str, domains: set):
    labels = name.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in domains:
            return candidate
    return None


def _is_local(name: str) -> bool:
    if "." not in name:                      # single label such as "printer"
        return True
    labels = name.split(".")
    if len(labels) == 4 and all(p.isdigit() for p in labels):  # an IP address, not a name
        return True
    if name == "localhost" or name.endswith(".localhost"):
        return True
    if any(name == s or name.endswith("." + s) for s in LOCAL_SUFFIXES):
        return True
    if name.endswith(".in-addr.arpa"):       # reverse lookup of a private IPv4 address
        octets = name[: -len(".in-addr.arpa")].split(".")[::-1]
        if 1 <= len(octets) <= 4 and all(o.isdigit() and int(o) <= 255 for o in octets):
            ip = ipaddress.ip_address(".".join(octets + ["0"] * (4 - len(octets))))
            return not ip.is_global
    if name.endswith(".ip6.arpa"):           # reverse lookup of a private IPv6 address
        nibbles = "".join(name[: -len(".ip6.arpa")].split(".")[::-1])
        if nibbles[:2] in ("fc", "fd") or nibbles[:3] in ("fe8", "fe9", "fea", "feb"):
            return True
        if nibbles == "0" * 31 + "1":
            return True
    return False


def lookalike_reason(name: str):
    """Return why `name` looks like a phishing copy of a known brand, or None.

    Deliberately conservative, because a match blocks the domain for the whole
    network: only character-swap spoofs, Unicode homographs, and a brand name
    combined with a login/delivery word on a domain the brand doesn't own.
    """
    parts = registrable_parts(name)
    sld = parts["sld"]
    if not sld or sld in BRANDS:
        return None
    if "xn--" in sld:
        uni_sld = registrable_parts(to_unicode(name))["sld"]
        brand = _normalize(uni_sld)
        if brand in BRANDS:
            return f"look-alike of {brand} (Unicode letters that imitate it)"
    brand = _normalize(sld)
    if brand in BRANDS and brand != sld and len(brand) >= 4:
        return f"look-alike of {brand} (characters swapped: {sld})"
    keyword = next((k for k in _KEYWORDS if k in sld or k in parts["sub"]), None)
    if keyword:
        for brand in BRANDS:
            if re.search(rf"(^|-){re.escape(brand)}(-|$)", sld):
                return f"uses '{brand}' with '{keyword}' on a domain {brand} doesn't own"
        sub_labels = parts["sub"].split(".") if parts["sub"] else []
        brand = next((b for b in BRANDS if b in sub_labels), None)
        if brand:
            return f"puts '{brand}' in front of someone else's domain ({sld})"
    return None


class Rules:
    def __init__(self, builtin: set, user_block: set, allow: set, smart: bool = True):
        self.builtin = builtin
        self.user_block = user_block
        self.allow = allow
        self.smart = smart

    def decide(self, name: str):
        """Return (action, reason). action is 'local', 'block' or 'allow'."""
        n = name.strip().rstrip(".").lower()
        if n == CANARY:
            return "local", "Firefox DNS check, answered 'no such domain' so Firefox keeps using this shield"
        if _is_local(n):
            return "local", "local name, answered here and never sent to the internet"
        hit = _suffix_match(n, self.allow)
        if hit:
            return "allow", f"on your allow list ({hit})"
        hit = _suffix_match(n, self.user_block)
        if hit:
            return "block", f"on your block list ({hit})"
        hit = _suffix_match(n, self.builtin)
        if hit:
            return "block", f"on the Cathodemon blocklist ({hit})"
        if self.smart:
            why = lookalike_reason(n)
            if why:
                return "block", why
        return "allow", ""


def load_rules(smart: bool = True) -> Rules:
    return Rules(_read(BUILTIN_PATH), _read(USER_BLOCK_PATH), _read(USER_ALLOW_PATH), smart)


def save_user_lists(block_text: str, allow_text: str) -> None:
    USER_DIR.mkdir(parents=True, exist_ok=True)
    USER_BLOCK_PATH.write_text(block_text.strip() + "\n", encoding="utf-8")
    USER_ALLOW_PATH.write_text(allow_text.strip() + "\n", encoding="utf-8")


def read_user_lists():
    def raw(path):
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""
    return raw(USER_BLOCK_PATH), raw(USER_ALLOW_PATH)
