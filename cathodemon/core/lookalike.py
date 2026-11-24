"""Detect typosquatting, homoglyph spoofing, IDN homographs and brand misuse."""
from __future__ import annotations

import re
from encodings.idna import ToUnicode

BRANDS = [
    "google", "gmail", "youtube", "microsoft", "outlook", "office365", "office",
    "windows", "apple", "icloud", "amazon", "aws", "facebook", "instagram",
    "whatsapp", "messenger", "netflix", "spotify", "linkedin", "twitter",
    "snapchat", "tiktok", "telegram", "dropbox", "adobe", "steam", "ebay",
    "walmart", "target", "bestbuy", "paypal", "venmo", "zelle", "cashapp",
    "stripe", "visa", "mastercard", "americanexpress", "chase", "wellsfargo",
    "bankofamerica", "citibank", "citi", "capitalone", "usbank", "hsbc",
    "barclays", "santander", "revolut", "coinbase", "binance", "kraken",
    "metamask", "blockchain", "robinhood", "dhl", "fedex", "ups", "usps",
    "dpd", "royalmail", "docusign", "wetransfer", "zoom", "slack", "github",
    "gitlab", "wordpress", "godaddy", "cloudflare", "verizon", "att", "tmobile",
    # A made-up bank used by the sample data and demos, so they show no real
    # company's trademark.
    "ebonmarsh",
]
PHISH_KEYWORDS = [
    "secure", "security", "login", "signin", "log-in", "account", "verify",
    "verification", "update", "confirm", "authenticate", "auth", "wallet",
    "billing", "payment", "recover", "unlock", "alert", "support", "service",
    "webscr", "manage", "portal", "id", "customer",
]
_HOMO = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
    "8": "b", "9": "g", "$": "s", "@": "a", "!": "i", "|": "l",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0405": "s", "\u03bf": "o",
    "\u03b1": "a", "\u03b5": "e", "\u03c1": "p", "\u03c5": "u",
}
_MULTI_TLDS = {"co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "com.br",
               "co.in", "co.nz", "co.za"}


def _normalize(s: str) -> str:
    return "".join(_HOMO.get(c, c) for c in s.lower())


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    if not m:
        return n
    if not n:
        return m
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]


def to_unicode(host: str) -> str:
    out = []
    for label in host.split("."):
        try:
            out.append(ToUnicode(label) if label.startswith("xn--") else label)
        except Exception:
            out.append(label)
    return ".".join(out)


def registrable_parts(host: str) -> dict:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return {"sld": labels[0] if labels else "", "tld": ".".join(labels[1:]), "sub": ""}
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_TLDS and len(labels) >= 3:
        return {"sld": labels[-3], "tld": last_two, "sub": ".".join(labels[:-3])}
    return {"sld": labels[-2], "tld": labels[-1], "sub": ".".join(labels[:-2])}


def analyze_lookalike(host: str) -> dict:
    findings = []
    unicode_host = to_unicode(host)
    is_idn = "xn--" in host

    if is_idn:
        findings.append(dict(severity="medium", title="Internationalized (punycode) domain",
            detail=(f"This hostname uses non-ASCII characters that display as "
                    f"\"{unicode_host}\". Attackers use look-alike Unicode letters so a fake "
                    f"domain is visually identical to a real one. Inspect it character by "
                    f"character.")))

    parts = registrable_parts(host)
    sld, sub = parts["sld"], parts["sub"]
    norm_sld = _normalize(sld)
    haystack = _normalize(f"{sub}.{sld}")
    shown_sld = registrable_parts(unicode_host)["sld"] if is_idn else sld  # what the user sees

    if is_idn:
        imitated = _normalize(shown_sld)
        if imitated in BRANDS and imitated != shown_sld:
            findings.append(dict(severity="high", title=f"Looks like a fake \"{imitated}\" domain",
                detail=(f"\"{shown_sld}\" is spelled with look-alike Unicode letters so it reads "
                        f"as \"{imitated}\". On screen it can be indistinguishable from the real "
                        f"site. This is a homograph attack.")))

    best = None
    for brand in BRANDS:
        if sld == brand:
            best = None
            break
        dist = _levenshtein(norm_sld, brand)
        near = 0 < dist <= (2 if len(brand) >= 8 else 1)
        contains_confused = brand in norm_sld and sld != brand and brand not in sld
        if near or contains_confused:
            if best is None or dist < best["dist"]:
                best = {"brand": brand, "dist": dist}

    if best:
        findings.append(dict(severity="high", title=f"Looks like a fake \"{best['brand']}\" domain",
            detail=(f"The registered name \"{sld}\" is a near-copy of \"{best['brand']}\" "
                    f"(edit distance {best['dist']}). This is the classic typosquatting / "
                    f"homoglyph trick used to fool people into trusting a lookalike site.")))

    for brand in BRANDS:
        if sld != brand and re.search(rf"(^|[.-]){brand}([.-]|$)", haystack) \
                and not haystack.endswith("." + brand):
            kw = next((k for k in PHISH_KEYWORDS if k in haystack), None)
            findings.append(dict(severity="high" if kw else "medium",
                title=f"\"{brand}\" appears but is not the real owner",
                detail=(f"\"{brand}\" shows up in the address, yet the domain is actually "
                        f"registered as \"{sld}\". "
                        + (f"Paired with the word \"{kw}\", this is a textbook "
                           f"credential-phishing layout."
                           if kw else
                           "Real brands serve their login pages from their own domain, not as "
                           "a label on someone else's."))))
            break

    hyphens = shown_sld.count("-")
    if hyphens >= 2:
        findings.append(dict(severity="low", title="Many hyphens in the domain",
            detail=(f"The name \"{shown_sld}\" contains {hyphens} hyphens. Heavily hyphenated names "
                    f"(brand-secure-login-portal) are disproportionately used by phishing pages.")))

    digits = sum(c.isdigit() for c in shown_sld)
    if len(shown_sld) > 4 and digits / max(len(shown_sld), 1) > 0.4:
        findings.append(dict(severity="low", title="Lots of digits in the domain",
            detail=("A high proportion of numbers in the registered name is common for "
                    "auto-generated, throwaway attack domains.")))

    return {"lookalike": {"unicode": unicode_host, "is_idn": is_idn, "sld": sld},
            "findings": findings}
