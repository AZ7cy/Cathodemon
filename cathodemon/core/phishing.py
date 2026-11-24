"""Explainable phishing analyzer.

Reads an email (headers + body) and explains, in plain language, every reason it
looks suspicious. Pure logic, no network. Mirrors the original browser analyzer.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

BRANDS = [
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google",
    "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
    "dhl", "fedex", "ups", "usps", "dpd", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "barclays", "coinbase", "binance", "metamask", "docusign",
    "dropbox", "adobe", "steam", "ebay", "stripe", "revolut", "santander", "venmo",
    # A made-up bank used by the sample data and demos, so they show no real
    # company's trademark.
    "ebonmarsh",
]
FREEMAIL = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me",
    "protonmail.com", "gmx.com", "mail.com", "yandex.com", "icloud.com",
]
SUSPICIOUS_TLDS = [
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "country", "kim",
    "work", "click", "link", "live", "rest", "fit", "review",
]
SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
]

URGENCY = [
    r"\burgent\b", r"\bimmediately\b", r"within \d+ ?(hours|hrs|days)", r"\bact now\b",
    r"\bas soon as possible\b", r"\bfinal (notice|warning|reminder)\b", r"\blast chance\b",
    r"\bexpire[sd]?\b", r"\bsuspend(ed|ing)?\b", r"\bdeactivat", r"\bterminat",
    r"\brestrict(ed|ion)?\b", r"\bimmediate action\b", r"\bavoid (closure|suspension)\b",
]
CREDS = [
    r"verify your (account|identity|password|email|information)",
    r"confirm your (account|identity|password|details|payment)",
    r"update your (payment|billing|card|account|password)",
    r"log ?in to (verify|confirm|restore|secure)", r"re-?activate your account",
    r"unusual (sign-?in|activity|login)", r"validate your account",
    r"enter your (password|pin|ssn|social security|card number|cvv)",
    r"\bone-?time (code|password|pin)\b",
]
PAYMENT = [
    r"gift ?card", r"\bwire transfer\b", r"\bbitcoin\b", r"\bcrypto(currency)?\b",
    r"\bseed phrase\b", r"\bwallet\b", r"\bbank (details|account)\b", r"\binvoice\b",
    r"\brefund\b", r"\bwon\b.*\b(lottery|prize)\b", r"\binheritance\b",
    r"\btax (refund|rebate)\b",
]
GENERIC_GREETING = [
    r"\bdear (customer|user|valued (customer|member)|account holder|sir/madam|member)\b",
    r"\bhello (dear|user|customer)\b",
]
RISKY_ATTACH = re.compile(
    r"\.(zip|rar|7z|iso|img|exe|scr|js|jse|vbs|hta|lnk|html?|docm|xlsm|pptm|jar)\b", re.I
)

_HOMO = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}


def _deleet(s: str) -> str:
    return "".join(_HOMO.get(c, c) for c in s.lower())


def levenshtein(a: str, b: str) -> int:
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


def _sld(host: str) -> str:
    labels = str(host).lower().rstrip(".").split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def _tld(host: str) -> str:
    return str(host).lower().split(".")[-1]


_URL_RE = re.compile(r"((?:https?://|www\.)[^\s<>()\"']+)", re.I)


def extract_urls(text: str):
    urls = []
    for m in _URL_RE.finditer(text or ""):
        raw = re.sub(r"[.,;:)\]]+$", "", m.group(1))
        with_scheme = raw if re.match(r"^https?://", raw, re.I) else "http://" + raw
        try:
            u = urlparse(with_scheme)
            host = (u.hostname or "").lower()
            if not host:
                continue
            urls.append({
                "raw": raw, "href": with_scheme, "host": host,
                "scheme": (u.scheme or "http").lower(), "userinfo": u.username or None,
                "path": (u.path or "") + (("?" + u.query) if u.query else ""),
            })
        except ValueError:
            continue
    return urls


_HEADER_RE = re.compile(r"^([A-Za-z-]+):\s*(.*)$")
_KNOWN_HEADER = re.compile(
    r"^(from|to|subject|reply-to|return-path|date|received|authentication-results|"
    r"received-spf|dkim-signature|message-id|sender|x-.*)$", re.I
)


def split_headers_body(text: str):
    lines = (text or "").split("\n")
    headers = {}
    saw = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "" and saw:
            i += 1
            break
        hm = _HEADER_RE.match(line)
        if hm and _KNOWN_HEADER.match(hm.group(1)):
            headers[hm.group(1).lower()] = hm.group(2).strip()
            saw = True
        elif not saw:
            break
        else:
            break
        i += 1
    body = "\n".join(lines[i:]) if saw else (text or "")
    return headers, body


def parse_address(value):
    if not value:
        return {"display": None, "email": None, "domain": None}
    m = re.match(r'^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$', value)
    email = (m.group(2) if m else value).strip().lower()
    display = m.group(1).strip() if m else None
    domain = email.split("@")[1] if "@" in email else None
    return {"display": display, "email": email, "domain": domain}


def _brand_hit(name: str):
    n = _deleet(name)
    for b in BRANDS:
        if n == b:
            return {"brand": b, "exact": True}
        if b in n and n != b and b not in name:
            return {"brand": b, "exact": False}
        if len(name) >= 4 and levenshtein(n, b) <= (2 if len(b) >= 8 else 1):
            return {"brand": b, "exact": False, "typo": True}
    return None


def _any(patterns, text) -> bool:
    return any(re.search(p, text, re.I) for p in patterns)


def analyze_email(text: str) -> dict:
    """Return a risk report: score (0-100), verdict, reasons, links, sender, stats."""
    reasons = []

    def add(weight, severity, title, detail, evidence=None):
        reasons.append({"weight": weight, "severity": severity, "title": title,
                        "detail": detail, "evidence": evidence})

    headers, body = split_headers_body(text or "")
    have_headers = bool(headers)
    full = f"{headers.get('subject', '')}\n{body}"
    frm = parse_address(headers.get("from"))
    reply_to = parse_address(headers.get("reply-to"))
    return_path = parse_address(headers.get("return-path"))

    # --- header / sender checks ---
    if have_headers:
        if frm["display"]:
            bh = _brand_hit(frm["display"])
            if bh and frm["domain"] and _sld(frm["domain"]) != bh["brand"] \
                    and not frm["domain"].endswith(bh["brand"] + ".com"):
                add(26, "high", "Sender name impersonates a brand",
                    f"The display name mentions \"{bh['brand']}\", but the actual sending "
                    f"address is {frm['email']}. A real {bh['brand']} message comes from a "
                    f"{bh['brand']}-owned domain, not {frm['domain']}.", headers.get("from"))
            if frm["domain"] in FREEMAIL and bh:
                add(22, "high", "Brand claim from a free mailbox",
                    f"The message claims to be \"{frm['display']}\" yet is sent from a free "
                    f"{frm['domain']} account. Companies do not send official mail from "
                    f"personal webmail.", headers.get("from"))
        if reply_to["email"] and frm["email"] and reply_to["domain"] != frm["domain"]:
            add(16, "medium", "Reply-To points elsewhere",
                f"Replies would go to {reply_to['email']} ({reply_to['domain']}), not the "
                f"sender's domain {frm['domain']}. Attackers do this so your reply reaches "
                f"them, not the real company.", f"Reply-To: {headers.get('reply-to')}")
        if return_path["domain"] and frm["domain"] and return_path["domain"] != frm["domain"]:
            add(8, "low", "Return-Path does not match From",
                f"The bounce address ({return_path['domain']}) differs from the From domain "
                f"({frm['domain']}) - common in spoofed or relayed mail.",
                f"Return-Path: {headers.get('return-path')}")
        auth = (headers.get("authentication-results", "") + " " + headers.get("received-spf", ""))
        if re.search(r"spf=fail|dkim=fail|dmarc=fail", auth, re.I):
            add(24, "high", "Authentication failed (SPF/DKIM/DMARC)",
                "The mail server recorded that sender authentication failed. This strongly "
                "suggests the From address is forged.", auth.strip()[:160])
        elif re.search(r"spf=softfail|dmarc=quarantine", auth, re.I):
            add(12, "medium", "Weak sender authentication",
                "Authentication results are soft-fail/quarantine - the sender could not be "
                "fully verified.", auth.strip()[:160])
        if frm["domain"] and "xn--" in frm["domain"]:
            add(18, "high", "Sender uses a punycode domain",
                f"The sending domain {frm['domain']} uses non-ASCII look-alike characters - a "
                f"tactic to mimic a trusted domain.", headers.get("from"))

    # --- link checks ---
    links = extract_urls(full)
    seen = set()
    flagged_link_brand = False
    for link in links:
        host = link["host"]
        dupe = host in seen
        seen.add(host)
        if link["userinfo"]:
            add(22, "high", "Deceptive link with embedded username",
                f"The link {link['raw']} uses the \"user@host\" trick: everything before the @ "
                f"is ignored by the browser, so it actually goes to {host}, not where it "
                f"appears to point.", link["raw"])
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            add(18, "high", "Link points to a raw IP address",
                f"{link['raw']} sends you to a bare IP ({host}) instead of a named site. "
                f"Legitimate companies use their domain, not an IP.", link["raw"])
        if "xn--" in host:
            add(18, "high", "Punycode (look-alike) link",
                f"{link['raw']} uses non-ASCII characters that can render as a familiar brand "
                f"while pointing somewhere else.", link["raw"])
        if host in SHORTENERS and not dupe:
            add(10, "medium", "Shortened link hides its destination",
                f"{link['raw']} is a URL shortener - you cannot see where it really leads "
                f"until you click. Phishing hides behind these.", link["raw"])
        if _tld(host) in SUSPICIOUS_TLDS and not dupe:
            add(10, "medium", f"Unusual top-level domain .{_tld(host)}",
                f"The link uses the .{_tld(host)} TLD, heavily abused for throwaway phishing "
                f"sites.", link["raw"])
        if link["scheme"] == "http" and not dupe:
            add(6, "low", "Unencrypted (http) link",
                f"{link['raw']} is plain HTTP. Any login page served over HTTP is unsafe.",
                link["raw"])
        sub_count = len(host.split(".")) - 2
        if sub_count >= 3 and not dupe:
            add(8, "low", "Deeply nested subdomains",
                f"{host} buries the real domain behind {sub_count} subdomains to look "
                f"legitimate at a glance.", link["raw"])
        bh = _brand_hit(_sld(host))
        if bh and not bh["exact"] and not flagged_link_brand:
            add(24, "high", f"Link mimics \"{bh['brand']}\"",
                f"The link domain {host} is a look-alike of {bh['brand']} but is not actually "
                f"owned by them. This is the classic phishing hook.", link["raw"])
            flagged_link_brand = True

    m = re.search(r"\b(paypal|apple|microsoft|amazon|google|netflix|bank|chase|coinbase)\b"
                  r"[^\n]{0,40}?(https?://[^\s]+)", full, re.I)
    if m:
        try:
            h = (urlparse(m.group(2)).hostname or "").lower()
            b = m.group(1).lower()
            if h and _sld(h) != b and b not in h:
                add(14, "medium", "Link text and destination disagree",
                    f"Text mentions \"{m.group(1)}\" but the adjacent link goes to {h}. "
                    f"Hover-text and real destination should match.", m.group(2))
        except ValueError:
            pass

    # --- content / social-engineering checks ---
    urgency_hits = sum(1 for p in URGENCY if re.search(p, full, re.I))
    if urgency_hits >= 1:
        add(min(18, 6 + urgency_hits * 4), "high" if urgency_hits >= 2 else "medium",
            "Pressure / urgency language",
            f"The message tries to rush you ({urgency_hits} urgency cue"
            f"{'s' if urgency_hits > 1 else ''} such as deadlines, suspension or \"act now\"). "
            f"Creating panic so you skip thinking is the core phishing technique.")
    if _any(CREDS, full):
        add(20, "high", "Asks you to verify or enter credentials",
            "The message pushes you to confirm a password, identity or account. Legitimate "
            "providers do not ask you to \"verify\" by following an email link.")
    if _any(PAYMENT, full):
        add(16, "high", "Money / payment lure",
            "It references gift cards, wire transfers, crypto, refunds or prizes - classic "
            "bait for financial fraud.")
    if _any(GENERIC_GREETING, full):
        add(8, "low", "Generic greeting",
            "It opens with \"Dear Customer/User\" rather than your name. Bulk phishing rarely "
            "knows who you are.")
    am = RISKY_ATTACH.search(full)
    if am:
        add(14, "medium", "Mentions a risky attachment type",
            f"A {am.group(0)} file is referenced. Executables, scripts, disk images and "
            f"macro-enabled documents are common malware carriers.", am.group(0))
    if re.search(r"enable (macros|editing|content)", full, re.I):
        add(16, "high", "Asks you to enable macros/content",
            "Requests to \"enable macros\" or \"enable content\" exist to run hidden code. "
            "This is a hallmark of document-based malware.")
    exclaims = full.count("!")
    if exclaims >= 5:
        add(4, "low", "Excessive exclamation marks",
            f"The text uses {exclaims} exclamation marks - a mild spam/scam signal.")
    if re.search(r"\$\s?\d{3,}|\d{3,}\s?(usd|dollars|btc|eth)", full, re.I) and _any(PAYMENT, full):
        add(6, "low", "Large sum of money mentioned",
            "A specific large amount paired with payment language is a common fraud framing.")

    # --- scoring ---
    score = min(100, sum(r["weight"] for r in reasons))
    order = {"high": 0, "medium": 1, "low": 2}
    reasons.sort(key=lambda r: (order.get(r["severity"], 9), -r["weight"]))

    if score >= 70:
        band, blurb = "DANGER", "Multiple strong phishing indicators. Do not click links, reply, or open attachments."
    elif score >= 45:
        band, blurb = "SUSPICIOUS", "Several warning signs. Treat as hostile until you independently verify the sender."
    elif score >= 20:
        band, blurb = "QUESTIONABLE", "Some red flags. Be cautious and verify through a known channel before acting."
    elif reasons:
        band, blurb = "LOW RISK", "Minor notes only. Still confirm anything involving money or credentials."
    else:
        band, blurb = "LOOKS CLEAN", "No common phishing signals detected. Judgement still required - no tool catches everything."

    return {
        "score": score,
        "verdict": {"band": band, "blurb": blurb},
        "reasons": reasons,
        "links": [{"raw": l["raw"], "host": l["host"], "scheme": l["scheme"]} for l in links],
        "sender": ({"from": frm["email"], "display": frm["display"],
                    "reply_to": reply_to["email"]} if have_headers else None),
        "stats": {"link_count": len(links), "reason_count": len(reasons),
                  "has_headers": have_headers},
    }
