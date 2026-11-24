"""Combine DNS, certificate and look-alike checks into one scored report."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

from .dns_checks import inspect_dns
from .cert import inspect_certificate
from .dnsclient import to_ascii
from .lookalike import analyze_lookalike

_PENALTY = {"high": 28, "medium": 14, "low": 6, "info": 0, "good": -8}


def parse_target(raw: str) -> dict:
    if not raw or not isinstance(raw, str):
        raise ValueError("Provide a domain or URL.")
    text = raw.strip()
    had_scheme = bool(re.match(r"^[a-z]+://", text, re.I))
    if not had_scheme:
        text = "http://" + text
    try:
        u = urlparse(text)
    except ValueError:
        raise ValueError("That does not look like a valid domain or URL.")
    host = (u.hostname or "").lower().rstrip(".")
    if not host or "." not in host:
        raise ValueError("Could not find a domain in that input.")
    try:
        host = to_ascii(host)  # international names -> punycode, so look-alike checks see "xn--"
    except UnicodeError:
        raise ValueError("That domain name contains characters DNS can't use.")
    path = (u.path or "") + (("?" + u.query) if u.query else "")
    return {"host": host, "path": path}


def _verdict(score: int) -> dict:
    if score >= 80:
        return {"band": "TRUSTED", "blurb": "Nothing alarming surfaced. Still verify the address matches what you expected."}
    if score >= 60:
        return {"band": "LIKELY OK", "blurb": "Mostly clean, with a few minor notes worth a glance."}
    if score >= 40:
        return {"band": "CAUTION", "blurb": "Several warning signs. Do not enter passwords or payment details without independent confirmation."}
    if score >= 20:
        return {"band": "SUSPICIOUS", "blurb": "Multiple strong indicators of a malicious or throwaway domain. Avoid interacting with it."}
    return {"band": "DANGER", "blurb": "This has the fingerprints of a phishing or scam domain. Do not trust it."}


def build_report(raw: str) -> dict:
    target = parse_target(raw)
    host = target["host"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_dns = pool.submit(inspect_dns, host)
        f_cert = pool.submit(inspect_certificate, host)
        dns_res, cert_res = f_dns.result(), f_cert.result()
    look_res = analyze_lookalike(host)

    findings = []
    for src, res in (("lookalike", look_res), ("certificate", cert_res), ("dns", dns_res)):
        for f in res["findings"]:
            findings.append({**f, "source": src})

    order = {"high": 0, "medium": 1, "low": 2, "good": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    score = 100
    for f in findings:
        score -= _PENALTY.get(f["severity"], 0)
    score = max(0, min(100, round(score)))

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "target": host,
        "path": target["path"] if target["path"] and target["path"] != "/" else None,
        "score": score,
        "verdict": _verdict(score),
        "counts": counts,
        "findings": findings,
        "data": {
            "dns": dns_res["records"],
            "certificate": cert_res["certificate"],
            "lookalike": look_res["lookalike"],
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
