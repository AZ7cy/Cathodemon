"""TLS certificate inspection: fetch with stdlib ssl, parse with our x509der."""
from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone

from . import dnsclient, x509der

_DAY = 86400


def _connect(host: str, port: int, timeout: float):
    """Open a TCP connection using an address from Cathodemon's own resolver,
    so the operating system's DNS settings are never consulted."""
    addresses, _ttl = dnsclient.resolve(host, "A")
    if not addresses:
        raise OSError(f"{host} has no IPv4 address")
    last = None
    for ip in addresses[:3]:
        try:
            return socket.create_connection((ip, port), timeout=timeout)
        except OSError as exc:
            last = exc
    raise last


def _fetch(host: str, port: int = 443, timeout: float = 7.0):
    """Return (der, authorized, auth_error) or None on connection failure."""
    authorized, auth_error, der = False, None, None
    try:
        raw = _connect(host, port, timeout)
    except OSError:
        return None  # nothing answered on port 443; a second try would only wait again
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(raw, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
            authorized = True
    except ssl.SSLCertVerificationError as e:
        auth_error = str(e)
    except (OSError, ssl.SSLError):
        auth_error = None
    finally:
        raw.close()
    if der is not None:
        return der, authorized, auth_error
    try:
        ctx = ssl._create_unverified_context()
        with _connect(host, port, timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        return der, authorized, auth_error
    except (OSError, ssl.SSLError):
        return None


def _host_matches(host, cn, sans):
    names = {n.lower() for n in sans}
    if cn:
        names.add(cn.lower())
    target = host.lower()
    for name in names:
        if name == target:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            if target.endswith(suffix):
                head = target[:-len(suffix)]
                if head and "." not in head:
                    return True
    return False


def inspect_certificate(host: str) -> dict:
    res = _fetch(host)
    if res is None:
        return {"certificate": None, "findings": [dict(severity="medium",
            title="No usable HTTPS certificate",
            detail="Could not complete a TLS handshake on port 443. The site may be HTTP-only, "
                   "down, or blocking inspection. Entering credentials on an HTTP-only site is "
                   "unsafe.")]}

    der, authorized, auth_error = res
    try:
        info = x509der.parse_certificate(der)
    except Exception:
        return {"certificate": None, "findings": [dict(severity="low",
            title="Certificate could not be parsed",
            detail="A certificate was presented but its structure could not be read.")]}

    now = datetime.now(timezone.utc)
    valid_from, valid_to = info["not_before"], info["not_after"]
    age_days = int((now - valid_from).total_seconds() // _DAY)
    days_left = int((valid_to - now).total_seconds() // _DAY)
    issuer = info["issuer_o"] or info["issuer_cn"] or "unknown issuer"
    self_signed = info["self_signed"] and not authorized
    fp = hashlib.sha256(der).hexdigest().upper()
    fp_fmt = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))

    certificate = {
        "subject": info["subject_cn"], "issuer": issuer,
        "valid_from": valid_from.strftime("%Y-%m-%d"), "valid_to": valid_to.strftime("%Y-%m-%d"),
        "age_days": age_days, "days_until_expiry": days_left,
        "alt_names": ", ".join(info["san"]) if info["san"] else None,
        "fingerprint256": fp_fmt, "self_signed": self_signed,
    }

    findings = []
    if age_days < 30:
        findings.append(dict(severity="medium" if age_days < 7 else "low",
            title=f"Certificate is only {age_days} day{'' if age_days == 1 else 's'} old",
            detail="A freshly issued certificate is normal for a new site, but phishing pages are "
                   "almost always brand new. Treat a young certificate on a \"familiar\" brand as "
                   "a red flag."))
    if days_left < 0:
        findings.append(dict(severity="high", title="Certificate has expired",
            detail=f"The certificate expired {abs(days_left)} day(s) ago. Browsers will warn, and "
                   f"the operator is clearly not maintaining the site."))
    elif days_left < 14:
        findings.append(dict(severity="low", title="Certificate expires soon",
            detail=f"Only {days_left} day(s) of validity remain."))

    if not authorized:
        findings.append(dict(severity="high" if self_signed else "medium",
            title="Self-signed certificate" if self_signed else "Certificate chain did not validate",
            detail=("The certificate vouches for itself rather than being signed by a trusted "
                    "authority. No third party has verified who runs this site."
                    if self_signed else
                    f"The chain failed standard validation ({auth_error or 'unknown reason'}). "
                    f"Could be a misconfiguration or an interception attempt.")))

    if not _host_matches(host, info["subject_cn"], info["san"]):
        findings.append(dict(severity="high", title="Certificate does not cover this hostname",
            detail=f"The certificate is issued for other names, not \"{host}\". The content you "
                   f"reach may not be who it claims to be."))

    return {"certificate": certificate, "findings": findings}
