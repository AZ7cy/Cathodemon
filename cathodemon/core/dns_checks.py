"""DNS records + plain-language oddity findings, using our own resolver."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from . import dnsclient


def _safe(name, rtype):
    try:
        return dnsclient.resolve(name, rtype)
    except Exception:
        return [], None


def inspect_dns(host: str) -> dict:
    # The first lookup teaches the resolver where this domain's servers are;
    # the remaining lookups then run in parallel against those servers.
    a, a_ttl = _safe(host, "A")
    jobs = {"AAAA": (host, "AAAA"), "MX": (host, "MX"), "NS": (host, "NS"),
            "TXT": (host, "TXT"), "CAA": (host, "CAA"), "DMARC": (f"_dmarc.{host}", "TXT")}
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {key: pool.submit(_safe, *args) for key, args in jobs.items()}
        got = {key: f.result()[0] for key, f in futures.items()}
    aaaa, mx, ns, txt, caa, dmarc_txt = (got["AAAA"], got["MX"], got["NS"],
                                         got["TXT"], got["CAA"], got["DMARC"])

    a_recs = [{"address": ip, "ttl": a_ttl if a_ttl is not None else 0} for ip in a]
    aaaa_recs = [{"address": ip} for ip in aaaa]
    mx_recs = sorted(({"priority": p, "exchange": ex.rstrip(".")} for (p, ex) in mx),
                     key=lambda x: x["priority"])
    ns_recs = [n.rstrip(".") for n in ns]
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    dmarc = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), None)

    records = {"A": a_recs, "AAAA": aaaa_recs, "MX": mx_recs, "NS": ns_recs,
               "TXT": txt, "CAA": caa, "SPF": spf, "DMARC": dmarc}
    findings = []

    if not a_recs and not aaaa_recs:
        findings.append(dict(severity="high", title="No address records",
            detail="The domain does not resolve to any IPv4 or IPv6 address. It may be parked, "
                   "dead, or recently registered to stage an attack."))

    ttls = [r["ttl"] for r in a_recs if r["ttl"]]
    if ttls and 0 < min(ttls) < 120:
        findings.append(dict(severity="medium", title="Unusually short DNS TTL",
            detail=f"Address records expire after {min(ttls)}s. Very short TTLs let an operator "
                   f"swap servers rapidly, a trick seen in fast-flux botnets and phishing kits."))

    if len(a_recs) > 8:
        findings.append(dict(severity="low", title="Many address records",
            detail=f"{len(a_recs)} IPv4 addresses are advertised. Legitimate for a CDN, but "
                   f"combined with a short TTL it can signal fast-flux hosting."))

    if not mx_recs:
        findings.append(dict(severity="info", title="No mail servers",
            detail="No MX records. The domain cannot receive email at the apex. A domain used "
                   "only to host phishing pages often has no mail setup."))

    if not spf:
        findings.append(dict(severity="medium", title="No SPF record",
            detail="There is no SPF policy, so anyone can forge mail claiming to be from this "
                   "domain and it will not fail a basic sender check."))
    if not dmarc:
        findings.append(dict(severity="medium", title="No DMARC policy",
            detail="Without DMARC, mail receivers get no instructions on what to do with forged "
                   "mail from this domain. Spoofing is far easier."))

    if not caa:
        findings.append(dict(severity="low", title="No CAA record",
            detail="No Certificate Authority Authorization record. Any CA may issue certificates "
                   "for this domain, widening the blast radius if DNS is ever hijacked."))

    return {"records": records, "findings": findings}
