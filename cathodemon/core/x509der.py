"""A minimal DER / X.509 parser - just enough to read a server certificate's
subject, issuer, validity window and SubjectAltName DNS entries. Standard
library only; no ASN.1 dependency.
"""
from __future__ import annotations

from datetime import datetime, timezone

_OID_CN = b"\x55\x04\x03"   # 2.5.4.3  commonName
_OID_O = b"\x55\x04\x0a"    # 2.5.4.10 organizationName
_OID_SAN = b"\x55\x1d\x11"  # 2.5.29.17 subjectAltName


def _read_len(data, off):
    b = data[off]
    off += 1
    if b < 0x80:
        return b, off
    num = b & 0x7F
    return int.from_bytes(data[off:off + num], "big"), off + num


def _tlv(data, off):
    """Return (tag, value_start, value_end) for the TLV at off."""
    tag = data[off]
    length, vs = _read_len(data, off + 1)
    return tag, vs, vs + length


def _children(data, start, end):
    out = []
    off = start
    while off < end:
        tag, vs, ve = _tlv(data, off)
        out.append((tag, vs, ve))
        off = ve
    return out


def _name(data, node):
    _tag, vs, ve = node
    cn = o = None
    for rdn in _children(data, vs, ve):          # SET
        for atv in _children(data, rdn[1], rdn[2]):  # SEQUENCE {oid, value}
            parts = _children(data, atv[1], atv[2])
            if len(parts) < 2:
                continue
            oid = data[parts[0][1]:parts[0][2]]
            value = data[parts[1][1]:parts[1][2]].decode("utf-8", "replace")
            if oid == _OID_CN and cn is None:
                cn = value
            elif oid == _OID_O and o is None:
                o = value
    return {"cn": cn, "o": o}


def _time(data, node):
    tag, vs, ve = node
    s = data[vs:ve].decode("ascii", "replace")
    if tag == 0x17:  # UTCTime  YYMMDDHHMMSSZ
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        return datetime(year, int(s[2:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]),
                        int(s[10:12]), tzinfo=timezone.utc)
    return datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12]),
                    int(s[12:14]) if len(s) >= 14 else 0, tzinfo=timezone.utc)


def _validity(data, node):
    times = _children(data, node[1], node[2])
    return _time(data, times[0]), _time(data, times[1])


def _san(data, node):
    seqs = _children(data, node[1], node[2])  # [3] EXPLICIT -> one SEQUENCE OF Extension
    if not seqs:
        return []
    ext_seq = seqs[0]
    for ext in _children(data, ext_seq[1], ext_seq[2]):
        parts = _children(data, ext[1], ext[2])
        if not parts:
            continue
        oid = data[parts[0][1]:parts[0][2]]
        if oid == _OID_SAN:
            octet = parts[-1]  # OCTET STRING wrapping GeneralNames
            inner = data[octet[1]:octet[2]]
            _t, gvs, gve = _tlv(inner, 0)
            return [inner[gn[1]:gn[2]].decode("ascii", "replace")
                    for gn in _children(inner, gvs, gve) if gn[0] == 0x82]  # [2] dNSName
    return []


def parse_certificate(der: bytes) -> dict:
    """Extract subject/issuer/validity/SAN from a DER X.509 certificate."""
    _t, vs, ve = _tlv(der, 0)                 # Certificate SEQUENCE
    cert = _children(der, vs, ve)
    tbs = _children(der, cert[0][1], cert[0][2])  # TBSCertificate children
    idx = 1 if tbs and tbs[0][0] == 0xA0 else 0   # skip optional [0] version
    idx += 1  # serialNumber
    idx += 1  # signature AlgorithmIdentifier
    issuer = _name(der, tbs[idx]); idx += 1
    not_before, not_after = _validity(der, tbs[idx]); idx += 1
    subject = _name(der, tbs[idx]); idx += 1
    idx += 1  # subjectPublicKeyInfo
    san = []
    for child in tbs[idx:]:
        if child[0] == 0xA3:  # [3] extensions
            try:
                san = _san(der, child)
            except (IndexError, ValueError):
                san = []
            break
    return {"subject_cn": subject["cn"], "issuer_o": issuer["o"], "issuer_cn": issuer["cn"],
            "not_before": not_before, "not_after": not_after, "san": san,
            "self_signed": subject == issuer}
